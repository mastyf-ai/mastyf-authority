"""Learn data budgets and change-gate budgets from a history of normal activity.

For each (identity, budget key) the rolling 24-hour total is computed at every event in the
history. The budget is the q-quantile of those totals times a margin, rounded up. Rare spikes
(a monthly export, a key rotation) fall above the quantile on purpose: they become planned
two-person approvals instead of loosening the everyday limit.

Anything never seen in the history gets 0. Learn only from a period believed clean: an
attacker already inside during learning would be baked into the budget.
"""

from __future__ import annotations

import math
from collections import defaultdict

import numpy as np

from .actions import Action
from .budgets import READ_ACTIONS, BudgetPolicy
from .features import DAY


def _rolling_totals(points: list[tuple[float, int]], start: float, end: float) -> np.ndarray:
    """Rolling 24 h total sampled every hour from start to end (quiet hours count as 0)."""
    ts = np.array(sorted(t for t, _ in points))
    order = sorted(points)
    cum = np.concatenate([[0], np.cumsum([n for _, n in order])])
    grid = np.arange(start + DAY, end + 1, 3600.0)
    hi = np.searchsorted(ts, grid, side="right")
    lo = np.searchsorted(ts, grid - DAY, side="right")
    return cum[hi] - cum[lo]


def _budget(points, q: float, margin: float, step: int, start: float, end: float) -> int:
    totals = _rolling_totals(points, start, end)
    v = float(np.quantile(totals, q)) * margin if len(totals) else 0.0
    floor = float(np.median([n for _, n in points])) * margin  # anything seen can at least do a typical action
    v = max(v, floor)
    return int(math.ceil(v / step) * step) if v > 0 else 0


def _span(history: list[Action]) -> tuple[float, float]:
    ts = [a.ts for a in history]
    return (min(ts), max(ts)) if ts else (0.0, 0.0)


def learn_data_budgets(history: list[Action], classes: dict[str, list[str]], q: float = 0.99,
                       margin: float = 2.0) -> dict[str, dict[str, int]]:
    shell = BudgetPolicy(classes, {})
    pts: dict[tuple[str, str], list] = defaultdict(list)
    for a in history:
        if a.action_type not in READ_ACTIONS:
            continue
        cls = shell.classify(a.resource)
        if cls is None:
            continue
        key = cls
        if a.destination:
            from .features import dest_key
            key = f"{cls}@{dest_key(a.destination)}"
        pts[(a.identity, key)].append((a.ts, a.count))
    start, end = _span(history)
    out: dict[str, dict[str, int]] = defaultdict(dict)
    for (ident, key), p in pts.items():
        out[ident][key] = _budget(p, q, margin, 10, start, end)
    return dict(out)


def _rolling(points, start: float, end: float, window: float) -> np.ndarray:
    ts = np.array(sorted(t for t, _ in points))
    order = sorted(points)
    cum = np.concatenate([[0], np.cumsum([n for _, n in order])])
    grid = np.arange(start + window, end + 1, 3600.0)
    return cum[np.searchsorted(ts, grid, side="right")] - cum[np.searchsorted(ts, grid - window, side="right")]


def learn_long_budgets(history: list[Action], classes: dict[str, list[str]], daily: dict[str, dict[str, int]],
                       q: float = 0.99, margin: float = 1.5) -> dict[str, dict[str, dict[str, int]]]:
    """Weekly and 4-weekly limits for the same ledger keys as the daily budgets.

    7d: the q-quantile of rolling 7-day totals in the history times `margin` (1.5: a busy week fits, a
    month of taking the full daily budget every day does not). 28d: three of those weeks. Never below the
    daily budget (a single normal day always fits). Needs at least 14 days of history for the key; keys
    without enough history keep only their daily budget."""
    shell = BudgetPolicy(classes, {})
    pts: dict[tuple[str, str], list] = defaultdict(list)
    for a in history:
        if a.action_type not in READ_ACTIONS:
            continue
        cls = shell.classify(a.resource)
        if cls is None:
            continue
        key = cls
        if a.destination:
            from .features import dest_key
            key = f"{cls}@{dest_key(a.destination)}"
        pts[(a.identity, key)].append((a.ts, a.count))
    start, end = _span(history)
    out: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    if end - start < 14 * DAY:
        return {}
    for (ident, key), p in pts.items():
        tot = _rolling(p, start, end, 7 * DAY)
        if not len(tot):
            continue
        d = int(daily.get(ident, {}).get(key, 0))
        w = max(d, int(math.ceil(float(np.quantile(tot, q)) * margin / 10) * 10))
        out[ident][key] = {"7d": w, "28d": max(d, 3 * w)}
    return dict(out)


def learn_teams(history: list[Action], classes: dict[str, list[str]], team_of: dict[str, list[str]],
                q: float = 0.99, margin: float = 2.0, min_members: int = 2) -> dict[str, dict]:
    """Per-team limits from how the whole team normally works.

    Each member's rolling 24 h totals are pooled, so one person's busy month neither sets nor
    escapes the limit, and a new joiner gets a sensible limit on day one. Actions a team uses are
    kept if at least `min_members` members used them (or the team is that small): one person's
    one-off oddity does not become the whole team's permission.
    """
    shell = BudgetPolicy(classes, {})
    start, end = _span(history)
    pts: dict[tuple[str, str, str], list] = defaultdict(list)  # (team, key, identity) -> points
    used: dict[tuple[str, str], set] = defaultdict(set)  # (team, action) -> identities
    size: dict[str, set] = defaultdict(set)
    for a in history:
        for t in team_of.get(a.identity, []):
            size[t].add(a.identity)
            used[(t, a.action_type)].add(a.identity)
            if a.action_type not in READ_ACTIONS:
                continue
            cls = shell.classify(a.resource)
            if cls is None:
                continue
            key = cls
            if a.destination:
                from .features import dest_key
                key = f"{cls}@{dest_key(a.destination)}"
            pts[(t, key, a.identity)].append((a.ts, a.count))
    pooled: dict[tuple[str, str], list] = defaultdict(list)
    for (t, key, _ident), p in pts.items():
        pooled[(t, key)].append(p)
    teams: dict[str, dict] = {}
    for t, members in size.items():
        need = min(min_members, len(members))
        acts = sorted(act for (tt, act), who in used.items() if tt == t and len(who) >= need)
        teams[t] = {"allowed_actions": acts, "budgets": {}, "learned_from_members": len(members)}
    for (t, key), lists in pooled.items():
        totals = np.concatenate([_rolling_totals(p, start, end) for p in lists])
        sizes = [n for p in lists for _, n in p]
        v = max(float(np.quantile(totals, q)) * margin if len(totals) else 0.0, float(np.median(sizes)) * margin)
        teams[t]["budgets"][key] = int(math.ceil(v / 10) * 10) if v > 0 else 0
    return teams


def learn_gate_budgets(history: list[Action], q: float = 0.99, margin: float = 2.0) -> dict:
    rew: dict[str, list] = defaultdict(list)
    wr: dict[tuple[str, str], list] = defaultdict(list)
    for a in history:
        if a.action_type == "repo.history_rewrite":
            rew[a.identity].append((a.ts, a.count))
        elif a.action_type == "file.write_bulk":
            wr[(a.identity, a.destination or a.resource)].append((a.ts, a.count))
    start, end = _span(history)
    write_budget: dict[str, dict[str, int]] = defaultdict(dict)
    for (ident, target), p in wr.items():
        write_budget[ident][target] = _budget(p, q, margin, 10, start, end)
    return {"rewrite_budget": {k: _budget(p, q, margin, 1, start, end) for k, p in rew.items()},
            "write_budget": dict(write_budget)}


def learn_novelty(events: list[tuple[float, str, str, list[str]]], q: float = 0.99, margin: float = 2.0,
                  window_margin: float = 1.5) -> dict[str, dict[str, dict[str, int]]]:
    """events: (ts, identity, data class, record ids) from a clean period, in time order.
    new_per_day  = q-quantile of the rolling-24h count of records not seen in the previous 30 days, x margin
    distinct_30d = distinct records seen over the learning period (<= 30 days) x window_margin
    """
    from collections import defaultdict as _dd
    seen: dict[tuple[str, str], dict[str, float]] = _dd(dict)
    pts: dict[tuple[str, str], list] = _dd(list)
    start = events[0][0] if events else 0.0
    end = events[-1][0] if events else 0.0
    for ts, ident, cls, ids in events:
        s = seen[(ident, cls)]
        new = sum(1 for r in set(ids) if r not in s or s[r] <= ts - 30 * DAY)
        for r in ids:
            s[r] = ts
        pts[(ident, cls)].append((ts, new))
    out: dict[str, dict[str, dict[str, int]]] = _dd(dict)
    for (ident, cls), p in pts.items():
        npd = _budget(p, q, margin, 10, start, end)
        out[ident][cls] = {"new_per_day": npd,
                           "distinct_30d": int(math.ceil(len(seen[(ident, cls)]) * window_margin / 10) * 10)}
    return dict(out)

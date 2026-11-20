"""Novelty scorer: catches quiet, slow and new kinds of misuse without any attack examples.

Insiders and intruders using stolen accounts nearly always do something that person has never done
before: a new destination, a new kind of action, a new system, an unusual hour, or more of something
than they ever did in a day. On its own that is common and harmless; what matters is how rare that
behaviour is in the whole organisation. So each action is scored as

    sum over its behaviours this person has never shown of  -log(share of people who have shown it)
    + growth beyond the person's own record daily volume (log ratio) x that action type's weight

and a per-person slow score accumulates these with daily decay (CUSUM), so a quiet insider who
does one slightly odd thing a day still crosses the line within days. Risk is calibrated on what
the organisation itself does: the 99.5th percentile of normal scores maps to 0.5 (escalate), and
the curve keeps rising after that. It can only ever make a decision stricter.

The same idea on daily CERT data (no attack labels used) caught 69 of 72 insiders on r4.2 at
5 alerts/day versus 20 for the isolation forest (tools/unsup_experiment.py).
"""

from __future__ import annotations

import math
import random
from collections import defaultdict

from .actions import Action
from .features import DAY, dest_key, hour_of, prefix

WARMUP_ACTIONS = 20
WARMUP_DAYS = 5.0
RARE_WEIGHT = -math.log(0.2)  # behaviour shown by fewer than 1 in 5 identities


def behaviours(a: Action) -> list[str]:
    out = [f"type:{a.action_type}", f"res:{prefix(a.resource, 2)}", f"res3:{prefix(a.resource, 3)}"]
    if a.destination:
        out.append(f"dest:{dest_key(a.destination)}")
        out.append(f"flow:{a.action_type}>{dest_key(a.destination)}")
    h = hour_of(a.ts)
    if h < 6 or h >= 21:
        out.append(f"night:{a.action_type}")
    return out


class NoveltyScorer:
    def __init__(self, decay_per_day: float = 0.6, seed: int = 0):
        self.seen: dict[str, set] = defaultdict(set)  # identity -> behaviours shown
        self.org: dict[str, set] = defaultdict(set)  # behaviour -> identities who showed it
        self.first: dict[str, float] = {}
        self.n_actions: dict[str, int] = defaultdict(int)
        self.day_vol: dict[tuple[str, str], tuple[int, int]] = {}  # (identity, type) -> (day, volume today)
        self.max_vol: dict[tuple[str, str], int] = defaultdict(int)  # best previous day
        self.slow: dict[str, tuple[float, float]] = {}  # identity -> (score, ts)
        self.decay = decay_per_day
        self.sample: list[float] = []  # reservoir of normal scores for calibration
        self.n_sampled = 0
        self.scale = 6.0  # score at which risk = 0.5 until calibrated
        self.rng = random.Random(seed)

    # ------------------------------------------------------------------ scoring
    def _weight(self, key: str) -> float:
        people = max(1, len(self.first))
        return -math.log((len(self.org.get(key, ())) + 1) / (people + 2))

    def mature(self, a: Action) -> bool:
        f = self.first.get(a.identity)
        return f is not None and self.n_actions[a.identity] >= WARMUP_ACTIONS and a.ts - f >= WARMUP_DAYS * DAY

    def raw(self, a: Action) -> tuple[float, list[str]]:
        if not self.mature(a):
            return 0.0, []
        mine = self.seen[a.identity]
        s, why = 0.0, []
        for b in behaviours(a):
            if b not in mine:
                w = self._weight(b)
                s += w
                if w >= 1.5:
                    why.append(f"first time for {a.identity}: {b.split(':', 1)[1]} "
                               f"({len(self.org.get(b, ()))} of {len(self.first)} identities have done this)")
        k = (a.identity, a.action_type)
        day = int(a.ts // DAY)
        d, v = self.day_vol.get(k, (day, 0))
        today = (v if d == day else 0) + a.count
        best = self.max_vol.get(k, 0)
        wt = self._weight(f"type:{a.action_type}")
        # Record growth only counts for things most people rarely do: everyday volume (mail, logins,
        # page views) swings all the time and drowned out real signals (CERT: +13 insiders at the
        # same alert budget, tools/detect_v2.py).
        if today > best and wt >= RARE_WEIGHT:
            grow = math.log1p((today - best) / (best + 1))
            s += grow * wt * 0.5
            if grow >= 1.0 and best > 0:
                why.append(f"{a.identity}: {today} {a.action_type} today, own previous daily record {best}")
        return s, why

    def _slow_now(self, identity: str, ts: float) -> float:
        sc, t = self.slow.get(identity, (0.0, ts))
        return sc * (self.decay ** max(0.0, (ts - t) / DAY))

    def score(self, a: Action) -> tuple[float, float, list[str]]:
        """(instant score, slow score including this action, reasons)."""
        s, why = self.raw(a)
        allowance = self.scale * 0.25
        slow = max(0.0, self._slow_now(a.identity, a.ts) + s - allowance)
        return s, slow, why

    def risk(self, a: Action) -> tuple[float, list[str]]:
        s, slow, why = self.score(a)
        x = max(s, slow)
        r = x / (x + self.scale) if x > 0 else 0.0
        if slow > s and slow > self.scale:
            why = why + [f"{a.identity}: unusual activity has kept accumulating (slow score {slow:.1f})"]
        return r, why

    # ------------------------------------------------------------------ learning
    def observe(self, a: Action, learn: bool = True) -> None:
        s, slow, _ = self.score(a)
        # attempts count as evidence even when refused; only allowed actions become "normal"
        self.slow[a.identity] = (slow, a.ts)
        if not learn:
            return
        if self.mature(a):
            self._calibrate(s)
        self.first.setdefault(a.identity, a.ts)
        self.n_actions[a.identity] += 1
        for b in behaviours(a):
            self.seen[a.identity].add(b)
            self.org[b].add(a.identity)
        k = (a.identity, a.action_type)
        day = int(a.ts // DAY)
        d, v = self.day_vol.get(k, (day, 0))
        if d != day:
            self.max_vol[k] = max(self.max_vol[k], v)
            v = 0
        self.day_vol[k] = (day, v + a.count)

    def _calibrate(self, s: float) -> None:
        self.n_sampled += 1
        if len(self.sample) < 5000:
            self.sample.append(s)
        else:
            j = self.rng.randrange(self.n_sampled)
            if j < 5000:
                self.sample[j] = s
        if self.n_sampled % 500 == 0 and len(self.sample) >= 2000:
            q = sorted(self.sample)[int(len(self.sample) * 0.995)]
            self.scale = max(2.0, q)  # 99.5th percentile of normal -> risk 0.5


class ReviewQueue:
    """A bounded daily list for a human reviewer: the `per_day` most unusual identities each day.

    Inline escalation catches the loud cases; this catches the quiet ones without flooding anyone.
    A fixed number per day beat one global threshold at the same budget on CERT (172 vs 161 of 192
    insiders on the tuning releases, tools/detect_v2.py), because a noisy day can no longer use up
    the whole period's budget.
    """

    def __init__(self, per_day: int = 5):
        self.per_day = per_day
        self.days: dict[int, dict[str, tuple[float, list[str]]]] = defaultdict(dict)

    def note(self, identity: str, ts: float, score: float, why: list[str]) -> None:
        if score <= 0:
            return
        day = self.days[int(ts // DAY)]
        best = day.get(identity)
        if best is None or score > best[0]:
            day[identity] = (score, why[:3])
        if len(self.days) > 60:  # keep two months
            del self.days[min(self.days)]

    def top(self, ts: float) -> list[dict]:
        day = self.days.get(int(ts // DAY), {})
        ranked = sorted(day.items(), key=lambda kv: -kv[1][0])[: self.per_day]
        return [{"identity": i, "score": round(s, 2), "why": w} for i, (s, w) in ranked]

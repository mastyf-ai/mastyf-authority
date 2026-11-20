"""Damage ceiling: the most any compromise can take, computed from the policy alone.

The key service and the change gates enforce their limits even when the authority is bypassed,
so the worst case of a break-in is a number you can compute in advance. This module computes it:

  for every identity, data class and window (24 h, 30 days):
      distinct records an attacker holding that identity can obtain
  for any k compromised identities together (an attacker with several accounts, or with approver
  accounts that can sign overruns): the worst combination, searched exhaustively
  for change gates: commits rewritten, files overwritten, backups deleted

Assumptions are explicit and conservative: the authority is bypassed (the attacker gets grants for
anything); compromised approvers sign whatever the attacker asks; bait records, the risk model and
people noticing are NOT counted (they only make the real number smaller). What is counted is only
what the key service and gates enforce: budgets, destination-bound budgets, new-record and 30-day
distinct limits, need-to-know cases, device binding, overrun caps and signature quorums, time locks.

tests/test_ceiling.py runs adaptive attackers against the real key service and checks they never
get more than this ceiling (and that the greedy attacker reaches it, so it is also tight).
"""

from __future__ import annotations

import itertools
import json
import math
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from .budgets import BudgetPolicy

INF = math.inf


@dataclass
class Threat:
    k: int = 1  # identities compromised together
    devices_stolen: bool = False  # attacker also controls the victims' registered devices (malware on laptop)
    case_records: int | None = None  # most records on one person's active cases (None: report as unknown)
    approvers: set[str] = field(default_factory=set)


def _fmt(x) -> str:
    return "unbounded" if x == INF else f"{int(x):,}"


def identity_ceiling(bp: BudgetPolicy, ident: str, cls: str, approvers_on_side: int, t: Threat,
                     outside_allowance: int = 20) -> dict:
    notes = []
    if any(fnmatchcase(ident, p) for p in bp.device_bound) and not t.devices_stolen:
        return {"per_day": 0, "per_30d": 0, "notes": ["device-bound: a stolen password or session gets nothing"]}
    entries = bp.budgets.get(ident, {})
    keys = {k: int(v) for k, v in entries.items() if k == cls or k.startswith(cls + "@")}
    per_day = float(sum(keys.values()))
    if len(keys) > 1:
        notes.append("separate budgets per destination add up: " + ", ".join(f"{k} {v:,}" for k, v in keys.items()))
    over = 0.0
    if approvers_on_side >= bp.overrun_signatures:
        cap = bp.overrun_cap(ident, cls)
        over = INF if cap is None else float(cap)
        if cap != 0:
            notes.append(f"{approvers_on_side} compromised approvers can sign overruns: "
                         + ("NO overrun cap in policy (set data_budgets.overrun_max)" if cap is None else f"+{cap:,}/24h"))
    nov = bp.novelty_for(ident, cls)
    if nov:
        d1 = min(per_day, nov.get("new_per_day", 0)) + over
        d30 = min(30 * per_day, 30 * nov.get("new_per_day", 0), nov.get("distinct_30d", 0)) + 30 * over
        notes.append(f"new-record limit {nov.get('new_per_day', 0):,}/24h, {nov.get('distinct_30d', 0):,} distinct/30d")
    else:
        d1, d30 = per_day + over, 30 * (per_day + over)
    if cls in bp.purpose_bound.get(ident, []):
        if t.case_records is None:
            notes.append(f"need-to-know: only records on assigned cases + {outside_allowance}/24h outside cases")
            cap1 = cap30 = None
        else:
            cap1 = t.case_records + outside_allowance
            cap30 = t.case_records * 30 + outside_allowance * 30  # cases may change daily: conservative
            d1, d30 = min(d1, cap1), min(d30, cap30)
    return {"per_day": d1, "per_30d": d30, "notes": notes}


def gate_ceiling(gp: dict, ident: str, approvers_on_side: int) -> dict:
    sigs = int(gp.get("signatures", 2))
    quorum = approvers_on_side >= sigs
    out = {"history_rewrite_commits_per_day": INF if quorum else int(gp.get("rewrite_budget", {}).get(ident, 0)),
           "protected_branch_rewrites": "allowed (quorum)" if quorum else "none",
           "files_overwritten_per_day": sum(int(v) for v in gp.get("write_budget", {}).get(ident, {}).values())
           if not quorum else INF,
           "backups_deleted": f"none within {int(gp.get('delete_lock_seconds', 259200)) // 3600} h; after that only "
                              f"if nobody cancels" if quorum else "none"}
    return out


def compute(policy: dict, threat: Threat | None = None) -> dict:
    t = threat or Threat()
    db = policy.get("data_budgets", policy)
    bp = BudgetPolicy.from_dict(db)
    gp = policy.get("change_gates", {})
    approvers = t.approvers or {n for n, r in policy.get("identities", {}).items() if r.get("approver")}
    outside = int(db.get("outside_case_allowance", 20))
    idents = sorted(set(bp.budgets) | approvers | set(gp.get("rewrite_budget", {})) | set(gp.get("write_budget", {})))
    classes = list(bp.classes)

    def value(group: tuple[str, ...]) -> tuple[dict, dict]:
        per_cls = {c: {"per_day": 0.0, "per_30d": 0.0} for c in classes}
        detail = {}
        for i in group:
            on_side = len([a for a in group if a in approvers and a != i])
            for c in classes:
                r = identity_ceiling(bp, i, c, on_side, t, outside)
                if r["per_day"] or r["notes"]:
                    detail.setdefault(i, {})[c] = r
                per_cls[c]["per_day"] += r["per_day"]
                per_cls[c]["per_30d"] += r["per_30d"]
        return per_cls, detail

    worst: dict = {}
    combos = itertools.combinations(idents, min(t.k, len(idents)))
    for c in classes:
        best, best_g = -1.0, ()
        for g in itertools.combinations(idents, min(t.k, len(idents))):
            v = value(g)[0][c]["per_30d"]
            if v > best:
                best, best_g = v, g
        pc, det = value(best_g)
        worst[c] = {"identities": list(best_g), "per_day": pc[c]["per_day"], "per_30d": pc[c]["per_30d"],
                    "how": {i: d[c] for i, d in det.items() if c in d}}
    del combos
    single = {i: {c: identity_ceiling(bp, i, c, 0, t, outside) for c in classes
                  if identity_ceiling(bp, i, c, 0, t, outside)["per_day"] > 0} for i in idents}
    gates = {i: gate_ceiling(gp, i, 0) for i in idents if i in gp.get("rewrite_budget", {}) or i in gp.get("write_budget", {})}
    k_gates = {}
    for g in itertools.combinations(idents, min(t.k, len(idents))):
        for i in g:
            on = len([a for a in g if a in approvers and a != i])
            r = gate_ceiling(gp, i, on)
            if r["history_rewrite_commits_per_day"] == INF:
                k_gates = {"identities": list(g), "result": r}
                break
        if k_gates:
            break
    uw = policy.get("undo_windows")
    undo = None
    if uw:
        undo = {"rules": [{"action": r["action"], "resource": r.get("resource", "*"), "min_count": r.get("min_count", 0),
                           "hours_before_it_can_happen": r["delay_seconds"] / 3600} for r in uw.get("rules", [])],
                "max_queued_per_identity_per_hour": uw.get("burst_per_hour", 5),
                "early_release_needs": uw.get("signatures", 2)}
    return {"undo_windows": undo, "threat": {"k": t.k, "devices_stolen": t.devices_stolen, "case_records": t.case_records,
                       "approvers": sorted(approvers)},
            "worst_case_by_class": worst, "single_identity": {i: v for i, v in single.items() if v},
            "change_gates_single": gates, "change_gates_with_quorum": k_gates or None,
            "unbounded": sorted(c for c, w in worst.items() if w["per_30d"] == INF)}


def report(res: dict) -> str:
    t = res["threat"]
    lines = [f"# Damage ceiling: {t['k']} compromised identit{'y' if t['k'] == 1 else 'ies'}"
             + (", their devices too" if t["devices_stolen"] else ", passwords/sessions only"), "",
             "Assumes the authority is bypassed and compromised approvers sign anything. Bait records, the risk "
             "model and people noticing are not counted.", "",
             "| Data class | Worst identities | Records per 24 h | Records per 30 days |", "|---|---|---|---|"]
    for c, w in res["worst_case_by_class"].items():
        lines.append(f"| {c} | {', '.join(w['identities']) or '-'} | {_fmt(w['per_day'])} | {_fmt(w['per_30d'])} |")
    if res["unbounded"]:
        lines += ["", "**Unbounded:** " + ", ".join(res["unbounded"]) + ". Set `data_budgets.overrun_max` so that "
                  "compromised approvers cannot sign unlimited overruns."]
    lines += ["", "Why (worst combination per class):"]
    for c, w in res["worst_case_by_class"].items():
        for i, d in w["how"].items():
            for n in d["notes"]:
                lines.append(f"- {c} / {i}: {n}")
    if res["change_gates_with_quorum"]:
        g = res["change_gates_with_quorum"]
        lines += ["", f"Change gates: with {', '.join(g['identities'])} compromised, approvals reach quorum: "
                  f"protected-branch rewrites {g['result']['protected_branch_rewrites']}; backups: {g['result']['backups_deleted']}."]
    if res.get("undo_windows"):
        u = res["undo_windows"]
        lines += ["", "Irreversible actions (undo windows): nothing below happens before its delay; anyone on the "
                  f"security team or an approver can cancel; at most {u['max_queued_per_identity_per_hour']} can be queued "
                  "per identity per hour (more freezes the identity and cancels them all):", ""]
        for r in u["rules"]:
            lines.append(f"- {r['action']}" + (f" (>= {r['min_count']:,})" if r["min_count"] else "")
                         + f": {r['hours_before_it_can_happen']:g} h")
    return "\n".join(lines) + "\n"


def to_json(res: dict) -> str:
    return json.dumps(res, indent=2, default=lambda x: "unbounded" if x == INF else str(x))

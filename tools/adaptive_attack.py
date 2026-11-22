"""The careful attacker: knows exactly how Authority decides and stays under every limit.

  PYTHONPATH=src .venv/bin/python tools/adaptive_attack.py [--seeds 5]

Worst case on purpose. The attacker is malware on the victim's own laptop (so the network, device and
working hours are the victim's) and has an exact copy of Authority's state (the code is public; we hand
it the live state too). Before every move it tries the move on its copy and only makes it if the copy
says ALLOW and the key service would release the records - it never triggers a question. Each working
hour it takes the largest amount that passes. We measure what it gets in 28 days, against:

  naive      the same goal in one go (the usual scripted attack)
  normal     what the victim themselves reads in 28 days

Goals: alice's customer records (crm.customer), bob's production secrets (secret). This bounds the harm
an undetectable attacker can do: if it is about the victim's own normal use, the defence is the data
budget learned from that normal use, not detection.
"""

from __future__ import annotations

import argparse
import copy
import json
from collections import Counter
from pathlib import Path

from authority import snapshot as snap
from authority.actions import Action
from authority.audit import AuditLog
from authority.budgets import BudgetPolicy, KeyService
from authority.learn import learn_data_budgets, learn_long_budgets
LONG = True
from authority.crypto import Signer
from authority.engine import Authority
from authority.grants import GrantIssuer
from authority.model import RiskModel
from authority.policy import Policy
from authority.scenarios import world

ROOT = Path(__file__).resolve().parents[1]
DAY = 86400.0
LADDER = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000]
GOALS = {
    "alice: customer records": ("human:alice", "data.read", "db://crm/customers/query", "crm.customer"),
    "bob: production secrets": ("human:bob", "secret.read", "vault://prod/db/password", "secret"),
}


def build(policy, model, signer, clock):
    auth = Authority(policy, GrantIssuer(signer, 3600, now=lambda: clock[0]), AuditLog(None, signer, now=lambda: clock[0]),
                     model=model, now=lambda: clock[0])
    auth.state.meta = policy.identity_meta()
    return auth


def clone(auth, ks, policy, model, signer, clock):
    c = build(policy, model, signer, clock)
    snap.load(c, snap.dump(auth, clock[0]))
    c.origins.load(auth.origins.to_json())
    k = KeyService(ks.policy, signer.public_key, {}, now=lambda: clock[0], custody=False)
    k.ledger, k.seen, k.new_ledger = copy.deepcopy(ks.ledger), copy.deepcopy(ks.seen), copy.deepcopy(ks.new_ledger)
    k.long_ledger = copy.deepcopy(ks.long_ledger)
    return c, k


def passes(auth, ks, a):
    d = auth.decide(a)
    if d.verdict != "ALLOW":
        return False, d
    return ks.release(d.grant, a).ok, d


def run_goal(seed: int, goal: str, adaptive: bool, model, learn_days=30, attack_days=28) -> dict:
    ident, kind, res, cls = GOALS[goal]
    events = [e.action for e in world(seed, None, days=learn_days + attack_days, attack_from=10**6)]
    events.sort(key=lambda x: x.ts)
    t0 = events[0].ts
    cut = t0 + learn_days * DAY
    policy = Policy.load(ROOT / "policies/default.json")
    clock = [t0]
    signer = Signer.generate()
    auth = build(policy, model, signer, clock)
    history = [x for x in events if x.ts < cut]
    for x in history:
        clock[0] = x.ts
        auth.note_baseline(x)
        auth.state.observe(x, learn=True)
        auth.novelty.observe(x, learn=True)
        if x.destination:
            auth.learned_destinations[(x.identity, x.destination)] = x.ts
    bp = BudgetPolicy.from_dict(policy.raw["data_budgets"])
    daily = learn_data_budgets(history, bp.classes)
    bp = BudgetPolicy(bp.classes, daily, long=learn_long_budgets(history, bp.classes, daily) if LONG else {})
    ks = KeyService(bp, signer.public_key, {}, now=lambda: clock[0], custody=False)
    victim_normal = sum(x.count for x in events if x.ts >= cut and x.identity == ident and x.action_type == kind
                        and bp.classify(x.resource) == cls)
    # attacker moves: every working hour on working days, inside the victim's own hours
    moves = []
    for d in range(learn_days, learn_days + attack_days):
        if (d % 7) in (5, 6):
            continue
        for h in range(10, 17):
            moves.append(t0 - (t0 % DAY) + d * DAY + h * 3600 + 1234)
    stream = sorted([(x.ts, 0, x) for x in events if x.ts >= cut] + [(t, 1, None) for t in moves], key=lambda z: z[:2])
    got, detected, reasons, n = 0, None, Counter(), 0
    for t, is_move, x in stream:
        clock[0] = t
        if not is_move:
            d = auth.decide(x)
            if d.verdict == "ALLOW" and bp.classify(x.resource):
                ks.release(d.grant, x)
            continue
        if detected is not None:
            continue
        if adaptive:
            best = 0
            for c in LADDER:  # largest amount its copy of Authority and of the key service would let through
                ca, ck = clone(auth, ks, policy, model, signer, clock)
                ok, _ = passes(ca, ck, Action(ident, kind, res, c, ts=t))
                if not ok:
                    break
                best = c
            if best == 0:
                continue
            amount = best
        else:
            amount = 50000 if n == 0 else 0
            if amount == 0:
                continue
        n += 1
        ok, d = passes(auth, ks, Action(ident, kind, res, amount, ts=t))
        if ok:
            got += amount
        else:
            detected = round((t - cut) / DAY, 1)
            reasons[(d.reasons or ["key service refused: data budget"])[0][:90] if d.verdict != "ALLOW"
                    else "key service refused: data budget"] += 1
    return {"seed": seed, "goal": goal, "attacker": "adaptive" if adaptive else "naive", "records_taken": got,
            "victim_normal_28d": victim_normal, "budget_per_day": bp.budgets.get(ident, {}).get(cls),
            "long_budget": bp.long.get(ident, {}).get(cls),
            "interrupted_after_days": detected, "why": dict(reasons), "moves": n}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--out", default=str(ROOT / "artifacts/adaptive_attack.json"))
    ap.add_argument("--daily-only", action="store_true", help="the old limits: rolling 24 h budgets only")
    a = ap.parse_args()
    global LONG
    LONG = not a.daily_only
    model = RiskModel.load(ROOT / "artifacts/risk_model.json")
    rows = []
    for seed in range(a.seeds):
        for goal in GOALS:
            for adaptive in (False, True):
                r = run_goal(100 + seed, goal, adaptive, model)
                rows.append(r)
                print(json.dumps(r), flush=True)
    summary = {}
    for goal in GOALS:
        ad = [r for r in rows if r["goal"] == goal and r["attacker"] == "adaptive"]
        nv = [r for r in rows if r["goal"] == goal and r["attacker"] == "naive"]
        summary[goal] = {
            "naive_taken_avg": round(sum(r["records_taken"] for r in nv) / len(nv)),
            "adaptive_taken_avg": round(sum(r["records_taken"] for r in ad) / len(ad)),
            "victim_normal_avg": round(sum(r["victim_normal_28d"] for r in ad) / len(ad)),
            "adaptive_vs_normal": round(sum(r["records_taken"] for r in ad) / max(1, sum(r["victim_normal_28d"] for r in ad)), 2),
            "adaptive_ever_interrupted": sum(1 for r in ad if r["interrupted_after_days"] is not None),
        }
    print(json.dumps(summary, indent=1))
    Path(a.out).write_text(json.dumps({"summary": summary, "runs": rows}, indent=1))


if __name__ == "__main__":
    main()

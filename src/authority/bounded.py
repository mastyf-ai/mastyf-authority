"""Measure the bounded-loss guarantee.

Two modes, same simulated worlds as replay.py:
  full   authority (policy, canaries, integrity, model, approvals) + key service budgets
  blind  WORST CASE: the authority is compromised or every detection layer is fooled, so every
         action gets a valid grant. Only the key service's budgets stand between attacker and data.

"Loss" = records whose keys were released to the attacker (confidentiality).
Malicious non-read actions (deletes, mass writes, rewrites, publishes) are not bounded by
budgets; blind mode reports how many of those would have run.

Legitimate work that hits a budget is re-requested with an overrun signed by two approvers,
and counted: that is the cost of the guarantee.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from . import script_integrity
from .actions import Action
from .audit import AuditLog
from .budgets import READ_ACTIONS, BudgetPolicy, KeyService, overrun_message
from .crypto import Signer, b64e
from .engine import ALLOW, ESCALATE, Authority, sign_approval
from .gates import GATED, ChangeGate, GatePolicy, gate_message
from .learn import learn_data_budgets, learn_gate_budgets
from .features import DAY
from .grants import GrantIssuer
from .model import RiskModel
from .policy import Policy
from .replay import FIX, VIDEO_MAP, Clock
from .scenarios import FAMILIES, world

APPROVERS = ("human:bob", "human:dana", "human:erin")


def run_world(family: str | None, seed: int, model: RiskModel | None, policy: Policy, mode: str,
              warmup_days: int = 30, learned: bool = False) -> dict:
    events = world(seed, family)
    clock = Clock()
    signer = Signer.generate()
    issuer = GrantIssuer(signer, policy.grant_ttl_seconds, now=clock)
    approver_signers = {n: Signer.generate() for n in APPROVERS}
    auth = Authority(policy, issuer, AuditLog(None, signer, now=clock), model=model, now=clock,
                     approver_keys={n: s.public_key for n, s in approver_signers.items()})
    bp = BudgetPolicy.from_dict(policy.raw["data_budgets"])
    gp = GatePolicy.from_dict(policy.raw["change_gates"])
    if learned:  # budgets learned from the (clean) warmup period instead of hand-set
        history = [e.action for e in events if e.action.ts < warmup_days * DAY]
        bp = BudgetPolicy(bp.classes, learn_data_budgets(history, bp.classes), bp.overrun_signatures)
        lg = learn_gate_budgets(history)
        gp.rewrite_budget, gp.write_budget = lg["rewrite_budget"], lg["write_budget"]
    pubs = {n: s.public_key for n, s in approver_signers.items()}
    ks = KeyService(bp, signer.public_key, pubs, now=clock)
    gate = ChangeGate(gp, signer.public_key, pubs, now=clock)

    def gate_sigs(grant: str, a: Action) -> list[dict]:
        from .crypto import b64d
        gid = json.loads(b64d(grant.split(".")[0]))["gid"]
        names = [n for n in APPROVERS if n != a.identity][:2]
        return [{"approver": n, "sig": b64e(approver_signers[n].sign(gate_message(gid, a.fingerprint())))}
                for n in names]

    v1 = (FIX / "tag_v1.js").read_text()
    skimmer = (FIX / "tag_v2_skimmer.js").read_text()
    live, build = v1, 0
    auth.record_integrity(script_integrity.check(None, v1) | {"verdict": "pass"})

    def overrun_for(grant: str, requester: str, amount: int) -> list[dict]:
        import json as _j
        from .crypto import b64d
        gid = _j.loads(b64d(grant.split(".")[0]))["gid"]
        names = [n for n in APPROVERS if n != requester][:2]
        return [{"approver": n, "amount": amount,
                 "sig": b64e(approver_signers[n].sign(overrun_message(gid, amount)))} for n in names]

    def get_grant(a: Action, benign: bool) -> str | None:
        if mode == "blind":
            return issuer.issue(a, "blind")
        d = auth.decide(a)
        if d.verdict == ESCALATE and benign:
            who, why = ("human:dana" if a.identity != "human:dana" else "human:erin"), "CHG-1234 verified"
            aid = auth.approve(d.fingerprint, a.identity, who, why,
                               sign_approval(approver_signers[who], d.fingerprint, a.identity, why))
            d = auth.decide(a, approval_id=aid)
        return d.grant if d.verdict == ALLOW else None

    st = {"family": family, "seed": seed, "mode": mode, "attack_read_attempted": 0, "attack_read_released": 0,
          "attack_reads_by_class": {}, "attack_nonread_steps": 0, "attack_nonread_executed": 0,
          "benign_reads": 0, "benign_overruns": 0, "benign_blocked": 0, "skimmer_live": False,
          "benign_overrun_by": {}, "benign_blocked_by": {},
          "benign_gate_approvals": 0, "attack_nonread_by": {}}
    bump = lambda d, k: d.__setitem__(k, d.get(k, 0) + 1)  # noqa: E731
    for e in events:
        a = e.action
        clock.t = a.ts
        if a.ts < warmup_days * DAY:
            auth.state.observe(a, learn=True)
            if a.action_type in READ_ACTIONS and bp.classify(a.resource):  # budgets in use during warmup too
                key, _ = bp.budget(a.identity, bp.classify(a.resource), a.destination)
                ks.ledger[(a.identity, key)].append((a.ts, a.count))
            continue
        cand = None
        if a.action_type == "artifact.publish":
            build += 1
            cand = skimmer if e.label else v1 + f"\n// build {build}\n"
            rep = script_integrity.check(live, cand)
            auth.record_integrity(rep)
            a = Action(**{**a.to_dict(), "metadata": {"candidate_sha256": rep["candidate_sha256"]}})

        is_read = a.action_type in READ_ACTIONS and bp.classify(a.resource) is not None
        grant = get_grant(a, benign=not e.label)

        if e.label:
            if is_read:
                st["attack_read_attempted"] += a.count
                if grant:
                    r = ks.release(grant, a)  # attacker gets no approver signatures
                    if r.ok:
                        st["attack_read_released"] += a.count
                        c = st["attack_reads_by_class"]
                        c[r.data_class] = c.get(r.data_class, 0) + a.count
            else:
                st["attack_nonread_steps"] += 1
                done = False
                if grant:
                    done = gate.apply(grant, a, content=cand).ok if a.action_type in GATED else True
                if done:
                    st["attack_nonread_executed"] += 1
                    bump(st["attack_nonread_by"], a.action_type)
                    if cand is not None and cand == skimmer:
                        st["skimmer_live"] = True
                        live = cand
            continue

        if a.action_type in GATED and grant:
            res = gate.apply(grant, a, content=cand)
            if not res.ok:
                st["benign_gate_approvals"] += 1
                bump(st["benign_overrun_by"], f"{a.identity}|gate:{a.action_type}")
                g2 = get_grant(a, benign=True)
                res = gate.apply(g2, a, gate_sigs(g2, a), content=cand) if g2 else res
                if not res.ok:
                    st["benign_blocked"] += 1
                    bump(st["benign_blocked_by"], f"{a.identity}|gate")
            if res.ok and cand is not None:
                live = cand
        if is_read:
            st["benign_reads"] += 1
            if grant is None:
                st["benign_blocked"] += 1
                bump(st["benign_blocked_by"], f"{a.identity}|authority")
                continue
            r = ks.release(grant, a)
            if not r.ok:
                st["benign_overruns"] += 1
                bump(st["benign_overrun_by"], f"{a.identity}|{r.reason.split(' ')[1]}")
                g2 = get_grant(a, benign=True)
                r2 = ks.release(g2, a, overrun_for(g2, a.identity, a.count)) if g2 else None
                if not (r2 and r2.ok):
                    st["benign_blocked"] += 1
                    bump(st["benign_blocked_by"], f"{a.identity}|" + ("authority" if not g2 else "overrun"))
    st["days"] = round((events[-1].action.ts - warmup_days * DAY) / DAY, 1)
    if family:
        start = next(e.action.ts for e in events if e.label)
        end = max(e.action.ts for e in events if e.label)
        st["attack_days"] = round((end - start) / DAY, 2)
    return st


def run(policy_path: str, model_path: str | None, out_dir: str, per_family: int = 6, seed_base: int = 900_000,
        learned: bool = False) -> dict:
    policy = Policy.load(policy_path)
    model = RiskModel.load(model_path) if model_path else None
    runs, summary = [], {}
    for mode in ("full", "blind"):
        for i, fam in enumerate(list(FAMILIES) + [None]):
            rs = [run_world(fam, seed_base + 1000 * i + k, model, policy, mode, learned=learned)
                  for k in range(per_family)]
            runs.extend(rs)
            days = sum(r["days"] for r in rs)
            s = {
                "benign_overruns_per_day": round(sum(r["benign_overruns"] for r in rs) / days, 3),
                "benign_gate_approvals_per_day": round(sum(r["benign_gate_approvals"] for r in rs) / days, 3),
                "benign_blocked": sum(r["benign_blocked"] for r in rs),
            }
            if fam:
                att = sum(r["attack_read_attempted"] for r in rs)
                rel = sum(r["attack_read_released"] for r in rs)
                by: dict[str, int] = {}
                for r in rs:
                    for k, v in r["attack_reads_by_class"].items():
                        by[k] = by.get(k, 0) + v
                s.update({
                    "video_incident": VIDEO_MAP[fam],
                    "records_attempted": att,
                    "records_released": rel,
                    "released_pct": round(100 * rel / att, 3) if att else None,
                    "released_by_class": by,
                    "max_released_one_world": max(r["attack_read_released"] for r in rs),
                    "nonread_steps_executed": f"{sum(r['attack_nonread_executed'] for r in rs)}"
                                              f"/{sum(r['attack_nonread_steps'] for r in rs)}",
                    "skimmer_went_live": sum(r["skimmer_live"] for r in rs),
                    "nonread_executed_by_type": {t: sum(r["attack_nonread_by"].get(t, 0) for r in rs)
                                                 for t in {t for r in rs for t in r["attack_nonread_by"]}},
                    "median_attack_days": statistics.median(r["attack_days"] for r in rs),
                })
            summary[f"{mode}:{fam or 'no_attack'}"] = s
            print(f"{mode}:{fam or 'no_attack'}", json.dumps({k: v for k, v in s.items() if k != 'video_incident'}),
                  flush=True)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / ("bounded_learned.json" if learned else "bounded.json")).write_text(json.dumps({"summary": summary, "runs": runs}, indent=2))
    return summary

"""End-to-end replay: run simulated org traffic with each incident through the full authority
(policy + canaries + integrity + model + approvals) and measure what the attacker got.

The attacker is persistent: when a step is refused it keeps trying the next steps.
Legitimate actions that get ESCALATE are approved by a second person and re-submitted,
which is the operational cost the report counts.
"""

from __future__ import annotations

import json
import random
import statistics
from pathlib import Path

from . import script_integrity
from .actions import Action
from .audit import AuditLog
from .crypto import Signer
from .engine import ALLOW, DENY, ESCALATE, Authority, sign_approval
from .features import DAY, HOUR
from .grants import GrantIssuer
from .model import RiskModel
from .policy import Policy
from .scenarios import FAMILIES, world

FIX = Path(__file__).resolve().parents[2] / "fixtures"
VOLUME_TYPES = {"secret.read", "data.export", "network.egress", "file.write_bulk", "backup.delete", "repo.history_rewrite"}

VIDEO_MAP = {
    "public_service_pivot": "Fugaku / RIKEN: entry via public status page, 3 days inside, 4,222 users' SSH keys",
    "bulk_exfil": "La Poste / Maileva: 20.9M names and addresses taken, disclosed ~2 months later",
    "supply_chain_publish": "Optimizely: vendor script turned skimmer on customer sites for 19 hours",
    "history_rewrite": "PolinRider (GitHub): commit history rewritten to hide malicious code",
    "ransomware_staging": "Healthcare ransomware: 17 providers posted in one day",
}


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _approver_for(identity: str) -> str:
    return "human:dana" if identity != "human:dana" else "human:bob"


def run_incident(family: str | None, seed: int, model: RiskModel | None, policy: Policy, warmup_days: int = 30) -> dict:
    clock = Clock()
    signer = Signer.generate()
    appr = {n: Signer.generate() for n in ("human:bob", "human:dana", "human:erin")}
    auth = Authority(policy, GrantIssuer(signer, policy.grant_ttl_seconds, now=clock), AuditLog(None, signer, now=clock),
                     model=model, now=clock, approver_keys={n: s.public_key for n, s in appr.items()})
    rng = random.Random(seed)
    v1 = (FIX / "tag_v1.js").read_text()
    skimmer = (FIX / "tag_v2_skimmer.js").read_text()
    live = v1
    auth.record_integrity(script_integrity.check(None, v1) | {"verdict": "pass"})  # baseline accepted at onboarding

    events = world(seed, family)
    attack_start = next((e.action.ts for e in events if e.label), None)
    stats = {"family": family, "seed": seed, "attack_steps": 0, "attack_steps_allowed": 0,
             "attack_volume_total": 0, "attack_volume_allowed": 0, "first_refusal_hours": None,
             "frozen": False, "first_refusal_stage": None,
             "benign_actions": 0, "benign_escalated": 0, "benign_denied": 0, "benign_denied_examples": [],
             "benign_denied_by": {}}
    build = 0
    for e in events:
        a = e.action
        clock.t = a.ts
        if a.ts < warmup_days * DAY:  # monitor mode: learn the baseline, decide nothing
            auth.state.observe(a, learn=True)
            continue

        if a.action_type == "artifact.publish":
            if e.label:
                cand = skimmer
            else:
                build += 1
                cand = v1 + f"\n// build {build}\n"
            rep = script_integrity.check(live, cand)
            auth.record_integrity(rep)
            a = Action(**{**a.to_dict(), "metadata": {"candidate_sha256": rep["candidate_sha256"]}})

        d = auth.decide(a)
        if d.verdict == ESCALATE and not e.label:
            who, why = _approver_for(a.identity), "change ticket CHG-1234 verified"
            aid = auth.approve(d.fingerprint, a.identity, who, why, sign_approval(appr[who], d.fingerprint, a.identity, why))
            d = auth.decide(a, approval_id=aid)
        if a.action_type == "artifact.publish" and d.verdict == ALLOW:
            live = cand

        if e.label:
            stats["attack_steps"] += 1
            vol = a.count if a.action_type in VOLUME_TYPES else 0
            stats["attack_volume_total"] += vol
            if d.verdict == ALLOW:
                stats["attack_steps_allowed"] += 1
                stats["attack_volume_allowed"] += vol
            elif stats["first_refusal_hours"] is None:
                stats["first_refusal_hours"] = round((a.ts - attack_start) / HOUR, 2)
                stats["first_refusal_stage"] = f"{d.verdict}:{d.stage}"
        else:
            stats["benign_actions"] += 1
            if d.verdict == DENY:
                stats["benign_denied"] += 1
                key = f"{a.identity}|{d.stage}"
                stats["benign_denied_by"][key] = stats["benign_denied_by"].get(key, 0) + 1
                if len(stats["benign_denied_examples"]) < 3:
                    stats["benign_denied_examples"].append({"identity": a.identity, "action": a.action_type,
                                                            "reasons": d.reasons})
    if family:
        attacker = next(e.action.identity for e in events if e.label)
        stats["frozen"] = attacker in auth.frozen
        stats["live_script_is_skimmer"] = live == skimmer
    stats["benign_escalated"] = sum(1 for r in auth.audit.records if r["event"].get("type") == "approval")
    stats["days_decided"] = round((events[-1].action.ts - warmup_days * DAY) / DAY, 1)
    return stats


def run(policy_path: str, model_path: str | None, out_dir: str, per_family: int = 6, seed_base: int = 900_000) -> dict:
    policy = Policy.load(policy_path)
    model = RiskModel.load(model_path) if model_path else None
    results = []
    for i, fam in enumerate(list(FAMILIES) + [None]):
        for k in range(per_family):
            r = run_incident(fam, seed_base + 1000 * i + k, model, policy)
            results.append(r)
            print(json.dumps({x: r[x] for x in ("family", "attack_steps", "attack_steps_allowed",
                                                "attack_volume_allowed", "attack_volume_total",
                                                "first_refusal_hours", "first_refusal_stage", "frozen",
                                                "benign_escalated", "benign_denied")}), flush=True)
    summary = {}
    for fam in list(FAMILIES) + [None]:
        rs = [r for r in results if r["family"] == fam]
        key = fam or "no_attack"
        tot_days = sum(r["days_decided"] for r in rs)
        s = {
            "runs": len(rs),
            "benign_approvals_per_day": round(sum(r["benign_escalated"] for r in rs) / tot_days, 2),
            "benign_denied_total": sum(r["benign_denied"] for r in rs),
        }
        if fam:
            vt = sum(r["attack_volume_total"] for r in rs)
            s.update({
                "video_incident": VIDEO_MAP[fam],
                "stopped_before_any_step_succeeded": sum(1 for r in rs if r["attack_steps_allowed"] == 0),
                "attack_steps_allowed": f"{sum(r['attack_steps_allowed'] for r in rs)}/{sum(r['attack_steps'] for r in rs)}",
                "attack_volume_allowed_pct": round(100 * sum(r["attack_volume_allowed"] for r in rs) / vt, 2) if vt else 0.0,
                "median_hours_to_first_refusal": statistics.median(
                    [r["first_refusal_hours"] for r in rs if r["first_refusal_hours"] is not None] or [None]),
                "attacks_never_refused": sum(1 for r in rs if r["first_refusal_hours"] is None),
                "attacker_frozen": f"{sum(r['frozen'] for r in rs)}/{len(rs)}",
            })
            if fam == "supply_chain_publish":
                s["skimmer_went_live"] = sum(r.get("live_script_is_skimmer", False) for r in rs)
        summary[key] = s
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "replay.json").write_text(json.dumps({"summary": summary, "runs": results}, indent=2))
    return summary

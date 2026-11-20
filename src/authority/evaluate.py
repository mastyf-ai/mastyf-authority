"""Train the risk model and measure it honestly.

Two evaluations, both on freshly generated worlds (new seeds) never used in training:
  in_distribution   train on all attack families, test on new worlds of all families
  leave_one_out     for each family, train WITHOUT it and test on it: how the model does
                    against an attack pattern it has never seen (the realistic case)
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from .features import DAY, HOUR
from .model import RiskModel, featurize
from .policy import Policy
from .scenarios import FAMILIES, world


def build(seeds: list[int], families: list[str | None], meta: dict):
    Xs, ys, worlds = [], [], []
    for s, fam in zip(seeds, families):
        ev = world(s, fam)
        X, y, _ = featurize(ev, meta)
        Xs.append(X)
        ys.append(y)
        worlds.append((fam, ev, X, y))
    return np.vstack(Xs), np.concatenate(ys), worlds


def _family_plan(n: int, fams: list[str], benign_share: float = 0.2):
    out: list[str | None] = []
    k = 0
    for i in range(n):
        if i % int(1 / benign_share) == 0:
            out.append(None)
        else:
            out.append(fams[k % len(fams)])
            k += 1
    return out


def score_worlds(model: RiskModel, worlds, escalate_at: float, deny_at: float, warmup_days: int = 30) -> dict:
    pos_scores, neg_scores = [], []
    detected, delays, n_incidents = 0, [], 0
    benign_flags, benign_days = 0, 0
    per_family: dict[str, list[int]] = {}
    for fam, ev, X, y in worlds:
        s = model.score_many(X)
        ts = np.array([e.action.ts for e in ev])
        after = ts >= warmup_days * DAY
        pos = (y == 1)
        neg = (y == 0) & after
        pos_scores.extend(s[pos].tolist())
        neg_scores.extend(s[neg].tolist())
        benign_flags += int((s[neg] >= escalate_at).sum())
        benign_days += (ts.max() - warmup_days * DAY) / DAY
        if fam:
            n_incidents += 1
            idx = np.where(pos)[0]
            flagged = idx[s[idx] >= escalate_at]
            hit = len(flagged) > 0
            per_family.setdefault(fam, []).append(int(hit))
            if hit:
                detected += 1
                delays.append((ts[flagged[0]] - ts[idx[0]]) / HOUR)
    out = {
        "attack_events": len(pos_scores),
        "benign_events": len(neg_scores),
        "auroc": round(float(roc_auc_score([1] * len(pos_scores) + [0] * len(neg_scores), pos_scores + neg_scores)), 4)
        if pos_scores else None,
        "attack_event_recall_at_escalate": round(float(np.mean(np.array(pos_scores) >= escalate_at)), 4) if pos_scores else None,
        "attack_event_recall_at_deny": round(float(np.mean(np.array(pos_scores) >= deny_at)), 4) if pos_scores else None,
        "incidents": n_incidents,
        "incidents_detected": detected,
        "incident_detection_rate": round(detected / n_incidents, 4) if n_incidents else None,
        "median_hours_to_first_flag": round(statistics.median(delays), 2) if delays else None,
        "benign_false_flags_per_day": round(benign_flags / max(benign_days, 1e-9), 3),
        "benign_false_flag_rate": round(benign_flags / max(len(neg_scores), 1), 5),
        "per_family_detection": {k: f"{sum(v)}/{len(v)}" for k, v in per_family.items()},
    }
    return out


def run(policy_path: str, out_dir: str, n_train: int = 100, n_test: int = 50, seed_base: int = 1000) -> dict:
    policy = Policy.load(policy_path)
    meta = policy.identity_meta()
    fams = list(FAMILIES)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report: dict = {"note": "synthetic data; numbers describe this simulation only",
                    "thresholds": {"escalate_at": policy.escalate_at, "deny_at": policy.deny_at}}

    train_seeds = list(range(seed_base, seed_base + n_train))
    test_seeds = list(range(seed_base + 50_000, seed_base + 50_000 + n_test))

    X, y, _ = build(train_seeds, _family_plan(n_train, fams), meta)
    model = RiskModel.train(X, y)
    model.meta.update({"train_worlds": n_train, "policy_version": policy.version})
    model.save(out / "risk_model.json")
    _, _, test_worlds = build(test_seeds, _family_plan(n_test, fams), meta)
    report["in_distribution"] = score_worlds(model, test_worlds, policy.escalate_at, policy.deny_at)
    print("in-distribution:", json.dumps(report["in_distribution"], indent=1), flush=True)

    loo = {}
    for i, held in enumerate(fams):
        others = [f for f in fams if f != held]
        Xh, yh, _ = build([s + 7_000 * (i + 1) for s in train_seeds], _family_plan(n_train, others), meta)
        m = RiskModel.train(Xh, yh)
        held_seeds = [s + 100_000 + 1_000 * i for s in range(n_test // 2)]
        _, _, hw = build(held_seeds, [held] * len(held_seeds), meta)
        _, _, bw = build([s + 200_000 + 1_000 * i for s in range(max(4, n_test // 10))],
                         [None] * max(4, n_test // 10), meta)
        loo[held] = score_worlds(m, hw + bw, policy.escalate_at, policy.deny_at)
        print(f"held out {held}:", json.dumps(loo[held]), flush=True)
    report["leave_one_family_out"] = loo
    (out / "eval.json").write_text(json.dumps(report, indent=2))
    return report

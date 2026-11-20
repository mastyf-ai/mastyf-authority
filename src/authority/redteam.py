"""Adaptive red team: an attacker that learns to evade the system.

The attacker controls one stolen identity for 14 days after the baseline period. It sees
only what a real attacker sees: whether each attempt gave it data. It searches over
strategies with random search then hill-climbing, re-running a fresh simulated org for
every candidate. Objective: records released to the attacker.

Strategy space:
  identity      human:alice | svc:export-job
  verb          data.read (records land in the attacker's session) | data.export
  destination   attacker host | a bucket the attacker names to match an allowlist pattern
                ("s3://corp-partner-x9") | the real warehouse (not a loss: the data stays home)
  chunk         records per request (10 .. 200k, log scale)
  every_h       hours between requests
  hour0, span   active hours window (mimic office hours or not)

Everything is real pipeline: authority (policy, model, approvals refused for the attacker),
key service with budgets, freezing.
"""

from __future__ import annotations

import json
import math
import random

import numpy as np
from pathlib import Path

from .actions import Action
from .audit import AuditLog
from .budgets import READ_ACTIONS, BudgetPolicy, KeyService
from .crypto import Signer
from .engine import ALLOW, ESCALATE, Authority, sign_approval
from .features import DAY, HOUR
from .grants import GrantIssuer
from .learn import learn_data_budgets, learn_novelty
from .model import RiskModel
from .policy import Policy
from .replay import Clock
from .scenarios import world

DESTS = {
    "attacker_host": "https://files.k7q2.net/u",
    "spoofed_bucket": "s3://corp-partner-x9/drop",
    "warehouse": "s3://corp-warehouse/nightly",
}
LOSS_DESTS = {"attacker_host", "spoofed_bucket"}  # attacker controls these
WARMUP, ATTACK_DAYS, TOTAL = 30, 14, 44


def random_strategy(rng: random.Random) -> dict:
    return {
        "identity": rng.choice(["human:alice", "svc:export-job"]),
        "verb": rng.choice(["data.read", "data.export"]),
        "dest": rng.choice(list(DESTS)),
        "log_chunk": rng.uniform(math.log(10), math.log(200_000)),
        "every_h": rng.uniform(0.5, 48),
        "hour0": rng.randint(0, 23),
        "span": rng.randint(1, 24),
        "harvest": rng.choice(["random", "portfolio"]),
    }


def mutate(s: dict, rng: random.Random) -> dict:
    s = dict(s)
    k = rng.choice(list(s))
    if k == "identity":
        s[k] = rng.choice(["human:alice", "svc:export-job"])
    elif k == "verb":
        s[k] = rng.choice(["data.read", "data.export"])
    elif k == "dest":
        s[k] = rng.choice(list(DESTS))
    elif k == "log_chunk":
        s[k] = min(math.log(200_000), max(math.log(10), s[k] + rng.gauss(0, 0.7)))
    elif k == "every_h":
        s[k] = min(48, max(0.5, s[k] * math.exp(rng.gauss(0, 0.5))))
    elif k == "harvest":
        s[k] = rng.choice(["random", "portfolio"])
    elif k == "hour0":
        s[k] = (s[k] + rng.randint(-4, 4)) % 24
    else:
        s[k] = min(24, max(1, s[k] + rng.randint(-4, 4)))
    return s


def _attack_events(s: dict, rng: random.Random) -> list[Action]:
    out, t = [], WARMUP * DAY + rng.uniform(0, DAY)
    resource = "db://crm/customers/query" if s["verb"] == "data.read" else "db://crm/customers"
    chunk = int(math.exp(s["log_chunk"]))
    while t < TOTAL * DAY:
        hour = (t % DAY) / HOUR
        in_window = (hour - s["hour0"]) % 24 < s["span"]
        if in_window:
            dest = DESTS[s["dest"]] if s["verb"] == "data.export" else None
            out.append(Action(s["identity"], s["verb"], resource, chunk, destination=dest, ts=t))
            t += s["every_h"] * HOUR * rng.uniform(0.8, 1.2)
        else:
            t += HOUR
    return out


N_CUSTOMERS = 1_000_000
PORTFOLIO = 3_000


class RecordModel:
    """Which customer records each read touches. Alice works a book of ~3,000 customers and keeps
    revisiting them (Zipf-like); ~2% of rows are customers outside her book."""

    def __init__(self, seed: int):
        self.r = np.random.default_rng(seed)
        pool = np.array([x for x in self.r.choice(N_CUSTOMERS, PORTFOLIO * 2, replace=False) if not self.is_bait(int(x))])
        self.portfolio = pool[:PORTFOLIO]
        w = 1.0 / np.arange(1, PORTFOLIO + 1) ** 1.1
        self.p = w / w.sum()

    @staticmethod
    def is_bait(x: int) -> bool:
        return x % 1000 == 7 and x >= 1000  # ids ending in "007": 0.1% of customers are bait records

    def _pad(self, ids: set, n: int, legit: bool = True) -> list[str]:
        while len(ids) < n:
            x = int(self.r.integers(0, N_CUSTOMERS))
            if legit and self.is_bait(x):
                continue  # legitimate screens never return bait records
            ids.add(x)
        return [f"c{x}" for x in ids]

    def benign(self, n: int) -> list[str]:
        n_out = int(self.r.binomial(n, 0.02))
        k = min(n - n_out, PORTFOLIO)
        ids = set(self.r.choice(self.portfolio, k, replace=False, p=self.p).tolist())
        return self._pad(ids, n)

    def attack(self, n: int, mode: str, stolen: set) -> list[str]:
        if mode == "portfolio":  # mimic: only alice's own customers, the ones not yet taken first
            fresh = [x for x in self.portfolio.tolist() if f"c{x}" not in stolen]
            pick = self.r.choice(fresh, min(n, len(fresh)), replace=False).tolist() if fresh else []
            ids = set(pick)
            while len(ids) < n:
                ids.add(int(self.r.choice(self.portfolio)))
                if len(ids) >= len(self.portfolio):
                    break
            return self._pad(ids, n)
        return self._pad(set(), n, legit=False)


def evaluate(s: dict, seed: int, model: RiskModel | None, policy: Policy, learned: bool = True,
             novelty: bool = False, bait: bool = False) -> dict:
    rng = random.Random(seed)
    clock = Clock()
    signer = Signer.generate()
    issuer = GrantIssuer(signer, policy.grant_ttl_seconds, now=clock)
    appr = {n: Signer.generate() for n in ("human:bob", "human:dana", "human:erin")}
    auth = Authority(policy, issuer, AuditLog(None, signer, now=clock), model=model, now=clock,
                     approver_keys={n: s.public_key for n, s in appr.items()})
    benign = [e.action for e in world(seed, None, days=TOTAL)]
    bp = BudgetPolicy.from_dict(policy.raw["data_budgets"])
    if learned:
        bp = BudgetPolicy(bp.classes, learn_data_budgets([a for a in benign if a.ts < WARMUP * DAY], bp.classes))
    recs = RecordModel(seed + 7)
    with_ids = []
    for a in benign:  # attach record ids to alice's customer reads/exports (her real working pattern)
        if a.identity == "human:alice" and bp.classify(a.resource) == "crm.customer":
            a = Action(**{**a.to_dict(), "metadata": {"record_ids": recs.benign(a.count)}})
        with_ids.append(a)
    benign = with_ids
    if novelty:
        hist = [(a.ts, a.identity, "crm.customer", a.metadata["record_ids"]) for a in benign
                if a.ts < WARMUP * DAY and "record_ids" in a.metadata]
        bp.novelty = learn_novelty(hist)
    ks = KeyService(bp, signer.public_key, {}, now=clock, custody=False)
    if bait:
        bp.canary_records = ["c*007"]  # ids ending in 007 = x % 1000 == 7
    attack = _attack_events(s, rng)
    evs = sorted([(a, 0) for a in benign] + [(a, 1) for a in attack], key=lambda x: x[0].ts)
    stolen = attempts = benign_refused = 0
    taken: set[str] = set()
    detected_at = None
    for a, mal in evs:
        clock.t = a.ts
        if a.ts < WARMUP * DAY:
            auth.state.observe(a, learn=True)
            if a.action_type in READ_ACTIONS and bp.classify(a.resource):
                cls = bp.classify(a.resource)
                key, _ = bp.budget(a.identity, cls, a.destination)
                ks.ledger[(a.identity, key)].append((a.ts, a.count))
                ids = a.metadata.get("record_ids")
                if ids and bp.novelty_for(a.identity, cls):
                    seen = ks.seen[(a.identity, cls)]
                    new = sum(1 for r in ids if r not in seen)
                    for r in ids:
                        seen[r] = a.ts
                    ks.new_ledger[(a.identity, cls)].append((a.ts, new))
            continue
        d = auth.decide(a)
        if not mal:
            if d.verdict == ESCALATE:  # the real owner's legitimate work still gets approved
                who = "human:dana" if a.identity != "human:dana" else "human:erin"
                aid = auth.approve(d.fingerprint, a.identity, who, "CHG verified",
                                   sign_approval(appr[who], d.fingerprint, a.identity, "CHG verified"))
                d = auth.decide(a, approval_id=aid)
            if d.verdict == ALLOW and a.action_type in READ_ACTIONS and bp.classify(a.resource):
                if not ks.release(d.grant, a).ok and "record_ids" in a.metadata:
                    benign_refused += 1
            continue
        attempts += 1
        a = Action(**{**a.to_dict(), "metadata": {"record_ids": recs.attack(a.count, s.get("harvest", "random"), taken)}})
        if d.verdict != ALLOW:
            if detected_at is None:
                detected_at = a.ts
            continue
        r = ks.release(d.grant, a)
        loss = r.ok and (a.action_type == "data.read" or s["dest"] in LOSS_DESTS)
        if loss:
            stolen += a.count
            taken.update(a.metadata["record_ids"])
    return {"stolen": len(taken), "rows_released": stolen, "attempts": attempts,
            "benign_refused": benign_refused,
            "first_refusal_h": round((detected_at - WARMUP * DAY) / HOUR, 1) if detected_at else None,
            "frozen": s["identity"] in auth.frozen or s["identity"] in ks.frozen}


def search(policy_path: str, model_path: str | None, out_dir: str, budget: int = 120, seed: int = 0,
           learned: bool = True, novelty: bool = False) -> dict:
    policy = Policy.load(policy_path)
    model = RiskModel.load(model_path) if model_path else None
    rng = random.Random(seed)
    history, best = [], None
    n_random = budget // 3
    for i in range(budget):
        cand = random_strategy(rng) if i < n_random or best is None else mutate(best[0], rng)
        # score on two different orgs so a lucky world does not decide
        r1 = evaluate(cand, 10_000 + i, model, policy, learned, novelty)
        r2 = evaluate(cand, 20_000 + i, model, policy, learned, novelty)
        score = min(r1["stolen"], r2["stolen"])
        history.append({"i": i, "strategy": cand, "score": score, "runs": [r1, r2]})
        if best is None or score > best[1]:
            best = (cand, score, [r1, r2])
            print(f"[{i}] new best: {score} records  {json.dumps(cand)}  {r1}", flush=True)
    top = sorted(history, key=lambda h: -h["score"])[:10]
    out = {"best_strategy": best[0], "best_stolen_min_of_2": best[1], "best_runs": best[2],
           "evaluations": budget * 2, "top10": top, "learned_budgets": learned, "novelty": novelty}
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / f"redteam{'_learned' if learned else ''}{'_novelty' if novelty else ''}.json").write_text(json.dumps(out, indent=2))
    return out

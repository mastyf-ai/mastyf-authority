"""The damage ceiling must hold against the real key service, and be tight.

An attacker who bypassed the authority (it signs its own grants) and controls k identities, including
any approvers among them, hammers the key service every hour for 30 days, probing for the largest
release that succeeds, on every budget key and destination, with overrun signatures from its
approvers. It must never exceed the computed ceiling, and should reach it."""

import json
from pathlib import Path

import pytest

from authority.actions import Action
from authority.budgets import BudgetPolicy, KeyService, overrun_message
from authority.ceiling import INF, Threat, compute
from authority.crypto import Signer, b64d, b64e
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "policies/default.json").read_text())
RES = {"ssh.key": "vault://prod/ssh/hosts", "secret": "vault://prod/db", "crm.customer": "db://crm/customers/query",
       "prod.files": "fs://prod/data", "system.config": "fs://login-node/etc"}
HOUR = 3600


def attack(group: list[str], days: int = 30) -> dict:
    t = [1_800_000_000.0]
    clock = lambda: t[0]  # noqa: E731
    auth = Signer.generate()
    approvers = {n for n, r in POLICY["identities"].items() if r.get("approver")}
    keys = {n: Signer.generate() for n in approvers}
    bp = BudgetPolicy.from_dict(POLICY["data_budgets"])
    ks = KeyService(bp, auth.public_key, {n: k.public_key for n, k in keys.items()}, now=clock, custody=False)
    iss = GrantIssuer(auth, 600, now=clock)  # authority bypassed: attacker gets any grant
    got: dict[str, list] = {c: [] for c in RES}

    def try_release(ident, cls, dest, n, overrun):
        a = Action(ident, "data.export" if dest else "data.read", RES[cls], n, destination=dest, ts=t[0])
        g = iss.issue(a, "attacker")
        sigs = None
        if overrun:
            gid = json.loads(b64d(g.split(".")[0]))["gid"]
            sigs = [{"approver": s, "amount": n, "sig": b64e(keys[s].sign(overrun_message(gid, n)))} for s in overrun]
        return ks.release(g, a, sigs).ok

    def greedy(ident, cls, dest, overrun):
        """Take as much as the key service will give right now (probe sizes halving from 4 M)."""
        total, step = 0, 1 << 22
        while step:
            if try_release(ident, cls, dest, step, overrun):
                total += step
            else:
                step //= 2
        return total

    for h in range(days * 24):
        t[0] = 1_800_000_000.0 + h * HOUR
        for ident in group:
            on_side = [a for a in group if a in approvers and a != ident]
            sigs = on_side[:2] if len(on_side) >= 2 else None
            for cls in RES:
                dests = [None] + [k.split("@", 1)[1] for k in bp.budgets.get(ident, {}) if k.startswith(cls + "@")]
                for d in dests:
                    n = greedy(ident, cls, d, None)
                    if sigs:
                        n += greedy(ident, cls, d, sigs)
                    if n:
                        got[cls].append((t[0], n))
    return got


def rolling_max(events: list) -> int:
    best = 0
    for i, (t, _) in enumerate(events):
        best = max(best, sum(n for t2, n in events if t - 86400 < t2 <= t))
    return best


CASES = [["human:alice"], ["human:bob"], ["svc:export-job"], ["svc:backup"],
         ["human:bob", "human:dana", "svc:export-job"], ["human:alice", "human:dana", "human:erin"]]


@pytest.mark.parametrize("group", CASES, ids=lambda g: "+".join(g))
def test_attacker_never_beats_the_ceiling_and_reaches_it(group):
    ceil = compute(POLICY, Threat(k=len(group)))
    got = attack(group, days=6)
    for cls, ev in got.items():
        # ceiling for exactly this group (not the worst group): recompute from the per-identity rules
        from authority.ceiling import identity_ceiling
        approvers = set(ceil["threat"]["approvers"])
        per_day = sum(identity_ceiling(BudgetPolicy.from_dict(POLICY["data_budgets"]), i, cls,
                                       len([a for a in group if a in approvers and a != i]), Threat())["per_day"]
                      for i in group)
        assert per_day != INF
        total, peak = sum(n for _, n in ev), rolling_max(ev)
        assert peak <= per_day, (cls, peak, per_day)
        assert total <= per_day * 6, (cls, total, per_day * 6)
        assert total >= per_day * 6 * 0.95, (cls, total, per_day * 6)  # tight: the greedy attacker gets it
    # and the worst group the calculator names is at least as bad as this one
    for cls in got:
        assert ceil["worst_case_by_class"][cls]["per_day"] >= sum(n for t, n in got[cls] if t < 1_800_000_000 + 86400)

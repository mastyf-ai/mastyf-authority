import json
from pathlib import Path

from authority.actions import Action
from authority.budgets import BudgetPolicy, KeyService
from authority.crypto import Signer
from authority.grants import GrantIssuer
from authority.quorum import QuorumVerifier, bundle

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    t = 100 * 86400.0

    def __call__(self):
        return self.t


def setup(t=2, n=3):
    clock = Clock()
    nodes = {f"node{i}": Signer.generate() for i in range(n)}
    qv = QuorumVerifier({k: s.public_key for k, s in nodes.items()}, t, now=clock)
    bp = BudgetPolicy.from_dict(json.loads((ROOT / "policies/default.json").read_text())["data_budgets"])
    ks = KeyService(bp, None, {}, now=clock, verifier=qv)
    issuers = {k: GrantIssuer(s, 60, now=clock) for k, s in nodes.items()}
    return ks, issuers, clock


def act(clock, n=10):
    return Action("human:alice", "data.read", "db://crm/customers/query", n, ts=clock.t)


def test_single_compromised_node_cannot_release():
    ks, iss, clock = setup()
    a = act(clock)
    assert not ks.release(bundle([iss["node0"].issue(a, "x")]), a).ok
    # the same node signing twice does not count twice
    assert not ks.release(bundle([iss["node0"].issue(a, "x"), iss["node0"].issue(a, "y")]), a).ok
    # a node outside the set does not count
    rogue = GrantIssuer(Signer.generate(), 60, now=clock)
    assert not ks.release(bundle([iss["node0"].issue(a, "x"), rogue.issue(a, "x")]), a).ok


def test_two_of_three_releases_and_strictest_factor_applies():
    ks, iss, clock = setup()
    a = act(clock, 3000)
    ok = bundle([iss["node0"].issue(a, "x"), iss["node2"].issue(a, "x")])
    assert ks.release(ok, a).ok
    b = act(clock, 1000)  # alice has 5000/day; 3000 used; node1 shrinks budget to 50% -> 2500
    tight = bundle([iss["node0"].issue(b, "x"), iss["node1"].issue(b, "x", {"budget_factor": 0.5})])
    assert not ks.release(tight, b).ok


def test_grants_for_different_actions_do_not_combine():
    ks, iss, clock = setup()
    a, other = act(clock, 10), act(clock, 4000)
    assert not ks.release(bundle([iss["node0"].issue(a, "x"), iss["node1"].issue(other, "x")]), other).ok

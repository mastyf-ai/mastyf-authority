import json
from pathlib import Path

import pytest

from authority.actions import Action
from authority.budgets import BudgetPolicy, EncryptedStore, KeyService, overrun_message
from authority.crypto import Signer, b64d, b64e
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    t = 100 * 86400.0

    def __call__(self):
        return self.t


@pytest.fixture
def env():
    clock = Clock()
    bp = BudgetPolicy.from_dict(json.loads((ROOT / "policies/default.json").read_text())["data_budgets"])
    authority = Signer.generate()
    approvers = {n: Signer.generate() for n in ("human:bob", "human:dana", "human:erin")}
    ks = KeyService(bp, authority.public_key, {n: s.public_key for n, s in approvers.items()}, now=clock)
    issuer = GrantIssuer(authority, 60, now=clock)
    return ks, issuer, approvers, clock


def read(clock, identity, resource, n, **meta):
    return Action(identity, "data.read", resource, n, ts=clock.t, metadata=meta)


def sigs(approvers, names, grant, amount):
    gid = json.loads(b64d(grant.split(".")[0]))["gid"]
    return [{"approver": n, "amount": amount, "sig": b64e(approvers[n].sign(overrun_message(gid, amount)))}
            for n in names]


def test_db_dump_is_ciphertext_and_keys_need_budget(env):
    ks, issuer, _, clock = env
    store = EncryptedStore(ks, "crm.customer")
    for i in range(5):
        store.put(f"r{i}", f"Jean Dupont {i}, 1 rue de Paris".encode())
    assert all(b"Dupont" not in b64d(v) for v in store.dump().values())
    a = read(clock, "human:alice", "db://crm/customers/query", 2, record_ids=["r0", "r1"])
    r = ks.release(issuer.issue(a, "d1"), a)
    assert r.ok and set(r.keys) == {"r0", "r1"}
    assert EncryptedStore.open("r0", store.rows["r0"], r.keys["r0"]).startswith(b"Jean Dupont 0")


def test_budget_caps_reads_even_with_valid_grants(env):
    ks, issuer, _, clock = env
    released = 0
    for _ in range(20):  # a fully compromised authority hands out valid grants for everything
        clock.t += 60
        a = read(clock, "human:alice", "db://crm/customers/query", 1000)
        if ks.release(issuer.issue(a, "x"), a).ok:
            released += 1000
    assert released == 5000  # alice's 24h read budget
    clock.t += 86400  # rolling window frees the budget again
    a = read(clock, "human:alice", "db://crm/customers/query", 1000)
    assert ks.release(issuer.issue(a, "x"), a).ok


def test_zero_budget_and_unclassified_fail_closed(env):
    ks, issuer, _, clock = env
    a = Action("svc:status-page", "secret.read", "fs://home/users/.ssh", 1, ts=clock.t)
    assert not ks.release(issuer.issue(a, "x"), a).ok
    b = read(clock, "human:alice", "db://unknown/table", 1)
    assert not ks.release(issuer.issue(b, "x"), b).ok


def test_overrun_needs_two_distinct_non_requester_approvers(env):
    ks, issuer, approvers, clock = env
    ks.policy.overrun_max["human:bob"]["ssh.key"] = 1000  # this test is about the signatures, not the cap
    a = Action("human:bob", "secret.read", "vault://prod/ssh/hosts", 300, ts=clock.t)
    g = issuer.issue(a, "x")
    assert not ks.release(g, a, sigs(approvers, ["human:dana"], g, 300)).ok  # one signer
    g = issuer.issue(a, "x")
    assert not ks.release(g, a, sigs(approvers, ["human:bob", "human:dana"], g, 300)).ok  # requester signs
    g = issuer.issue(a, "x")
    forged = sigs(approvers, ["human:dana", "human:erin"], g, 300)
    forged[1]["sig"] = forged[0]["sig"]
    assert not ks.release(g, a, forged).ok
    g = issuer.issue(a, "x")
    other = issuer.issue(a, "y")  # signatures for a different grant do not transfer
    assert not ks.release(g, a, sigs(approvers, ["human:dana", "human:erin"], other, 300)).ok
    g = issuer.issue(a, "x")
    assert ks.release(g, a, sigs(approvers, ["human:dana", "human:erin"], g, 300)).ok
    g = issuer.issue(a, "x")
    assert not ks.release(g, a, sigs(approvers, ["human:dana", "human:erin"], g, 299)).ok  # approved less than requested


def test_model_factor_only_shrinks(env):
    ks, issuer, _, clock = env
    a = read(clock, "human:alice", "db://crm/customers/query", 5000)
    assert not ks.release(issuer.issue(a, "x", {"budget_factor": 0.5}), a).ok  # 8000 * 0.5 < 5000
    assert ks.release(issuer.issue(a, "x", {"budget_factor": 7.0}), a).ok  # clamped to 1.0: 5000 <= 8000
    b = read(clock, "human:alice", "db://crm/customers/query", 3001)
    assert not ks.release(issuer.issue(b, "x", {"budget_factor": 7.0}), b).ok  # still capped at 8000


def test_grant_from_other_key_rejected(env):
    ks, _, _, clock = env
    a = read(clock, "human:alice", "db://crm/customers/query", 1)
    rogue = GrantIssuer(Signer.generate(), 60, now=clock)
    assert not ks.release(rogue.issue(a, "x"), a).ok


def test_export_budget_is_bound_to_destination(env):
    ks, issuer, _, clock = env
    ok = Action("svc:export-job", "data.export", "db://crm/customers", 9000, destination="s3://corp-warehouse/nightly", ts=clock.t)
    assert ks.release(issuer.issue(ok, "x"), ok).ok
    bad = Action("svc:export-job", "data.export", "db://crm/customers", 10, destination="https://files.attacker.net/u", ts=clock.t)
    r = ks.release(issuer.issue(bad, "x"), bad)
    assert not r.ok and r.remaining == 0


def test_future_timestamps_do_not_reset_the_budget(env):
    ks, issuer, _, clock = env
    released = 0
    for i in range(20):  # attacker claims every request happened a day later than the last
        a = Action("human:alice", "data.read", "db://crm/customers/query", 1000, ts=clock.t + 86400 * (i + 1))
        if ks.release(issuer.issue(a, "x"), a).ok:
            released += 1000
    assert released == 5000


def test_spoofed_bucket_name_gets_no_budget(env):
    ks, issuer, _, clock = env
    a = Action("human:alice", "data.export", "db://crm/customers", 10, destination="s3://corp-partner-x9/drop", ts=clock.t)
    assert not ks.release(issuer.issue(a, "x"), a).ok


def test_overrun_cap_holds_even_with_valid_signatures(env):
    ks, issuer, approvers, clock = env  # default policy: bob may get at most 50 ssh keys of overrun per 24 h
    a = Action("human:bob", "secret.read", "vault://prod/ssh/hosts", 100, ts=clock.t)
    assert ks.release(issuer.issue(a, "x"), a).ok  # the budget itself
    b = Action("human:bob", "secret.read", "vault://prod/ssh/hosts", 40, ts=clock.t)
    g = issuer.issue(b, "x")
    assert ks.release(g, b, sigs(approvers, ["human:dana", "human:erin"], g, 40)).ok
    g = issuer.issue(b, "x")
    r = ks.release(g, b, sigs(approvers, ["human:dana", "human:erin"], g, 40))
    assert not r.ok and r.reason.startswith("overrun cap")

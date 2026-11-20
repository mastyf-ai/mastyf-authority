"""Property-based fuzzing: random and malformed inputs must never crash the system or
produce an allow/release they should not."""

import json
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from authority import script_integrity
from authority.actions import ACTION_TYPES, Action
from authority.audit import AuditLog
from authority.budgets import BudgetPolicy, KeyService
from authority.crypto import Signer, b64e
from authority.engine import ALLOW, Authority
from authority.grants import GrantError, GrantIssuer, GrantVerifier
from authority.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
POLICY = Policy.load(ROOT / "policies/default.json")
SETTINGS = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])

json_scalar = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True), st.text(max_size=50))
json_val = st.recursive(json_scalar, lambda c: st.one_of(st.lists(c, max_size=4),
                                                        st.dictionaries(st.text(max_size=10), c, max_size=4)),
                        max_leaves=10)
identities = st.sampled_from(list(POLICY.identities) + ["human:mallory", "", "svc:status-page\x00"])
resources = st.one_of(st.text(max_size=80), st.sampled_from([
    "db://crm/customers/query", "db://crm/customers/canary-1", "vault://prod/ssh/hosts", "fs://home/users/.ssh",
    "github://org/app/main", "github://org/app/../main", "cdn://static/js/tag.js"]))


def fresh():
    s = Signer.generate()
    t = [1e6]
    now = lambda: t[0]  # noqa: E731
    return Authority(POLICY, GrantIssuer(s, 60, now=now), AuditLog(None, s, now=now), model=None, now=now), s


@SETTINGS
@given(st.dictionaries(st.sampled_from(["identity", "action_type", "resource", "count", "destination", "ts",
                                        "session", "metadata", "extra"]), json_val, max_size=9))
def test_decide_never_crashes_on_garbage(raw):
    auth, _ = fresh()
    d = auth.decide(raw)
    assert d.verdict in ("ALLOW", "ESCALATE", "DENY")


@SETTINGS
@given(identities, st.sampled_from(ACTION_TYPES), resources, st.integers(0, 10**12),
       st.one_of(st.none(), st.text(max_size=60)))
def test_allow_only_for_permitted_known_identities(identity, atype, resource, count, dest):
    auth, _ = fresh()
    try:
        a = Action(identity or "x", atype, resource or "r", count, destination=dest or None, ts=1e6)
    except Exception:
        return
    d = auth.decide(a)
    if d.verdict == ALLOW:
        rule = POLICY.identities[a.identity]
        assert a.action_type in rule.allowed_actions
        assert not POLICY.is_canary(a.resource, a.metadata)
        assert d.grant


@SETTINGS
@given(st.text(max_size=300))
def test_garbage_grants_never_verify(token):
    v = GrantVerifier(Signer.generate().public_key, now=lambda: 1e6)
    a = Action("human:alice", "data.read", "db://crm/customers/query", 1, ts=1e6)
    try:
        v.verify(token, a)
        raise AssertionError("garbage token verified")
    except GrantError:
        pass


@SETTINGS
@given(st.binary(max_size=200), st.dictionaries(st.text(max_size=8), json_scalar, max_size=5))
def test_forged_payload_with_wrong_signature_rejected(sig, payload):
    v = GrantVerifier(Signer.generate().public_key, now=lambda: 1e6)
    a = Action("human:alice", "data.read", "db://crm/customers/query", 1, ts=1e6)
    payload.update({"fp": a.fingerprint(), "exp": 2e6, "gid": "g"})
    tok = b64e(json.dumps(payload).encode()) + "." + b64e(sig)
    try:
        v.verify(tok, a)
        raise AssertionError("forged grant verified")
    except GrantError:
        pass


@SETTINGS
@given(st.lists(st.tuples(st.sampled_from(["human:alice", "human:bob", "svc:status-page", "svc:export-job"]),
                          st.sampled_from(["data.read", "secret.read", "data.export"]),
                          st.sampled_from(["db://crm/customers/query", "vault://prod/ssh/hosts", "vault://prod/db",
                                           "fs://home/users/.ssh", "db://crm/customers"]),
                          st.integers(0, 50_000),
                          st.sampled_from([None, "s3://corp-warehouse/x", "https://evil.net/u", "s3://corp-reports/w"]),
                          st.floats(0, 3 * 86400)), max_size=40))
def test_key_service_never_releases_more_than_budget_in_any_24h(ops):
    """Invariant: for every (identity, budget key), released volume in any 24 h window <= budget,
    even when every request carries a valid grant (authority fully compromised)."""
    s = Signer.generate()
    t = [0.0]
    ks = KeyService(BudgetPolicy.from_dict(POLICY.raw["data_budgets"]), s.public_key, {}, now=lambda: t[0])
    iss = GrantIssuer(s, 60, now=lambda: t[0])
    released = []
    for ident, atype, res, n, dest, dt in sorted(ops, key=lambda o: o[5]):
        t[0] = dt
        a = Action(ident, atype, res, n, destination=dest, ts=dt)
        r = ks.release(iss.issue(a, "x"), a)
        if r.ok:
            key, cap = ks.policy.budget(ident, r.data_class, dest)
            released.append((dt, ident, key, n, cap))
    for t0, ident, key, _, cap in released:
        window = sum(n for t1, i, k, n, _ in released if i == ident and k == key and t0 - 86400 < t1 <= t0)
        assert window <= cap


@SETTINGS
@given(st.text(max_size=3000), st.one_of(st.none(), st.text(max_size=3000)))
def test_script_check_total_on_any_input(candidate, previous):
    rep = script_integrity.check(previous, candidate)
    assert rep["verdict"] in ("pass", "review", "block")

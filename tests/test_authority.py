import dataclasses
import json
from pathlib import Path

import pytest

from authority import script_integrity
from authority.actions import Action
from authority.audit import AuditLog, verify_log
from authority.crypto import Signer
from authority.engine import ALLOW, DENY, ESCALATE, Authority, sign_approval
from authority.grants import GrantError, GrantIssuer, GrantVerifier
from authority.policy import Policy

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    t = 40 * 86400.0

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    policy = Policy.load(ROOT / "policies/default.json")
    signer = Signer.generate()
    audit = AuditLog(tmp_path / "audit.jsonl", signer, now=clock)
    appr = {n: Signer.generate() for n in ("human:bob", "human:dana", "human:erin", "human:alice")}
    auth = Authority(policy, GrantIssuer(signer, 60, now=clock), audit, model=None, now=clock,
                     approver_keys={n: s.public_key for n, s in appr.items() if n != "human:alice"})
    real_approve = auth.approve

    def approve(fp, requester, approver, reason, signature=None):  # tests sign as the named approver
        sig = signature if signature is not None else sign_approval(appr[approver], fp, requester, reason)
        return real_approve(fp, requester, approver, reason, sig)

    auth.approve = approve
    auth._appr = appr
    return auth, clock, signer, tmp_path


def act(clock, **kw):
    kw.setdefault("ts", clock.t)
    return Action(**kw)


def test_malformed_and_unknown_fail_closed(env):
    auth, clock, *_ = env
    assert auth.decide({"identity": "human:alice"}).verdict == DENY
    assert auth.decide({"identity": "x", "action_type": "nope", "resource": "r"}).verdict == DENY
    d = auth.decide(act(clock, identity="human:mallory", action_type="data.read", resource="db://x"))
    assert d.verdict == DENY and "unknown identity" in d.reasons[0]


def test_not_permitted_action_denied(env):
    auth, clock, *_ = env
    d = auth.decide(act(clock, identity="svc:status-page", action_type="secret.read", resource="fs://home/users/.ssh", count=10))
    assert d.verdict == DENY and d.stage == "policy"


def test_canary_freezes_identity(env):
    auth, clock, *_ = env
    d = auth.decide(act(clock, identity="human:alice", action_type="data.read", resource="db://crm/customers/canary-7"))
    assert d.verdict == DENY and d.stage == "canary"
    d2 = auth.decide(act(clock, identity="human:alice", action_type="data.read", resource="db://crm/customers/query"))
    assert d2.verdict == DENY and "frozen" in d2.reasons[0]


def test_protected_branch_rewrite_denied(env):
    auth, clock, *_ = env
    d = auth.decide(act(clock, identity="human:carol", action_type="repo.history_rewrite", resource="github://org/app/main", count=3))
    assert d.verdict == DENY


def test_no_model_means_sensitive_escalates(env):
    auth, clock, *_ = env
    d = auth.decide(act(clock, identity="svc:export-job", action_type="data.export", resource="db://crm/customers",
                        count=100, destination="s3://corp-warehouse/nightly"))
    assert d.verdict == ESCALATE and any("model unavailable" in r for r in d.reasons)
    d = auth.decide(act(clock, identity="human:alice", action_type="data.read", resource="db://crm/customers/query"))
    assert d.verdict == ALLOW and d.grant


def test_volume_threshold_and_two_person_approval(env):
    auth, clock, *_ = env
    a = act(clock, identity="human:bob", action_type="secret.read", resource="vault://prod/ssh/hosts", count=40)
    d = auth.decide(a)
    assert d.verdict == ESCALATE
    with pytest.raises(PermissionError):
        auth.approve(d.fingerprint, "human:bob", "human:bob", "self approval attempt")
    with pytest.raises(PermissionError):
        auth.approve(d.fingerprint, "human:bob", "human:alice", "alice is not an approver")
    aid = auth.approve(d.fingerprint, "human:bob", "human:dana", "CHG-1001 key rotation")
    d2 = auth.decide(a, approval_id=aid)
    assert d2.verdict == ALLOW and d2.approved_by == "human:dana"
    # approval is single-use and bound to the exact action
    assert auth.decide(a, approval_id=aid).verdict == ESCALATE
    bigger = act(clock, identity="human:bob", action_type="secret.read", resource="vault://prod/ssh/hosts", count=400)
    aid2 = auth.approve(d.fingerprint, "human:bob", "human:dana", "CHG-1001 key rotation")
    assert auth.decide(bigger, approval_id=aid2).verdict == ESCALATE


def test_approval_cannot_override_hard_deny(env):
    auth, clock, *_ = env
    a = act(clock, identity="human:carol", action_type="repo.history_rewrite", resource="github://org/app/main", count=3)
    aid = auth.approve(a.fingerprint(), "human:carol", "human:dana", "please let me rewrite main")
    assert auth.decide(a, approval_id=aid).verdict == DENY


def test_unlisted_destination_escalates_denied_destination_denies(env):
    auth, clock, *_ = env
    d = auth.decide(act(clock, identity="human:alice", action_type="data.export", resource="db://crm/customers",
                        count=10, destination="https://files.unknown-host.net/u"))
    assert d.verdict == ESCALATE
    d = auth.decide(act(clock, identity="human:alice", action_type="data.export", resource="db://crm/customers",
                        count=10, destination="https://abc.ngrok.io/x"))
    assert d.verdict == DENY


def test_skimmer_blocked_benign_update_passes(env):
    auth, clock, *_ = env
    v1 = (ROOT / "fixtures/tag_v1.js").read_text()
    bad = (ROOT / "fixtures/tag_v2_skimmer.js").read_text()
    good = script_integrity.check(v1, v1 + "\n// build 2\n")
    assert good["verdict"] == "pass"
    rep = script_integrity.check(v1, bad)
    assert rep["verdict"] == "block"
    codes = {f["code"] for f in rep["findings"]}
    assert {"new_host", "new_sensitive_field_access", "wallet_address_material"} <= codes
    auth.record_integrity(rep)
    a = act(clock, identity="svc:ci-bot", action_type="artifact.publish", resource="cdn://static/js/tag.js",
            metadata={"candidate_sha256": rep["candidate_sha256"]})
    d = auth.decide(a)
    assert d.verdict == DENY and d.stage == "integrity"
    aid = auth.approve(a.fingerprint(), "svc:ci-bot", "human:dana", "vendor says it is fine")
    assert auth.decide(a, approval_id=aid).verdict == DENY  # a block cannot be approved away


def test_repeated_denials_auto_freeze(env):
    auth, clock, *_ = env
    for i in range(3):
        clock.t += 60
        auth.decide(act(clock, identity="svc:status-page", action_type="process.exec", resource="proc://sh"))
    assert "svc:status-page" in auth.frozen


def test_grant_verification(env):
    auth, clock, signer, _ = env
    a = act(clock, identity="human:alice", action_type="data.read", resource="db://crm/customers/query", count=5)
    d = auth.decide(a)
    v = GrantVerifier(signer.public_key, now=clock)
    v.verify(d.grant, a)
    with pytest.raises(GrantError, match="already used"):
        v.verify(d.grant, a)
    other = act(clock, identity="human:alice", action_type="data.read", resource="db://crm/customers/query", count=5000)
    d2 = auth.decide(a)
    with pytest.raises(GrantError, match="does not match"):
        v.verify(d2.grant, other)
    clock.t += 61
    with pytest.raises(GrantError, match="expired"):
        v.verify(d2.grant, a)
    with pytest.raises(GrantError, match="signature"):
        GrantVerifier(Signer.generate().public_key, now=clock).verify(d2.grant, a)


def test_audit_chain_detects_tampering(env):
    auth, clock, signer, tmp = env
    for _ in range(3):
        auth.decide(act(clock, identity="human:alice", action_type="data.read", resource="db://crm/customers/query"))
    path = tmp / "audit.jsonl"
    ok, _ = verify_log(path, signer.public_key)
    assert ok
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["event"]["verdict"] = "ALLOW-EDITED"
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    ok, msg = verify_log(path, signer.public_key)
    assert not ok and "altered" in msg


def test_approval_needs_the_approvers_own_signature(env):
    auth, clock, *_ = env
    a = act(clock, identity="human:bob", action_type="secret.read", resource="vault://prod/ssh/hosts", count=40)
    fp = auth.decide(a).fingerprint
    forged = sign_approval(Signer.generate(), fp, "human:bob", "CHG-1 rotation")  # attacker's own key
    with pytest.raises(PermissionError):
        auth.approve(fp, "human:bob", "human:dana", "CHG-1 rotation", forged)
    with pytest.raises(PermissionError):
        auth.approve(fp, "human:bob", "human:dana", "CHG-1 rotation", "")
    # a valid signature for a different reason does not transfer
    other = sign_approval(auth._appr["human:dana"], fp, "human:bob", "something else")
    with pytest.raises(PermissionError):
        auth.approve(fp, "human:bob", "human:dana", "CHG-1 rotation", other)


def test_caller_timestamp_is_ignored(env):
    auth, clock, *_ = env
    for i in range(3):  # 3 x 40 = 120 secrets fits the daily limit; attacker claims each is a day later
        d = auth.decide({"identity": "human:bob", "action_type": "secret.read", "resource": "vault://prod/db",
                         "count": 5, "ts": clock.t + 86400 * (i + 1)})
    assert all(r["event"].get("action", {}).get("ts", clock.t) == clock.t for r in auth.audit.records
               if r["event"].get("type") == "decision")


def test_state_survives_restart_via_verified_audit_log(env):
    auth, clock, signer, tmp = env
    a = act(clock, identity="human:bob", action_type="secret.read", resource="vault://prod/ssh/hosts", count=40)
    d = auth.decide(a)  # escalates -> pending
    aid = auth.approve(d.fingerprint, "human:bob", "human:dana", "CHG-9 key rotation")
    for _ in range(3):
        clock.t += 60
        auth.decide(act(clock, identity="svc:status-page", action_type="process.exec", resource="proc://sh"))
    assert "svc:status-page" in auth.frozen
    records = [json.loads(x) for x in (tmp / "audit.jsonl").read_text().splitlines()]
    fresh = Authority(auth.policy, auth.issuer, AuditLog(None, signer, now=clock), model=None, now=clock,
                      approver_keys=auth.approver_keys)
    fresh.restore(records)
    assert "svc:status-page" in fresh.frozen  # freeze survived
    assert d.fingerprint in fresh.pending  # pending request survived
    assert fresh.decide(a, approval_id=aid).verdict == ALLOW  # approval survived and is usable once
    assert fresh.decide(a, approval_id=aid).verdict == ESCALATE


def test_no_budget_for_class_is_denied_up_front(tmp_path):
    """Reading a data class with no daily budget (and no overrun allowance) is refused by the
    authority itself, not only by the key service."""
    import json as _json
    from pathlib import Path as _P

    from authority.actions import Action as _A
    from authority.audit import AuditLog as _Log
    from authority.crypto import Signer as _S
    from authority.engine import Authority as _Auth
    from authority.grants import GrantIssuer as _GI
    from authority.policy import Policy as _P2
    pol = _P2.from_dict(_json.loads((_P(__file__).resolve().parents[1] / "policies/default.json").read_text()))
    s = _S.generate()
    auth = _Auth(pol, _GI(s, 60), _Log(tmp_path / "a.jsonl", s))
    secret = auth.decide(_A("human:alice", "data.read", "vault://prod/payments-key", 1))
    assert secret.verdict == "DENY" and "no daily budget for secret" in " ".join(secret.reasons)
    crm = auth.decide(_A("human:alice", "data.read", "db://crm/customers/query", 5))
    assert "no daily budget" not in " ".join(crm.reasons)


def test_ask_once_learns_an_approved_destination(env):
    """destinations.learn_on_approval: after one approved action to a new destination, that identity's
    later actions to the same destination stop escalating for the allowlist (and only for that identity)."""
    auth, clock, signer, tmp = env
    a = act(clock, identity="human:alice", action_type="data.export", resource="db://analytics/weekly",
            count=1, destination="s3://partner-x")
    msg = "destination s3://partner-x not on the allowlist"
    d = auth.decide(a)
    assert d.verdict == ESCALATE and msg in d.reasons
    auth.policy.raw.setdefault("destinations", {})["learn_on_approval"] = False
    aid = auth.approve(d.fingerprint, "human:alice", "human:dana", "weekly partner report")
    assert auth.decide(a, approval_id=aid).verdict == ALLOW
    assert msg in auth.decide(dataclasses.replace(a, count=2)).reasons  # off by default: still asks
    auth.policy.raw["destinations"]["learn_on_approval"] = True
    d = auth.decide(dataclasses.replace(a, count=3))
    aid = auth.approve(d.fingerprint, "human:alice", "human:dana", "weekly partner report")
    assert auth.decide(dataclasses.replace(a, count=3), approval_id=aid).verdict == ALLOW
    assert msg not in auth.decide(dataclasses.replace(a, count=4)).reasons      # asked once
    assert ("human:alice", "s3://partner-x") in auth.learned_destinations
    assert ("human:erin", "s3://partner-x") not in auth.learned_destinations   # per identity only
    # survives a restart: rebuilt from the signed audit log
    records = [json.loads(x) for x in (tmp / "audit.jsonl").read_text().splitlines() if x.strip()]
    fresh = Authority(Policy.load(ROOT / "policies/default.json"), GrantIssuer(signer, 60, now=clock),
                      AuditLog(tmp / "audit2.jsonl", signer, now=clock), model=None, now=clock)
    fresh.restore(records)
    assert ("human:alice", "s3://partner-x") in fresh.learned_destinations

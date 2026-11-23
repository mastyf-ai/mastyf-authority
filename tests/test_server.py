import hashlib
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from authority.audit import AuditLog
from authority.crypto import Signer
from authority.engine import Authority, sign_approval
from authority.grants import GrantIssuer, GrantVerifier
from authority.policy import Policy
from authority.server import make_handler

ROOT = Path(__file__).resolve().parents[1]
KEYS = {"k-alice-0123456789abcdef": "human:alice", "k-bob-0123456789abcdef": "human:bob",
        "k-dana-0123456789abcdef": "human:dana", "k-admin-0123456789abcdef": "admin"}


@pytest.fixture
def srv():
    policy = Policy.load(ROOT / "policies/default.json")
    s = Signer.generate()
    dana = Signer.generate()
    auth = Authority(policy, GrantIssuer(s, 60), AuditLog(None, s), approver_keys={"human:dana": dana.public_key})
    callers = {hashlib.sha256(k.encode()).hexdigest(): who for k, who in KEYS.items()}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(auth, callers, GrantVerifier(s.public_key)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", dana
    httpd.shutdown()


def call(base, path, key, body=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_no_key_and_wrong_key_rejected(srv):
    base, _ = srv
    assert call(base, "/v1/decide", "nope", {"action": {}})[0] == 401


def test_cannot_act_as_someone_else(srv):
    base, _ = srv
    code, body = call(base, "/v1/decide", "k-alice-0123456789abcdef",
                      {"action": {"identity": "human:bob", "action_type": "secret.read", "resource": "vault://prod/db"}})
    assert code == 403 and body["verdict"] == "DENY"


def test_cannot_approve_as_someone_else_or_without_signature(srv):
    base, dana = srv
    act = {"identity": "human:bob", "action_type": "secret.read", "resource": "vault://prod/ssh/hosts", "count": 40}
    _, d = call(base, "/v1/decide", "k-bob-0123456789abcdef", {"action": act})
    assert d["verdict"] == "ESCALATE"
    fp = d["fingerprint"]
    req = {"fingerprint": fp, "requester": "human:bob", "approver": "human:dana", "reason": "CHG-77 rotation"}
    assert call(base, "/v1/approve", "k-bob-0123456789abcdef", req)[0] == 403  # bob posing as dana
    assert call(base, "/v1/approve", "k-dana-0123456789abcdef", req)[0] == 400  # dana's key, no signature
    req["signature"] = sign_approval(dana, fp, "human:bob", "CHG-77 rotation")
    code, body = call(base, "/v1/approve", "k-dana-0123456789abcdef", req)
    assert code == 200
    _, d2 = call(base, "/v1/decide", "k-bob-0123456789abcdef", {"action": act, "approval_id": body["approval_id"]})
    assert d2["verdict"] == "ALLOW"


def test_admin_only_endpoints(srv):
    base, _ = srv
    assert call(base, "/v1/freeze", "k-alice-0123456789abcdef", {"identity": "human:bob"})[0] == 403
    assert call(base, "/v1/freeze", "k-admin-0123456789abcdef", {"identity": "human:bob", "reason": "test"})[0] == 200


def test_pending_queue_visible_to_approvers_only(srv):
    base, _ = srv
    act = {"identity": "human:bob", "action_type": "secret.read", "resource": "vault://prod/ssh/hosts", "count": 40}
    _, d = call(base, "/v1/decide", "k-bob-0123456789abcdef", {"action": act})
    assert d["verdict"] == "ESCALATE"
    assert call(base, "/v1/pending", "k-alice-0123456789abcdef")[0] == 403
    code, body = call(base, "/v1/pending", "k-dana-0123456789abcdef")
    assert code == 200 and any(p["fingerprint"] == d["fingerprint"] for p in body["pending"])
    code, body = call(base, "/v1/deny", "k-dana-0123456789abcdef",
                      {"fingerprint": d["fingerprint"], "approver": "human:dana", "reason": "not planned"})
    assert code == 200 and body["removed"]
    assert not call(base, "/v1/pending", "k-dana-0123456789abcdef")[1]["pending"]


def test_requester_learns_what_became_of_its_request(srv):
    """GET /v1/approval: waiting, then approved with the id to retry with, or denied; only for the requester."""
    base, dana = srv
    bob, alice, dk = "k-bob-0123456789abcdef", "k-alice-0123456789abcdef", "k-dana-0123456789abcdef"
    act = {"identity": "human:bob", "action_type": "secret.read", "resource": "vault://prod/ssh/hosts", "count": 40}
    fp = call(base, "/v1/decide", bob, {"action": act})[1]["fingerprint"]
    assert call(base, f"/v1/approval?fingerprint={fp}", bob)[1]["status"] == "waiting"
    assert call(base, f"/v1/approval?fingerprint={fp}", alice)[1] == {"status": "unknown"}  # not hers
    assert call(base, "/v1/approval?fingerprint=short", bob)[0] == 400
    why = "CHG-77 rotation"
    call(base, "/v1/approve", dk, {"fingerprint": fp, "requester": "human:bob", "approver": "human:dana",
                                   "reason": why, "signature": sign_approval(dana, fp, "human:bob", why)})
    st = call(base, f"/v1/approval?fingerprint={fp}", bob)[1]
    assert st["status"] == "approved" and st["approver"] == "human:dana"
    assert call(base, f"/v1/approval?fingerprint={fp}", alice)[1] == {"status": "unknown"}
    assert call(base, "/v1/decide", bob, {"action": act, "approval_id": st["approval_id"]})[1]["verdict"] == "ALLOW"

    act2 = {**act, "count": 41}
    fp2 = call(base, "/v1/decide", bob, {"action": act2})[1]["fingerprint"]
    call(base, "/v1/deny", dk, {"fingerprint": fp2, "approver": "human:dana", "reason": "not planned"})
    st2 = call(base, f"/v1/approval?fingerprint={fp2}", bob)[1]
    assert st2 == {"status": "denied", "approver": "human:dana", "reason": "not planned"}



def test_server_ignores_caller_timestamps():
    """Future- or back-dated requests are stamped with the server's clock before the engine sees them,
    so they cannot empty the daily windows, burst counters or time-of-day features."""
    policy = Policy.load(ROOT / "policies/default.json")
    s = Signer.generate()
    auth = Authority(policy, GrantIssuer(s, 60), AuditLog(None, s), now=lambda: 1_000_000.0)
    seen = []
    real = auth.decide
    auth.decide = lambda act, approval_id=None: (seen.append(act["ts"]), real(act, approval_id=approval_id))[1]
    callers = {hashlib.sha256(k.encode()).hexdigest(): who for k, who in KEYS.items()}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(auth, callers, GrantVerifier(s.public_key)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    act = {"identity": "human:alice", "action_type": "data.read", "resource": "db://crm/customers/1", "count": 1}
    try:
        for ts in (5e9, 0, -1, 1_000_000.0):
            assert call(base, "/v1/decide", "k-alice-0123456789abcdef", {"action": {**act, "ts": ts}})[0] == 200
        assert call(base, "/v1/decide", "k-alice-0123456789abcdef", {"action": act})[0] == 200
    finally:
        httpd.shutdown()
    assert seen == [1_000_000.0] * 5

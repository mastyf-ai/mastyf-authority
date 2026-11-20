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

"""Production durability of the Rust key service: crash + restart must not reset budgets,
must not make used grants reusable, and must not lose record keys."""

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from authority.actions import Action
from authority.crypto import Signer
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")


class Svc:
    def __init__(self, tmp, auth_pem, *extra):
        self.p = subprocess.Popen([str(BIN), "--policy", str(ROOT / "policies/default.json"),
                                   "--authority-key", str(auth_pem), "--fake-clock", *extra],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def ask(self, req):
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def crash(self):
        os.kill(self.p.pid, signal.SIGKILL)
        self.p.wait(timeout=5)


@pytest.fixture
def setup(tmp_path):
    auth = Signer.generate()
    (tmp_path / "auth.pem").write_text(auth.public_pem())
    return auth, tmp_path


def read(n, ids=None, t=None):
    return Action("human:alice", "data.read", "db://crm/customers/query", n, ts=t or time.time(),
                  metadata={"record_ids": ids} if ids else {})


def test_crash_does_not_reset_budget_reuse_grants_or_lose_keys(setup):
    auth, tmp = setup
    state = tmp / "state"
    now = time.time()
    iss = GrantIssuer(auth, 600, now=lambda: now)
    s = Svc(tmp, tmp / "auth.pem", "--state-dir", str(state), "--init-kek")
    dek = s.ask({"op": "new_record_key", "record_id": "c1", "class": "crm.customer"})["dek"]
    g_used = None
    for i in range(5):  # alice: 5000 records / 24 h
        a = read(1000)
        g = iss.issue(a, "x")
        assert s.ask({"op": "release", "grant": g, "action": a.to_dict(), "now": now + i})["ok"]
        g_used = (g, a)
    s.crash()  # SIGKILL: no clean shutdown

    s = Svc(tmp, tmp / "auth.pem", "--state-dir", str(state))
    a = read(1000)
    r = s.ask({"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now + 10})
    assert not r["ok"] and r["reason"].startswith("budget")  # budget survived the crash
    r = s.ask({"op": "release", "grant": g_used[0], "action": g_used[1].to_dict(), "now": now + 11})
    assert not r["ok"] and "already used" in r["reason"]  # spent grant stays spent
    b = Action("human:bob", "secret.read", "vault://prod/db", 1, ts=now)
    s.ask({"op": "new_record_key", "record_id": "s1", "class": "secret"})
    # same KEK after restart: the record key created before the crash still unwraps to the same bytes
    a = Action("human:bob", "secret.read", "vault://prod/db", 1, ts=now, metadata={"record_ids": ["s1"]})
    assert s.ask({"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now + 12})["ok"]
    c = Action("human:alice", "data.read", "db://crm/customers/query", 1, ts=now, metadata={"record_ids": ["c1"]})
    s.crash()
    s = Svc(tmp, tmp / "auth.pem", "--state-dir", str(state))
    later = GrantIssuer(auth, 600, now=lambda: now + 86400 * 2)
    r = s.ask({"op": "release", "grant": later.issue(c, "x"), "action": c.to_dict(), "now": now + 86400 * 2})
    assert r["ok"], r
    assert r["keys"]["c1"] == dek
    s.crash()


def test_refuses_to_start_without_kek_or_with_loose_permissions(setup):
    auth, tmp = setup
    p = subprocess.run([str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key",
                        str(tmp / "auth.pem"), "--state-dir", str(tmp / "s1")], capture_output=True, text=True,
                       input="", timeout=10)
    assert p.returncode != 0 and "no KEK" in p.stderr
    (tmp / "s2").mkdir()
    k = tmp / "s2" / "kek.b64"
    k.write_text("A" * 43 + "=")
    os.chmod(k, 0o644)
    p = subprocess.run([str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key",
                        str(tmp / "auth.pem"), "--state-dir", str(tmp / "s2")], capture_output=True, text=True,
                       input="", timeout=10)
    assert p.returncode != 0 and "chmod 600" in p.stderr


def test_kek_from_external_command(setup):
    auth, tmp = setup
    import base64
    key = base64.b64encode(os.urandom(32)).decode()
    s = Svc(tmp, tmp / "auth.pem", "--state-dir", str(tmp / "s3"), "--kek-command", f"printf %s {key}")
    assert s.ask({"op": "new_record_key", "record_id": "r", "class": "crm.customer"})["ok"]
    s.crash()


def test_gate_state_survives_crash(setup):
    auth, tmp = setup
    from authority import script_integrity
    now = time.time()
    iss = GrantIssuer(auth, 600, now=lambda: now)
    state = tmp / "g"
    s = Svc(tmp, tmp / "auth.pem", "--state-dir", str(state), "--init-kek")
    rw = Action("human:carol", "repo.history_rewrite", "github://org/app/feature/1", 25, ts=now)
    assert s.ask({"op": "gate", "grant": iss.issue(rw, "x"), "action": rw.to_dict(), "now": now})["ok"]
    v1 = (ROOT / "fixtures/tag_v1.js").read_text()
    # first publish has no baseline -> review -> needs signatures; seed via a passing update path instead:
    s.ask({"op": "gate_set_live", "resource": "cdn://static/js/tag.js", "content": v1})
    v2 = v1 + "\n// build 2\n"
    pub = Action("svc:ci-bot", "artifact.publish", "cdn://static/js/tag.js", 1, ts=now,
                 metadata={"candidate_sha256": script_integrity.check(None, v2)["candidate_sha256"]})
    assert s.ask({"op": "gate", "grant": iss.issue(pub, "x"), "action": pub.to_dict(), "content": v2, "now": now})["ok"]
    s.crash()
    s = Svc(tmp, tmp / "auth.pem", "--state-dir", str(state))
    rw2 = Action("human:carol", "repo.history_rewrite", "github://org/app/feature/2", 10, ts=now)
    r = s.ask({"op": "gate", "grant": iss.issue(rw2, "x"), "action": rw2.to_dict(), "now": now + 60})
    assert not r["ok"] and "rewrite budget" in r["reason"]  # 25 + 10 > 30 survived the crash
    v3 = v2 + "// build 3\n"  # live version (v2) survived: a small benign update still passes
    pub3 = Action("svc:ci-bot", "artifact.publish", "cdn://static/js/tag.js", 1, ts=now,
                  metadata={"candidate_sha256": script_integrity.check(None, v3)["candidate_sha256"]})
    r = s.ask({"op": "gate", "grant": iss.issue(pub3, "x"), "action": pub3.to_dict(), "content": v3, "now": now + 61})
    assert r["ok"], r
    s.crash()


def test_unfreeze_needs_two_approvers_and_survives_restart(setup):
    auth, tmp = setup
    from authority.crypto import b64e
    appr = {n: Signer.generate() for n in ("human:dana", "human:erin")}
    (tmp / "appr.json").write_text(json.dumps({n: s.public_pem() for n, s in appr.items()}))
    pol = json.loads((ROOT / "policies/default.json").read_text())
    pol["data_budgets"]["canary_records"] = ["bait-*"]
    (tmp / "policy.json").write_text(json.dumps(pol))
    now = time.time()
    iss = GrantIssuer(auth, 600, now=lambda: now)
    state = tmp / "u"

    def svc(*extra):
        return subprocess.Popen([str(BIN), "--policy", str(tmp / "policy.json"), "--authority-key", str(tmp / "auth.pem"),
                                 "--approvers", str(tmp / "appr.json"), "--state-dir", str(state), "--fake-clock", *extra],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def ask(p, req):
        p.stdin.write(json.dumps(req) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    p = svc("--init-kek")
    ask(p, {"op": "new_record_key", "record_id": "bait-1", "class": "crm.customer"})
    a = Action("human:alice", "data.read", "db://crm/customers/query", 1, ts=now, metadata={"record_ids": ["bait-1"]})
    assert "canary" in ask(p, {"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now})["reason"]
    os.kill(p.pid, signal.SIGKILL)
    p = svc()
    b = read(10)
    assert "frozen" in ask(p, {"op": "release", "grant": iss.issue(b, "x"), "action": b.to_dict(), "now": now})["reason"]
    until = int(now) + 600
    msg = f"mastyf-unfreeze|human:alice|{until}".encode()
    one = [{"approver": "human:dana", "sig": b64e(appr["human:dana"].sign(msg))}]
    assert not ask(p, {"op": "unfreeze", "identity": "human:alice", "until": until, "sigs": one, "now": now})["ok"]
    two = one + [{"approver": "human:erin", "sig": b64e(appr["human:erin"].sign(msg))}]
    assert ask(p, {"op": "unfreeze", "identity": "human:alice", "until": until, "sigs": two, "now": now})["ok"]
    os.kill(p.pid, signal.SIGKILL)
    p = svc()
    c = read(10)
    assert ask(p, {"op": "release", "grant": iss.issue(c, "x"), "action": c.to_dict(), "now": now})["ok"]
    os.kill(p.pid, signal.SIGKILL)

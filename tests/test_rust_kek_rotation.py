"""KEK rotation: every record key is re-wrapped under the new KEK, all-or-nothing, and the old KEK
stops working. Rotation refuses to run while the service holds the state directory."""

import json
import os
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
KEK_A = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY="
KEK_B = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


def kek(tmp, name, value):
    p = tmp / name
    p.write_text(value)
    os.chmod(p, 0o600)
    return p


class Svc:
    def __init__(self, tmp, kek_file):
        self.p = subprocess.Popen([str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key",
                                   str(tmp / "auth.pem"), "--fake-clock", "--state-dir", str(tmp / "state"),
                                   "--kek-file", str(kek_file)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def ask(self, req):
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def stop(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


def rotate(tmp, old, new):
    return subprocess.run([str(BIN), "rotate-kek", "--state-dir", str(tmp / "state"), "--old-kek-file", str(old),
                           "--new-kek-file", str(new)], capture_output=True, text=True)


def test_rotation(tmp_path):
    auth = Signer.generate()
    (tmp_path / "auth.pem").write_text(auth.public_pem())
    a_file, b_file = kek(tmp_path, "a.b64", KEK_A), kek(tmp_path, "b.b64", KEK_B)
    now = time.time()
    iss = GrantIssuer(auth, 600, now=lambda: now)

    def get(svc, rid, t):
        a = Action("human:alice", "data.read", "db://crm/customers/query", 1, ts=now, metadata={"record_ids": [rid]})
        return svc.ask({"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now + t})

    s = Svc(tmp_path, a_file)
    deks = {f"c{i}": s.ask({"op": "new_record_key", "record_id": f"c{i}", "class": "crm.customer"})["dek"] for i in range(50)}
    r = rotate(tmp_path, a_file, b_file)
    assert r.returncode != 0 and "in use" in r.stderr  # service still running
    s.stop()

    journal = tmp_path / "state" / "keyservice.journal"
    before = journal.read_bytes()
    r = rotate(tmp_path, b_file, a_file)  # wrong old KEK
    assert r.returncode != 0 and "nothing changed" in r.stderr
    assert journal.read_bytes() == before

    r = rotate(tmp_path, a_file, b_file)
    assert r.returncode == 0, r.stderr
    assert "re-wrapped 50 record keys" in r.stderr
    assert (tmp_path / "state" / "keyservice.pre-rotation").stat().st_mode & 0o077 == 0

    s = Svc(tmp_path, b_file)  # new KEK: same record keys
    for i, (rid, dek) in enumerate(list(deks.items())[:5]):
        got = get(s, rid, i)
        assert got["ok"] and got["keys"][rid] == dek, got
    s.stop()
    s = Svc(tmp_path, a_file)  # old KEK: the service refuses to start at all
    assert s.p.wait(timeout=10) != 0 and "does not open" in s.p.stderr.read()

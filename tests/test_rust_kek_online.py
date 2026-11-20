"""Online KEK rotation: start with the new KEK plus --previous-kek-file; old record keys keep releasing
at once while a background thread re-wraps them; afterwards the new KEK alone opens everything, the old
KEK alone is refused, and the journal keeps one wrapping per record."""

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
    def __init__(self, tmp, kek_file, previous=None):
        cmd = [str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key", str(tmp / "auth.pem"),
               "--fake-clock", "--state-dir", str(tmp / "state"), "--kek-file", str(kek_file)]
        if previous:
            cmd += ["--previous-kek-file", str(previous)]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def ask(self, req):
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def stop(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)
        return self.p.stderr.read()


def test_online_rotation(tmp_path):
    auth = Signer.generate()
    (tmp_path / "auth.pem").write_text(auth.public_pem())
    a_file, b_file = kek(tmp_path, "a.b64", KEK_A), kek(tmp_path, "b.b64", KEK_B)
    now = time.time()
    iss = GrantIssuer(auth, 600, now=lambda: now)

    def get(svc, rid):
        a = Action("human:alice", "data.read", "db://crm/customers/query", 1, ts=now, metadata={"record_ids": [rid]})
        r = svc.ask({"op": "release", "grant": iss.issue(a, rid), "action": a.to_dict(), "now": now + 1})
        assert r["ok"], r
        return r["keys"][rid]

    s = Svc(tmp_path, a_file)
    deks = {f"c{i}": s.ask({"op": "new_record_key", "record_id": f"c{i}", "class": "crm.customer"})["dek"]
            for i in range(50)}
    s.stop()

    # new KEK + previous KEK: no downtime for old keys, background re-wrap finishes
    s = Svc(tmp_path, b_file, previous=a_file)
    assert get(s, "c7") == deks["c7"]  # served at once, whether or not c7 has been re-wrapped yet
    for _ in range(100):
        st = s.ask({"op": "kek_status"})
        if st["previous"] == 0:
            break
        time.sleep(0.05)
    assert st == {"ok": True, "current": 50, "previous": 0, "unopenable": 0}
    deks["new"] = s.ask({"op": "new_record_key", "record_id": "new", "class": "crm.customer"})["dek"]
    err = s.stop()
    assert "KEK rotation done" in err

    # the new KEK alone opens everything, with the same data keys
    s = Svc(tmp_path, b_file)
    assert all(get(s, rid) == dek for rid, dek in deks.items())
    s.stop()
    wraps = [x for x in (tmp_path / "state" / "keyservice.journal").read_text().splitlines() if '"e":"wrap"' in x]
    assert len(wraps) == 51  # compaction kept one wrapping per record

    # the old KEK alone is refused
    s = Svc(tmp_path, a_file)
    assert s.p.wait(timeout=10) != 0
    assert "does not open the stored record keys" in s.p.stderr.read()

    # a previous KEK equal to the current one is a mistake, not a rotation
    s = Svc(tmp_path, b_file, previous=b_file)
    assert s.p.wait(timeout=10) != 0

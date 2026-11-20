"""Approvals checked by the Rust service (change gates, budget overruns, unfreeze) accept passkey
signatures from approvers' registered devices, alongside Ed25519 CLI signatures."""

import hashlib
import json
import subprocess
import time
from pathlib import Path

import pytest

from authority.actions import Action
from authority.binding import ES256, Device, DeviceRegistry
from authority.crypto import Signer, b64d, b64e
from authority.gates import gate_message
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")
RP = "authority.corp.example"


def passkey(dev, name, device, msg: bytes):
    return {"approver": name, "device": device, "proof": dev.prove_challenge(hashlib.sha256(msg).digest())}


@pytest.fixture
def svc(tmp_path):
    auth = Signer.generate()
    appr = {n: Signer.generate() for n in ("human:dana", "human:erin")}
    devs = {"human:dana": Device(rp_id=RP), "human:erin": Device(rp_id=RP, alg=ES256), "human:alice": Device(rp_id=RP)}
    reg = DeviceRegistry(rp_id=RP)
    for who, d in devs.items():
        reg.register(who, "mbp", d.sign_public, d.kex_public, alg=d.alg)
    reg.save(tmp_path / "devices.json")
    (tmp_path / "a.pem").write_text(auth.public_pem())
    (tmp_path / "appr.json").write_text(json.dumps({n: s.public_pem() for n, s in appr.items()}))
    p = subprocess.Popen([str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key", str(tmp_path / "a.pem"),
                          "--approvers", str(tmp_path / "appr.json"), "--approver-devices", str(tmp_path / "devices.json"),
                          "--fake-clock"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def ask(req):
        p.stdin.write(json.dumps(req) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())
    yield ask, auth, appr, devs
    p.stdin.close()
    p.wait(timeout=10)


def test_gate_accepts_passkeys_and_rejects_replays_and_non_approvers(svc):
    ask, auth, appr, devs = svc
    now = time.time()
    iss = GrantIssuer(auth, 600, now=lambda: now)

    def rewrite(sigs_for):
        a = Action("human:carol", "repo.history_rewrite", "github://org/app/main", 5, ts=now)
        g = iss.issue(a, "d")
        gid = json.loads(b64d(g.split(".")[0]))["gid"]
        msg = gate_message(gid, a.fingerprint())
        return ask({"op": "gate", "grant": g, "action": a.to_dict(), "sigs": sigs_for(msg), "content": None, "now": now})

    assert not rewrite(lambda m: [])["ok"]  # protected branch needs two approvers
    r = rewrite(lambda m: [passkey(devs["human:dana"], "human:dana", "mbp", m),
                           passkey(devs["human:erin"], "human:erin", "mbp", m)])
    assert r["ok"], r
    r = rewrite(lambda m: [passkey(devs["human:dana"], "human:dana", "mbp", m),
                           {"approver": "human:erin", "sig": b64e(appr["human:erin"].sign(m))}])
    assert r["ok"], r  # passkey + CLI signature mix
    # alice has a registered device but is not an approver
    r = rewrite(lambda m: [passkey(devs["human:dana"], "human:dana", "mbp", m),
                           passkey(devs["human:alice"], "human:alice", "mbp", m)])
    assert not r["ok"]
    # dana's passkey answering a different request does not count
    r = rewrite(lambda m: [passkey(devs["human:dana"], "human:dana", "mbp", m + b"x"),
                           passkey(devs["human:erin"], "human:erin", "mbp", m)])
    assert not r["ok"]


def test_overrun_with_passkeys(svc):
    ask, auth, appr, devs = svc
    now = time.time()
    iss = GrantIssuer(auth, 600, now=lambda: now)
    a = Action("human:alice", "data.read", "db://crm/customers/query", 5000, ts=now)
    assert ask({"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now})["ok"]
    b = Action("human:alice", "data.read", "db://crm/customers/query", 800, ts=now)
    g = iss.issue(b, "x")
    gid = json.loads(b64d(g.split(".")[0]))["gid"]
    msg = f"mastyf-overrun|{gid}|1000".encode()
    assert not ask({"op": "release", "grant": g, "action": b.to_dict(), "now": now + 1})["ok"]  # over budget
    g = iss.issue(b, "x")
    gid = json.loads(b64d(g.split(".")[0]))["gid"]
    msg = f"mastyf-overrun|{gid}|1000".encode()
    over = [{**passkey(devs[n], n, "mbp", msg), "amount": 1000} for n in ("human:dana", "human:erin")]
    r = ask({"op": "release", "grant": g, "action": b.to_dict(), "overrun": over, "now": now + 2})
    assert r["ok"], r

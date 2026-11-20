"""Device enrolment (passkeys) and passkey-signed approvals.

The point: a stolen password / API key must not be able to add the attacker's own device."""

import hashlib
import json
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from authority.actions import Action
from authority.binding import ES256, Device, DeviceRegistry
from authority.crypto import Signer, b64d, b64e
from authority.engine import approval_message
from authority.enroll import Enrollment, enroll_message, registration_challenge
from authority.grants import GrantIssuer
from authority.webauthn import cbor_decode, cbor_encode, make_registration, verify_registration

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
RP = "authority.corp.example"
ORIGIN = f"https://{RP}"


def kex_bytes(dev):
    return dev.kex_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def register(enr, b, dev, name, uv=True, kex=None, cred=b"cred-"):
    kex = kex or kex_bytes(dev)
    chal = registration_challenge(b["rid"], b["identity"], b["exp"], kex_bytes(dev))
    att, cd = make_registration(dev._sign, dev.alg, chal, RP, ORIGIN, cred + name.encode(), user_verified=uv)
    return enr.finish(b["rid"], name, att, cd, kex)


@pytest.fixture
def world(tmp_path):
    reg = DeviceRegistry(rp_id=RP, origin=ORIGIN)
    events, alerts = [], []
    approvers = {"human:dana", "human:erin"}
    enr = Enrollment(reg, audit=events.append, alert=lambda who, t: alerts.append((who, t)),
                     save_path=tmp_path / "devices.json", is_approver=lambda n: n in approvers)
    devs = {n: Device(rp_id=RP) for n in ("dana-mbp", "erin-mbp")}
    for who, d in (("human:dana", "dana-mbp"), ("human:erin", "erin-mbp")):
        reg.register(who, d, devs[d].sign_public, devs[d].kex_public, cred_id=b"cred-" + d.encode())
    return reg, enr, devs, events, alerts


def test_cbor_roundtrip_and_limits():
    v = {1: 2, 3: -7, -1: 1, -2: b"x" * 32, "s": [True, False, None, "é"]}
    assert cbor_decode(cbor_encode(v))[0] == v
    with pytest.raises(ValueError):
        cbor_decode(b"\x9f")  # indefinite length
    with pytest.raises(ValueError):
        cbor_decode(b"\x5a\xff\xff\xff\xff")  # claims 4 GB


def test_stolen_login_cannot_enrol_a_device(world):
    reg, enr, devs, _, _ = world
    attacker = Device(rp_id=RP)
    b = enr.begin("human:alice")  # attacker holds alice's API key, alice has no device yet
    with pytest.raises(PermissionError, match="not authorised"):
        register(enr, b, attacker, "attacker-laptop")
    with pytest.raises(PermissionError, match="own device"):
        enr.approve(b["rid"], "human:alice", proof="{}", device_id="x")
    with pytest.raises(PermissionError, match="not an approver"):
        enr.approve(b["rid"], "human:mallory", proof="{}", device_id="x")
    chal = hashlib.sha256(enroll_message(b["rid"], b["identity"], b["exp"])).digest()
    assert enr.approve(b["rid"], "human:dana", proof=devs["dana-mbp"].prove_challenge(chal), device_id="dana-mbp") \
        == "1 of 2 approvals"
    with pytest.raises(PermissionError):  # one approver is not enough
        register(enr, b, attacker, "attacker-laptop")
    assert "human:alice" not in reg.devices or not reg.devices["human:alice"]


def test_two_approvers_then_registration_binds_the_encryption_key(world):
    reg, enr, devs, events, alerts = world
    alice = Device(rp_id=RP, alg=ES256)
    b = enr.begin("human:alice")
    chal = hashlib.sha256(enroll_message(b["rid"], b["identity"], b["exp"])).digest()
    for who, d in (("human:dana", "dana-mbp"), ("human:erin", "erin-mbp")):
        enr.approve(b["rid"], who, proof=devs[d].prove_challenge(chal), device_id=d)
    # a man-in-the-middle swapping in his own encryption key breaks the passkey challenge
    with pytest.raises(ValueError, match="challenge"):
        register(enr, b, alice, "alice-mbp", kex=kex_bytes(Device()))
    out = register(enr, b, alice, "alice-mbp")
    assert out == {"identity": "human:alice", "device": "alice-mbp", "alg": ES256}
    assert "alice-mbp" in reg.devices["human:alice"]
    saved = json.loads((Path(enr.save_path)).read_text())
    assert saved["devices"]["human:alice"]["alice-mbp"]["cred_id"] == b64e(b"cred-alice-mbp")
    assert DeviceRegistry.from_json(saved).devices["human:alice"].keys() == {"alice-mbp"}
    assert any(e["type"] == "device_enrolled" for e in events) and alerts[-1][0] == "human:alice"
    # the new device works for key releases
    g, fp = "grant-1", "f" * 64
    kex, why = reg.check("human:alice", "alice-mbp", alice.prove(g, fp), g, fp)
    assert kex is not None, why
    # second device: authorised by the first, no approvers needed
    b2 = enr.begin("human:alice")
    assert b2["has_devices"] and b2["allow"][0]["device"] == "alice-mbp"
    chal2 = hashlib.sha256(enroll_message(b2["rid"], b2["identity"], b2["exp"])).digest()
    enr.authorise_with_device(b2["rid"], "alice-mbp", alice.prove_challenge(chal2))
    assert register(enr, b2, Device(rp_id=RP), "alice-phone")["device"] == "alice-phone"
    assert enr.remove("human:alice", "alice-phone", "human:alice")
    assert "alice-phone" not in reg.devices["human:alice"]


def test_registration_rejects_bad_input(world):
    reg, enr, devs, _, _ = world
    b = enr.begin("human:dana")
    chal = hashlib.sha256(enroll_message(b["rid"], b["identity"], b["exp"])).digest()
    enr.authorise_with_device(b["rid"], "dana-mbp", devs["dana-mbp"].prove_challenge(chal))
    d = Device(rp_id=RP)
    with pytest.raises(ValueError, match="verification"):
        register(enr, b, d, "dana-2", uv=False)
    kex = kex_bytes(d)
    c = registration_challenge(b["rid"], b["identity"], b["exp"], kex)
    att, cd = make_registration(d._sign, d.alg, c, "evil.example", ORIGIN, b"id")
    with pytest.raises(ValueError, match="relying party"):
        enr.finish(b["rid"], "dana-2", att, cd, kex)
    att, cd = make_registration(d._sign, d.alg, c, RP, "https://evil.example", b"id")
    with pytest.raises(ValueError, match="origin"):
        enr.finish(b["rid"], "dana-2", att, cd, kex)
    with pytest.raises(ValueError):
        verify_registration(b"\xa1" + b"\x00" * 3, cd, c, RP, ORIGIN)
    with pytest.raises(ValueError, match="name"):
        register(enr, b, d, "../../etc")
    # replayed old assertion from the existing device cannot authorise a new request
    b3 = enr.begin("human:dana")
    with pytest.raises(PermissionError):
        enr.authorise_with_device(b3["rid"], "dana-mbp", devs["dana-mbp"].prove_challenge(chal))


def test_passkey_approval_in_authority(tmp_path):
    from authority.audit import AuditLog
    from authority.engine import Authority
    from authority.policy import Policy
    pol = Policy.load(ROOT / "policies/default.json")
    approvers = [n for n, r in pol.identities.items() if r.approver and r.kind == "human"]
    appr = approvers[0]
    reg = DeviceRegistry(rp_id=RP, origin=ORIGIN)
    dev = Device(rp_id=RP)
    reg.register(appr, "mbp", dev.sign_public, dev.kex_public)
    signer = Signer.generate()
    auth = Authority(pol, GrantIssuer(signer, 60), AuditLog(tmp_path / "a.log", signer), devices=reg)
    fp, req, why = "a" * 64, "human:bob" if appr != "human:bob" else "human:carol", "CHG-1234 rotate keys"
    chal = hashlib.sha256(approval_message(fp, req, why)).digest()
    proof = json.loads(dev.prove_challenge(chal))
    proof["device"] = "mbp"
    assert auth.approve(fp, req, appr, why, json.dumps(proof))
    with pytest.raises(PermissionError):  # same assertion again: counter did not advance
        auth.approve(fp, req, appr, why, json.dumps(proof))
    other = json.loads(dev.prove_challenge(hashlib.sha256(approval_message(fp, req, "something else")).digest()))
    other["device"] = "mbp"
    with pytest.raises(PermissionError):  # signed a different reason
        auth.approve(fp, req, appr, why, json.dumps(other))


def test_http_pages_and_enrolment_flow(tmp_path):
    from http.server import ThreadingHTTPServer

    from authority.audit import AuditLog
    from authority.engine import Authority
    from authority.grants import GrantVerifier
    from authority.policy import Policy
    from authority.server import make_handler
    pol = Policy.load(ROOT / "policies/default.json")
    signer = Signer.generate()
    auth = Authority(pol, GrantIssuer(signer, 60), AuditLog(tmp_path / "a.log", signer))
    reg = DeviceRegistry(rp_id=RP, origin=ORIGIN)
    enr = Enrollment(reg, approver_keys={}, is_approver=lambda n: False)
    keys = {"k-alice": "human:alice"}
    callers = {hashlib.sha256(k.encode()).hexdigest(): v for k, v in keys.items()}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(auth, callers, GrantVerifier(signer.public_key), enr))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def call(path, body=None, key="k-alice"):
        r = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                   headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())
    try:
        with urllib.request.urlopen(base + "/enroll") as r:
            csp = r.headers["Content-Security-Policy"]
            assert "script-src 'self'" in csp and "unsafe" not in csp and b"<script src=\"/web/app.js\"" in r.read()
        with urllib.request.urlopen(base + "/web/app.js") as r:
            assert r.headers["Content-Type"].startswith("text/javascript")
        assert call("/v1/devices", key="wrong")[0] == 401
        code, b = call("/v1/enroll/begin", {})
        assert code == 200 and b["identity"] == "human:alice" and not b["has_devices"]
        d = Device(rp_id=RP)
        chal = registration_challenge(b["rid"], b["identity"], b["exp"], kex_bytes(d))
        att, cd = make_registration(d._sign, d.alg, chal, RP, ORIGIN, b"cid")
        code, r = call("/v1/enroll/finish", {"rid": b["rid"], "device_name": "mbp", "attestation": b64e(att),
                                             "client_data": b64e(cd), "kex": b64e(kex_bytes(d))})
        assert code == 400 and "not authorised" in r["error"]  # API key alone is not enough
        assert call("/v1/enroll/status?rid=" + b["rid"])[1]["authorised"] is False
        assert call("/v1/enroll/pending")[0] == 403  # alice is not an approver
    finally:
        httpd.shutdown()


@pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")
def test_rust_picks_up_new_device_without_restart(tmp_path):
    pol = json.loads((ROOT / "policies/default.json").read_text())
    pol["data_budgets"]["device_bound"] = ["human:*"]
    (tmp_path / "policy.json").write_text(json.dumps(pol))
    auth = Signer.generate()
    (tmp_path / "auth.pem").write_text(auth.public_pem())
    reg = DeviceRegistry(rp_id=RP, origin=ORIGIN)
    reg.save(tmp_path / "devices.json")
    proc = subprocess.Popen([str(BIN), "--policy", str(tmp_path / "policy.json"), "--authority-key", str(tmp_path / "auth.pem"),
                             "--devices", str(tmp_path / "devices.json"), "--fake-clock"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def ask(req):
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())
    try:
        now = time.time()
        iss = GrantIssuer(auth, 600, now=lambda: now)
        d = Device(rp_id=RP)

        def release():
            a = Action("human:alice", "data.read", "db://crm/customers/query", 10, ts=now)
            g = iss.issue(a, "x")
            gid = json.loads(b64d(g.split(".")[0]))["gid"]
            a2 = Action(a.identity, a.action_type, a.resource, a.count, ts=now,
                        metadata={"device_id": "mbp", "device_proof": d.prove(gid, a.fingerprint())})
            return ask({"op": "release", "grant": g, "action": a2.to_dict(), "now": now})
        assert not release()["ok"]  # not enrolled yet
        time.sleep(1.1)  # make sure the file's modification time changes
        reg.register("human:alice", "mbp", d.sign_public, d.kex_public)
        reg.save(tmp_path / "devices.json")
        time.sleep(3)
        r = release()
        assert r["ok"], r
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)

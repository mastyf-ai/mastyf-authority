import json
from pathlib import Path

import pytest

from authority.actions import Action
from authority.binding import CaseRegistry, Device, DeviceRegistry, case_message
from authority.budgets import BudgetPolicy, EncryptedStore, KeyService
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
    d = json.loads((ROOT / "policies/default.json").read_text())["data_budgets"]
    d["device_bound"] = ["human:*"]
    d["purpose_bound"] = {"human:alice": ["crm.customer"]}
    bp = BudgetPolicy.from_dict(d)
    auth, case_sys = Signer.generate(), Signer.generate()
    devices = DeviceRegistry()
    laptop = Device()
    devices.register("human:alice", "alice-mbp", laptop.sign_public, laptop.kex_public)
    cases = CaseRegistry(case_sys.public_key, now=clock, outside_allowance=5)
    ks = KeyService(bp, auth.public_key, {}, now=clock, devices=devices, cases=cases)
    store = EncryptedStore(ks, "crm.customer")
    for i in range(100):
        store.put(f"c{i}", f"customer {i} secret details".encode())
    return ks, GrantIssuer(auth, 60, now=clock), laptop, cases, case_sys, store, clock


def assign(cases, case_sys, case_id, who, recs, exp):
    sig = b64e(case_sys.sign(case_message(case_id, who, recs, exp)))
    return cases.assign(case_id, who, recs, exp, sig)


def request(issuer, clock, ids, device=None, device_id="alice-mbp", who="human:alice"):
    a = Action(who, "data.read", "db://crm/customers/query", len(ids), ts=clock.t, metadata={"record_ids": ids})
    g = issuer.issue(a, "d")
    meta = {"record_ids": ids}
    if device is not None:
        gid = json.loads(b64d(g.split(".")[0]))["gid"]
        meta.update(device_id=device_id, device_proof=device.prove(gid, a.fingerprint()))
    return g, Action(who, "data.read", "db://crm/customers/query", len(ids), ts=clock.t, metadata=meta)


def test_stolen_login_without_device_gets_nothing(env):
    ks, iss, laptop, cases, case_sys, store, clock = env
    assign(cases, case_sys, "case-1", "human:alice", ["c1", "c2", "c3"], clock.t + 86400)
    g, a = request(iss, clock, ["c1", "c2"])  # valid grant, no device proof: a stolen session
    r = ks.release(g, a)
    assert not r.ok and r.reason.startswith("device")
    g, a = request(iss, clock, ["c1", "c2"], device=Device())  # attacker's own device
    assert not ks.release(g, a).ok


def test_device_gets_keys_only_it_can_open(env):
    ks, iss, laptop, cases, case_sys, store, clock = env
    assign(cases, case_sys, "case-1", "human:alice", ["c1", "c2"], clock.t + 86400)
    g, a = request(iss, clock, ["c1", "c2"], device=laptop)
    r = ks.release(g, a)
    assert r.ok
    wrapped = r.keys["c1"]
    assert isinstance(wrapped, str)  # not a raw key
    dek = laptop.unwrap(wrapped, "c1")
    assert EncryptedStore.open("c1", store.rows["c1"], dek) == b"customer 1 secret details"
    with pytest.raises(Exception):
        Device().unwrap(wrapped, "c1")  # anyone else who intercepts it cannot open it


def test_device_proof_cannot_be_reused_for_another_request(env):
    ks, iss, laptop, cases, case_sys, store, clock = env
    assign(cases, case_sys, "case-1", "human:alice", ["c1", "c2"], clock.t + 86400)
    g1, a1 = request(iss, clock, ["c1"], device=laptop)
    g2, a2 = request(iss, clock, ["c2"])
    a2 = Action(a2.identity, a2.action_type, a2.resource, a2.count, ts=a2.ts,
                metadata={**a2.metadata, "device_id": "alice-mbp", "device_proof": a1.metadata["device_proof"]})
    assert not ks.release(g2, a2).ok


def test_need_to_know_cases(env):
    ks, iss, laptop, cases, case_sys, store, clock = env
    assert not cases.assign("case-x", "human:alice", ["c9"], clock.t + 86400,
                            b64e(Signer.generate().sign(case_message("case-x", "human:alice", ["c9"], clock.t + 86400))))
    assign(cases, case_sys, "case-1", "human:alice", [f"c{i}" for i in range(10)], clock.t + 3600)
    g, a = request(iss, clock, [f"c{i}" for i in range(10)], device=laptop)
    assert ks.release(g, a).ok
    g, a = request(iss, clock, ["c50", "c51", "c52"], device=laptop)  # 3 outside-case lookups: allowed
    assert ks.release(g, a).ok
    g, a = request(iss, clock, ["c60", "c61", "c62"], device=laptop)  # would exceed 5 outside per day
    r = ks.release(g, a)
    assert not r.ok and r.reason.startswith("need-to-know")
    clock.t += 7200  # case expired: its records now count as outside-case lookups (3 of 5 used)
    g, a = request(iss, clock, ["c1", "c2", "c3"], device=laptop)
    r = ks.release(g, a)
    assert not r.ok and r.reason.startswith("need-to-know")


def _proof_req(iss, clock, dev, ids, user_verified=True):
    a = Action("human:alice", "data.read", "db://crm/customers/query", len(ids), ts=clock.t, metadata={"record_ids": ids})
    g = iss.issue(a, "d")
    gid = json.loads(b64d(g.split(".")[0]))["gid"]
    proof = dev.prove(gid, a.fingerprint(), user_verified=user_verified)
    return g, Action(a.identity, a.action_type, a.resource, a.count, ts=a.ts,
                     metadata={"record_ids": ids, "device_id": "alice-mbp", "device_proof": proof})


def test_p256_passkey_presence_and_clone_detection(env):
    from authority.binding import ES256
    ks, iss, _, cases, case_sys, store, clock = env
    phone = Device(alg=ES256)
    ks.devices.register("human:alice", "alice-mbp", phone.sign_public, phone.kex_public, alg=ES256)
    assign(cases, case_sys, "case-1", "human:alice", ["c1", "c2", "c3"], clock.t + 86400)
    g, a = _proof_req(iss, clock, phone, ["c1"])
    assert ks.release(g, a).ok  # P-256 passkey with fingerprint
    g, a = _proof_req(iss, clock, phone, ["c2"], user_verified=False)
    r = ks.release(g, a)
    assert not r.ok and "user verification" in r.reason  # no fingerprint/PIN
    # a copy of the key in an attacker's hands: its counter lags the real device's
    clone = Device(alg=ES256)
    clone._sign, clone.count = phone._sign, 1
    g, a = _proof_req(iss, clock, clone, ["c3"])
    r = ks.release(g, a)
    assert not r.ok and "cloned" in r.reason
    g, a = _proof_req(iss, clock, phone, ["c3"])  # identity is now frozen until an operator checks
    assert not ks.release(g, a).ok


def test_assertion_for_other_request_or_other_site_rejected(env):
    ks, iss, laptop, cases, case_sys, store, clock = env
    assign(cases, case_sys, "case-1", "human:alice", ["c1", "c2"], clock.t + 86400)
    g1, a1 = _proof_req(iss, clock, laptop, ["c1"])
    g2, a2 = _proof_req(iss, clock, laptop, ["c2"])
    swapped = Action(a2.identity, a2.action_type, a2.resource, a2.count, ts=a2.ts,
                     metadata={**a2.metadata, "device_proof": a1.metadata["device_proof"]})
    assert not ks.release(g2, swapped).ok
    evil = Device(rp_id="evil.example")
    evil._sign, evil.sign_public = laptop._sign, laptop.sign_public
    evil.count = 100
    g, a = _proof_req(iss, clock, evil, ["c1"])
    r = ks.release(g, a)
    assert not r.ok and "relying party" in r.reason

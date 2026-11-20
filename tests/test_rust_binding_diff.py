"""Differential test for device binding and need-to-know cases: Python and Rust must decide
identically on random passkey assertions (valid, no fingerprint, replayed, swapped, cloned, wrong
site, Ed25519 and P-256) and case-bound record requests; Rust-wrapped keys must open on the device."""

import json
import random
import subprocess
from pathlib import Path

import pytest

from authority.actions import Action
from authority.binding import ES256, CaseRegistry, Device, DeviceRegistry, case_message
from authority.budgets import BudgetPolicy, KeyService
from authority.crypto import Signer, b64d, b64e
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")


def test_binding_agrees(tmp_path):
    rng = random.Random(99)
    t = [1_800_000_000.0]
    clock = lambda: t[0]  # noqa: E731
    pol = json.loads((ROOT / "policies/default.json").read_text())
    db = pol["data_budgets"]
    db["device_bound"] = ["human:*"]
    db["purpose_bound"] = {"human:alice": ["crm.customer"]}
    db["outside_case_allowance"] = 4
    (tmp_path / "policy.json").write_text(json.dumps(pol))
    auth, case_sys = Signer.generate(), Signer.generate()
    devs = {"mbp": Device(), "phone": Device(alg=ES256), "bobpc": Device()}
    reg = DeviceRegistry()
    reg.register("human:alice", "mbp", devs["mbp"].sign_public, devs["mbp"].kex_public)
    reg.register("human:alice", "phone", devs["phone"].sign_public, devs["phone"].kex_public, alg=ES256)
    reg.register("human:bob", "bobpc", devs["bobpc"].sign_public, devs["bobpc"].kex_public)
    (tmp_path / "devices.json").write_text(json.dumps(reg.export_json()))
    (tmp_path / "auth.pem").write_text(auth.public_pem())
    (tmp_path / "case.pem").write_text(case_sys.public_pem())
    cases = CaseRegistry(case_sys.public_key, now=clock, outside_allowance=4)
    py = KeyService(BudgetPolicy.from_dict(db), auth.public_key, {}, now=clock, devices=reg, cases=cases)
    proc = subprocess.Popen([str(BIN), "--policy", str(tmp_path / "policy.json"), "--authority-key", str(tmp_path / "auth.pem"),
                             "--devices", str(tmp_path / "devices.json"), "--case-key", str(tmp_path / "case.pem"),
                             "--fake-clock"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def ask(req):
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    pool = [f"c{i}" for i in range(60)] + [f"k{i}" for i in range(10)]
    for rid in pool:
        cls = "crm.customer" if rid[0] == "c" else "ssh.key"
        py.new_record_key(rid, cls)
        assert ask({"op": "new_record_key", "record_id": rid, "class": cls})["ok"]
    iss = GrantIssuer(auth, 60, now=clock)
    old_proofs, bad, opened = [], [], 0
    for i in range(1500):
        t[0] += rng.choice([5, 60, 3600, 30000])
        if rng.random() < 0.08:  # the case system assigns a case (sometimes with a forged signature)
            recs = rng.sample(pool[:60], rng.randint(1, 8))
            exp = int(t[0] + rng.choice([600, 7200, 86400]))
            signer = case_sys if rng.random() < 0.85 else Signer.generate()
            sig = b64e(signer.sign(case_message(f"case{i}", "human:alice", recs, exp)))
            a_py = cases.assign(f"case{i}", "human:alice", recs, exp, sig)
            a_rs = ask({"op": "assign_case", "case": f"case{i}", "to": "human:alice", "records": recs, "exp": exp,
                        "sig": sig, "now": t[0]})["ok"]
            if a_py != a_rs:
                bad.append({"i": i, "assign": [a_py, a_rs]})
            continue
        who = rng.choice(["human:alice", "human:alice", "human:bob"])
        if who == "human:alice":
            ids = rng.sample(pool[:60], rng.choice([1, 2, 5]))
            res = "db://crm/customers/query"
        else:
            ids = rng.sample(pool[60:], rng.choice([1, 2]))
            res = "vault://prod/ssh/hosts"
        a = Action(who, "data.read" if who == "human:alice" else "secret.read", res, len(ids), ts=t[0],
                   metadata={"record_ids": ids})
        g = iss.issue(a, "d")
        gid = json.loads(b64d(g.split(".")[0]))["gid"]
        did = rng.choice(["mbp", "phone"]) if who == "human:alice" else "bobpc"
        dev = devs[did]
        kind = rng.random()
        if kind < 0.65:
            proof = dev.prove(gid, a.fingerprint())
        elif kind < 0.72:
            proof = dev.prove(gid, a.fingerprint(), user_verified=False)
        elif kind < 0.78 and old_proofs:
            proof = rng.choice(old_proofs)  # replayed / swapped assertion
        elif kind < 0.84:
            other = Device(alg=dev.alg)  # attacker's own key under the victim's device id
            proof = other.prove(gid, a.fingerprint())
        elif kind < 0.88:
            proof = None  # stolen session, no device
        elif kind < 0.92:
            wrong = Device(alg=dev.alg, rp_id="evil.example")
            wrong._sign, wrong.count = dev._sign, dev.count + 1
            proof = wrong.prove(gid, a.fingerprint())
        elif i < 1350:
            proof = dev.prove(gid, a.fingerprint())  # clone attempts only at the end (they freeze accounts)
        else:
            clone = Device(alg=dev.alg)
            clone._sign, clone.count = dev._sign, max(0, dev.count - 2)  # lagging copy of the key
            proof = clone.prove(gid, a.fingerprint())
        meta = {"record_ids": ids}
        if proof is not None:
            meta.update(device_id=did, device_proof=proof)
            old_proofs.append(proof)
        a2 = Action(a.identity, a.action_type, a.resource, a.count, ts=a.ts, metadata=meta)
        rp = py.release(g, a2)
        rr = ask({"op": "release", "grant": g, "action": a2.to_dict(), "now": t[0]})
        if rp.ok != rr["ok"] or rp.reason.split(":")[0] != rr["reason"].split(":")[0] \
                or (not rp.ok and rp.reason.split(":")[1:2] != rr["reason"].split(":")[1:2]):
            bad.append({"i": i, "kind": round(kind, 2), "py": [rp.ok, rp.reason], "rust": [rr["ok"], rr["reason"]]})
        elif rr["ok"] and rr.get("keys"):
            rid = ids[0]
            dek = dev.unwrap(rr["keys"][rid], rid)  # Rust wrapped it; the Python device opens it
            assert len(dek) == 32
            opened += 1
    proc.stdin.close()
    proc.wait(timeout=10)
    assert not bad, json.dumps(bad[:4], indent=1)
    assert opened > 50, opened

"""The Python reference accepts approvers' passkeys for change gates, budget overruns and unfreeze,
with the same rule as the Rust key service: the passkey signs SHA-256 of the approval message."""

import hashlib
import json
from pathlib import Path

from authority.actions import Action
from authority.binding import ES256, Device, DeviceRegistry, approver_signed
from authority.budgets import BudgetPolicy, KeyService, overrun_message
from authority.crypto import Signer, b64d, b64e
from authority.gates import ChangeGate, GatePolicy, gate_message
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]
RP = "authority.corp.example"
POLICY = json.loads((ROOT / "policies/default.json").read_text())


class Clock:
    t = 100 * 86400.0

    def __call__(self):
        return self.t


def setup():
    appr = {n: Signer.generate() for n in ("human:dana", "human:erin")}
    devs = {"human:dana": Device(rp_id=RP), "human:erin": Device(rp_id=RP, alg=ES256), "human:mallory": Device(rp_id=RP)}
    reg = DeviceRegistry(rp_id=RP)
    for who, d in devs.items():
        reg.register(who, "mbp", d.sign_public, d.kex_public, alg=d.alg)
    return appr, devs, reg


def passkey(dev, name, msg):
    return {"approver": name, "device": "mbp", "proof": dev.prove_challenge(hashlib.sha256(msg).digest())}


def test_approver_signed_cli_passkey_and_refusals():
    appr, devs, reg = setup()
    keys = {n: s.public_key for n, s in appr.items()}
    msg = b"mastyf-gate|g1|fp"
    assert approver_signed(keys, reg, {"approver": "human:dana", "sig": b64e(appr["human:dana"].sign(msg))}, msg) == "human:dana"
    assert approver_signed(keys, reg, passkey(devs["human:erin"], "human:erin", msg), msg) == "human:erin"
    # a registered device that is not an approver's
    assert approver_signed(keys, reg, passkey(devs["human:mallory"], "human:mallory", msg), msg) is None
    # signed a different request
    assert approver_signed(keys, reg, passkey(devs["human:dana"], "human:dana", b"other"), msg) is None
    # passkey without a device registry, malformed values
    assert approver_signed(keys, None, passkey(devs["human:dana"], "human:dana", msg), msg) is None
    assert approver_signed(keys, reg, {"approver": "human:dana", "sig": "!!not-base64"}, msg) is None
    assert approver_signed(keys, reg, {"approver": "human:dana", "device": "mbp", "proof": "{"}, msg) is None
    assert approver_signed(keys, reg, "nonsense", msg) is None


def test_passkey_replay_is_refused_by_the_clone_counter():
    appr, devs, reg = setup()
    keys = {n: s.public_key for n, s in appr.items()}
    msg = b"mastyf-unfreeze|human:carol|1"
    s = passkey(devs["human:dana"], "human:dana", msg)
    assert approver_signed(keys, reg, s, msg) == "human:dana"
    assert approver_signed(keys, reg, s, msg) is None  # same counter again


def test_gate_counts_passkeys_and_cli_signatures_but_not_the_requester():
    appr, devs, reg = setup()
    clock = Clock()
    auth = Signer.generate()
    gate = ChangeGate(GatePolicy.from_dict(POLICY["change_gates"]), auth.public_key,
                      {n: s.public_key for n, s in appr.items()}, now=clock, approver_devices=reg)
    a = Action("human:carol", "repo.history_rewrite", "github://org/app/main", 5, ts=clock.t)
    msg = gate_message("g1", a.fingerprint())
    mixed = [passkey(devs["human:dana"], "human:dana", msg), {"approver": "human:erin", "sig": b64e(appr["human:erin"].sign(msg))}]
    assert gate._signers("g1", a, mixed) == {"human:dana", "human:erin"}
    a2 = Action("human:dana", "repo.history_rewrite", "github://org/app/main", 5, ts=clock.t)
    msg2 = gate_message("g2", a2.fingerprint())
    assert gate._signers("g2", a2, [passkey(devs["human:dana"], "human:dana", msg2)]) == set()


def test_overrun_and_unfreeze_accept_passkeys():
    appr, devs, reg = setup()
    clock = Clock()
    auth = Signer.generate()
    ks = KeyService(BudgetPolicy.from_dict(POLICY["data_budgets"]), auth.public_key,
                    {n: s.public_key for n, s in appr.items()}, now=clock, approver_devices=reg)
    g = GrantIssuer(auth, 60, now=clock).issue(Action("human:carol", "data.read", "db://crm/customers/1", 10, ts=clock.t), "d")
    gid = json.loads(b64d(g.split(".")[0]))["gid"]
    sigs = [dict(passkey(devs[n], n, overrun_message(gid, 700)), amount=700) for n in ("human:dana", "human:erin")]
    assert ks._overrun_amount(gid, "human:carol", sigs) == 700
    # amounts must agree; booleans are not amounts
    bad = [dict(passkey(devs["human:dana"], "human:dana", overrun_message(gid, 1)), amount=True)]
    assert ks._overrun_amount(gid, "human:carol", bad) == 0

    ks.frozen["human:carol"] = "test"
    until = int(clock.t) + 600
    msg = f"mastyf-unfreeze|human:carol|{until}".encode()
    ok, why = ks.unfreeze("human:carol", until, [passkey(devs["human:dana"], "human:dana", msg),
                                                  passkey(devs["human:erin"], "human:erin", msg)])
    assert ok, why
    assert "human:carol" not in ks.frozen

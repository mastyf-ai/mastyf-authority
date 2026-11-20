"""Undo windows for irreversible actions."""

import json
from pathlib import Path

from authority.actions import Action
from authority.crypto import Signer, b64e
from authority.grants import GrantIssuer
from authority.undo import UndoGate, UndoPolicy, undo_message

ROOT = Path(__file__).resolve().parents[1]
POL = UndoPolicy.from_dict(json.loads((ROOT / "policies/default.json").read_text())["undo_windows"])
H = 3600


def world(tmp_path, alerts=None):
    t = [1_800_000_000.0]
    auth = Signer.generate()
    appr = {n: Signer.generate() for n in ("human:dana", "human:erin")}
    gate = UndoGate(POL, auth.public_key, {n: s.public_key for n, s in appr.items()}, tmp_path / "undo.journal",
                    alert=(lambda kind, **kw: alerts.append(kind)) if alerts is not None else None, now=lambda: t[0])
    iss = GrantIssuer(auth, 600, now=lambda: t[0])
    return t, auth, appr, gate, iss


def act(t, who, kind, res, n=1):
    return Action(who, kind, res, n, ts=t[0])


def test_payment_waits_and_can_be_cancelled(tmp_path):
    alerts = []
    t, auth, appr, gate, iss = world(tmp_path, alerts)
    a = act(t, "svc:billing", "payment.send", "bank://acct/ops", 5_000_000)  # $50,000 in cents
    r = gate.submit(iss.issue(a, "x"), a)
    assert not r.ok and r.pending_id and r.execute_after == t[0] + 4 * H
    assert gate.due() == [] and gate.execute(r.pending_id) is None  # not before the window ends
    assert gate.cancel(r.pending_id, "human:dana")
    t[0] += 5 * H
    assert gate.due() == [] and gate.execute(r.pending_id) is None
    small = act(t, "svc:billing", "payment.send", "bank://acct/ops", 5_000)
    assert gate.submit(iss.issue(small, "x"), small).ok  # small payment: no delay
    assert "undo_queued" in alerts and "undo_cancelled" in alerts


def test_executes_exactly_once_after_window_and_survives_restart(tmp_path):
    t, auth, appr, gate, iss = world(tmp_path)
    a = act(t, "human:carol", "dns.change", "dns://corp.example/www")
    pid = gate.submit(iss.issue(a, "x"), a).pending_id
    t[0] += 2 * H
    gate2 = UndoGate(POL, auth.public_key, gate.approver_keys, tmp_path / "undo.journal", now=lambda: t[0])  # restart
    assert gate2.due() == [pid]
    assert gate2.execute(pid)["resource"] == "dns://corp.example/www"
    assert gate2.execute(pid) is None
    gate3 = UndoGate(POL, auth.public_key, gate.approver_keys, tmp_path / "undo.journal", now=lambda: t[0])
    assert gate3.due() == [] and gate3.execute(pid) is None  # never repeated after another restart


def test_two_approvers_release_early_not_the_requester(tmp_path):
    t, auth, appr, gate, iss = world(tmp_path)
    a = act(t, "human:dana", "key.delete", "kms://prod/old-key")
    pid = gate.submit(iss.issue(a, "x"), a).pending_id
    fp = gate.pending[pid]["fingerprint"]
    sig = lambda n: {"approver": n, "sig": b64e(appr[n].sign(undo_message(pid, fp)))}  # noqa: E731
    assert not gate.expedite(pid, [sig("human:dana"), sig("human:erin")])  # requester's own does not count
    other = Signer.generate()
    gate.approver_keys["human:frank"] = other.public_key
    assert gate.expedite(pid, [sig("human:erin"), {"approver": "human:frank", "sig": b64e(other.sign(undo_message(pid, fp)))}])
    assert gate.execute(pid) is not None


def test_ransomware_run_is_stopped_and_nothing_executes(tmp_path):
    alerts = []
    t, auth, appr, gate, iss = world(tmp_path, alerts)
    results = []
    targets = [("backup.delete", "backup://vault/nightly"), ("key.delete", "kms://prod/db"),
               *[("storage.delete", f"s3://prod-{i}") for i in range(10)]]
    for kind, res in targets:
        a = act(t, "svc:backup", kind, res, 5000)
        results.append(gate.submit(iss.issue(a, "x"), a))
        t[0] += 60
    assert sum(1 for r in results if r.pending_id) == 5
    assert "frozen" in results[5].reason and all(not r.ok for r in results)
    t[0] += 4 * 24 * H
    assert gate.due() == []  # everything it queued was cancelled
    assert "undo_burst" in alerts


def test_panic_cancels_everything_and_unknown_actions_fail_closed(tmp_path):
    t, auth, appr, gate, iss = world(tmp_path)
    pids = []
    for who in ("human:alice", "human:bob", "human:carol"):
        a = act(t, who, "permission.grant", "idp://admins")
        pids.append(gate.submit(iss.issue(a, "x"), a).pending_id)
    assert gate.panic("human:mallory") == 0  # not security, not an approver
    assert gate.panic("human:erin") == 3
    t[0] += 2 * H
    assert gate.due() == []
    weird = act(t, "human:alice", "data.read", "db://crm/x")
    assert not gate.submit(iss.issue(weird, "x"), weird).ok

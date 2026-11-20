"""Rust undo gate == Python undo gate on random sequences; and it survives a crash."""

import json
import os
import random
import signal
import subprocess
from pathlib import Path

import pytest

from authority.actions import Action
from authority.crypto import Signer, b64e
from authority.grants import GrantIssuer
from authority.undo import UndoGate, UndoPolicy, undo_message

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")
POLICY = json.loads((ROOT / "policies/default.json").read_text())
KINDS = [("payment.send", "bank://acct/ops", [500, 5_000_000]), ("storage.delete", "s3://prod-x", [10, 5000]),
         ("key.delete", "kms://prod/k", [1]), ("dns.change", "dns://corp/www", [1]), ("email.bulk_send", "mail://all", [100, 9000]),
         ("permission.grant", "idp://admins", [1]), ("data.read", "db://crm/x", [1])]


def spawn(tmp, auth_pem, appr_json, state=None):
    args = [str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key", str(auth_pem),
            "--approvers", str(appr_json), "--fake-clock"]
    if state:
        args += ["--state-dir", str(state), "--kek-file", str(tmp / "kek.b64")]
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def ask(req):
        p.stdin.write(json.dumps(req) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())
    return p, ask


@pytest.fixture
def keys(tmp_path):
    auth = Signer.generate()
    appr = {n: Signer.generate() for n in ("human:dana", "human:erin", "human:bob")}
    (tmp_path / "a.pem").write_text(auth.public_pem())
    (tmp_path / "appr.json").write_text(json.dumps({n: s.public_pem() for n, s in appr.items()}))
    (tmp_path / "kek.b64").write_text("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=")
    os.chmod(tmp_path / "kek.b64", 0o600)
    return auth, appr


def test_rust_and_python_agree(tmp_path, keys):
    auth, appr = keys
    rng = random.Random(3)
    t = [1_800_000_000.0]
    py = UndoGate(UndoPolicy.from_dict(POLICY["undo_windows"]), auth.public_key, {n: s.public_key for n, s in appr.items()},
                  now=lambda: t[0])
    iss = GrantIssuer(auth, 600, now=lambda: t[0])
    p, ask = spawn(tmp_path, tmp_path / "a.pem", tmp_path / "appr.json")
    pids, bad = [], []
    for i in range(1500):
        t[0] += rng.choice([1, 60, 600, 3600, 20000])
        op = rng.random()
        if op < 0.5:
            who = rng.choice(["svc:billing", "human:carol", "svc:backup", "human:dana"])
            kind, res, counts = rng.choice(KINDS)
            a = Action(who, kind, res, rng.choice(counts), ts=t[0])
            g = iss.issue(a, "d")
            if rng.random() < 0.05:
                g = g[:-4] + "AAAA"
            rp = py.submit(g, a)
            rr = ask({"op": "undo_submit", "grant": g, "action": a.to_dict(), "now": t[0]})
            if rp.pending_id:
                pids.append(rp.pending_id)
            got = (rp.ok, bool(rp.pending_id), rp.reason.split(" ")[0])
            want = (rr["ok"], bool(rr.get("pending_id")), rr["reason"].split(" ")[0])
        elif op < 0.65 and pids:
            pid, by = rng.choice(pids), rng.choice(["human:dana", "human:erin", "human:mallory", "svc:billing"])
            got, want = py.cancel(pid, by), ask({"op": "undo_cancel", "pid": pid, "by": by})["ok"]
        elif op < 0.75 and pids:
            pid = rng.choice(pids)
            fp = py.pending[pid]["fingerprint"]
            sigs = [{"approver": n, "sig": b64e(appr[n].sign(undo_message(pid, fp)))} for n in rng.sample(list(appr), rng.choice([1, 2, 3]))]
            got, want = py.expedite(pid, sigs), ask({"op": "undo_expedite", "pid": pid, "sigs": sigs, "now": t[0]})["ok"]
        elif op < 0.78:
            by, ident = rng.choice(["human:erin", "human:mallory"]), rng.choice([None, "human:carol"])
            got = py.panic(by, ident)
            want = ask({"op": "undo_panic", "by": by, "identity": ident})["cancelled"]
        else:
            due_py = sorted(py.due())
            due_rs = ask({"op": "undo_due", "now": t[0]})["due"]
            got, want = due_py, due_rs
            if due_py and rng.random() < 0.7:
                pid = rng.choice(due_py)
                got = (due_py, py.execute(pid) is not None)
                want = (due_rs, ask({"op": "undo_execute", "pid": pid, "now": t[0]})["ok"])
        if got != want:
            bad.append({"i": i, "py": got, "rust": want})
    p.stdin.close()
    p.wait(timeout=10)
    assert not bad, json.dumps(bad[:4], indent=1, default=str)


def test_crash_never_executes_twice_or_early(tmp_path, keys):
    auth, appr = keys
    t = 1_800_000_000.0
    iss = GrantIssuer(auth, 600, now=lambda: t)
    p, ask = spawn(tmp_path, tmp_path / "a.pem", tmp_path / "appr.json", tmp_path / "state")
    a = Action("human:carol", "key.delete", "kms://prod/old", 1, ts=t)
    pid = ask({"op": "undo_submit", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": t})["pending_id"]
    b = Action("human:carol", "dns.change", "dns://corp/www", 1, ts=t)
    pid2 = ask({"op": "undo_submit", "grant": iss.issue(b, "x"), "action": b.to_dict(), "now": t})["pending_id"]
    assert ask({"op": "undo_cancel", "pid": pid2, "by": "human:erin"})["ok"]
    os.kill(p.pid, signal.SIGKILL)
    p.wait()
    p, ask = spawn(tmp_path, tmp_path / "a.pem", tmp_path / "appr.json", tmp_path / "state")
    assert ask({"op": "undo_execute", "pid": pid, "now": t + 3600})["ok"] is False  # still locked (72 h)
    assert ask({"op": "undo_due", "now": t + 80 * 3600})["due"] == [pid]  # the cancelled one stays cancelled
    assert ask({"op": "undo_execute", "pid": pid, "now": t + 80 * 3600})["ok"]
    os.kill(p.pid, signal.SIGKILL)
    p.wait()
    p, ask = spawn(tmp_path, tmp_path / "a.pem", tmp_path / "appr.json", tmp_path / "state")
    assert ask({"op": "undo_execute", "pid": pid, "now": t + 81 * 3600})["ok"] is False  # never twice
    p.stdin.close()
    p.wait(timeout=10)

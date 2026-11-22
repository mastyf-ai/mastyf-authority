"""Backup/restore drill and upgrade compatibility for the engine's state directory."""

import hashlib
import json
import shutil
from pathlib import Path

from authority import snapshot as snap
from authority.audit import AuditLog, iter_records, repair_tail, verify_log
from authority.crypto import Signer, b64e
from authority.engine import Authority
from authority.grants import GrantIssuer
from authority.policy import Policy

ROOT = Path(__file__).resolve().parents[1]


def _engine(path, signer, t):
    return Authority(Policy.load(ROOT / "policies/default.json"), GrantIssuer(signer, 60, now=lambda: t[0]),
                     AuditLog(path, signer, now=lambda: t[0], sync_interval=0, segment_bytes=20_000), now=lambda: t[0])


def _restore_like_serve(state: Path, signer, t):
    """The same steps `authority serve` takes at startup."""
    repair_tail(state / "audit.jsonl")
    body = snap.read(state / "snapshot.json", signer.public_key)
    frm, head = (body["seq"], body["head"]) if body else (0, "0" * 64)
    ok, msg = verify_log(state / "audit.jsonl", signer.public_key, frm, head)
    assert ok, msg
    auth = _engine(None, signer, t)
    if body:
        snap.load(auth, body["state"])
    auth.restore(iter_records(state / "audit.jsonl", after_seq=frm))
    return auth


def test_hot_backup_restores_with_everything_it_captured(tmp_path):
    signer = Signer.generate()
    t = [1_000_000.0]
    live = _engine(tmp_path / "live/audit.jsonl", signer, t)
    for i in range(300):
        t[0] += 7
        live.decide({"identity": "human:alice", "action_type": "auth.login", "resource": f"sso://app{i % 9}"})
        if i == 100:
            live.freeze("human:bob", "drill")
            seq, head = live.audit.position
            snap.write(tmp_path / "live/snapshot.json", live, signer, seq, head, t[0])
        if i == 200:
            live.freeze("human:carol", "drill 2")
    # copy while "running": every file as it is, plus a half-written line as a copy might catch
    backup = tmp_path / "backup"
    shutil.copytree(tmp_path / "live", backup)
    with open(backup / "audit.jsonl", "ab") as f:
        f.write(b'{"seq": 99999, "ts": 1, "pr')
    restored = _restore_like_serve(backup, signer, t)
    assert restored.frozen.keys() >= {"human:bob", "human:carol"}
    assert restored.audit.position == (0, "0" * 64)  # in-memory log for the check; the files verified above
    # and the restored copy can carry on as the live log would
    cont = AuditLog(backup / "audit.jsonl", signer, now=lambda: t[0], sync_interval=0, segment_bytes=20_000)
    assert cont.position == live.audit.position
    cont.append({"type": "decision", "note": "after restore"})
    cont.close()
    assert verify_log(backup / "audit.jsonl", signer.public_key)[0]


def _old_append(path: Path, signer, events):
    """The v0.1.0 writer (single file, no segments, no fsync): the upgrade must read what it wrote."""
    prev, seq = "0" * 64, 0
    with open(path, "a") as f:
        for ts, ev in events:
            rec = {"seq": seq + 1, "ts": ts, "prev": prev, "event": ev}
            h = hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
            rec["hash"] = h
            rec["sig"] = b64e(signer.sign(h.encode()))
            f.write(json.dumps(rec, default=str) + "\n")
            prev, seq = h, rec["seq"]


def test_upgrade_from_a_v0_1_0_audit_log(tmp_path):
    signer = Signer.generate()
    events = [(1000.0 + i, {"type": "decision", "verdict": "ALLOW", "fingerprint": f"f{i}",
                            "action": {"identity": "human:alice", "action_type": "auth.login", "resource": "sso://x",
                                       "count": 1, "destination": None, "ts": 1000.0 + i, "session": None}})
              for i in range(50)]
    events.append((2000.0, {"type": "freeze", "identity": "human:bob", "reason": "old"}))
    _old_append(tmp_path / "audit.jsonl", signer, events)
    t = [3000.0]
    auth = _restore_like_serve(tmp_path, signer, t)  # no snapshot yet: full replay
    assert auth.frozen == {"human:bob": "old"}
    new = AuditLog(tmp_path / "audit.jsonl", signer, sync_interval=0)
    assert new.position[0] == 51
    new.append({"type": "unfreeze", "identity": "human:bob", "operator": "upgrade-test"})
    new.close()
    assert verify_log(tmp_path / "audit.jsonl", signer.public_key) == (True, "52 records verified")
    assert (tmp_path / "audit.jsonl").stat().st_mode & 0o077 == 0  # tightened to owner-only on upgrade

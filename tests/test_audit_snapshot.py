"""Segmented audit log, torn-write repair, and signed state snapshots: a restart from snapshot + tail must
behave exactly like a restart that replays the whole history, and any tampering must be refused."""

import gzip
import json
import os
import shutil
from pathlib import Path

import pytest

from authority import snapshot as snap
from authority.audit import AuditLog, iter_records, record_at, repair_tail, segments, verify_log
from authority.crypto import Signer
from authority.engine import Authority
from authority.grants import GrantIssuer
from authority.model import RiskModel
from authority.policy import Policy
from authority.scenarios import world

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "artifacts/risk_model.json"


def test_rotation_chain_and_gzip(tmp_path):
    s = Signer.generate()
    log = AuditLog(tmp_path / "audit.jsonl", s, segment_bytes=4000, sync_interval=0)
    for i in range(200):
        log.append({"type": "decision", "i": i})
    log.close()
    assert len(segments(tmp_path / "audit.jsonl")) > 5
    assert verify_log(tmp_path / "audit.jsonl", s.public_key) == (True, "200 records verified")
    # a restart continues the same chain
    log = AuditLog(tmp_path / "audit.jsonl", s, segment_bytes=4000, sync_interval=0)
    log.append({"type": "freeze", "identity": "x"})
    log.close()
    assert [r["seq"] for r in iter_records(tmp_path / "audit.jsonl")] == list(range(1, 202))
    # operators may gzip closed segments; verification and replay still work
    first = segments(tmp_path / "audit.jsonl")[0]
    with open(first, "rb") as f, gzip.open(str(first) + ".gz", "wb") as g:
        shutil.copyfileobj(f, g)
    first.unlink()
    assert verify_log(tmp_path / "audit.jsonl", s.public_key)[0]
    assert record_at(tmp_path / "audit.jsonl", 3)["event"] == {"type": "decision", "i": 2}
    # verification from an anchor only reads what follows it
    r100 = record_at(tmp_path / "audit.jsonl", 100)
    assert verify_log(tmp_path / "audit.jsonl", s.public_key, 100, r100["hash"]) == (True, "101 records verified")


def test_tampering_in_an_archived_segment_is_found(tmp_path):
    s = Signer.generate()
    log = AuditLog(tmp_path / "audit.jsonl", s, segment_bytes=3000, sync_interval=0)
    for i in range(100):
        log.append({"type": "decision", "i": i})
    log.close()
    seg = segments(tmp_path / "audit.jsonl")[1]
    lines = seg.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["event"]["i"] = -1
    lines[2] = json.dumps(rec)
    seg.write_text("\n".join(lines) + "\n")
    ok, msg = verify_log(tmp_path / "audit.jsonl", s.public_key)
    assert not ok and "altered" in msg


def test_torn_final_record_is_cut_back(tmp_path):
    s = Signer.generate()
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p, s, sync_interval=0)
    for i in range(10):
        log.append({"type": "decision", "i": i})
    log.close()
    good = p.stat().st_size
    junk = b'{"seq": 11, "ts": 1, "prev": "ab'
    with open(p, "ab") as f:
        f.write(junk)  # power cut mid-write
    assert repair_tail(p) == len(junk)
    assert p.stat().st_size == good
    assert repair_tail(p) == 0  # intact files are left alone
    assert verify_log(p, s.public_key) == (True, "10 records verified")
    log = AuditLog(p, s, sync_interval=0)
    assert log.position[0] == 10
    log.close()


def test_critical_events_are_synced_before_returning(tmp_path, monkeypatch):
    s = Signer.generate()
    log = AuditLog(tmp_path / "audit.jsonl", s, sync_interval=0)
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd)))
    log.append({"type": "decision"})
    assert synced == []  # routine decisions: group-synced
    log.append({"type": "freeze", "identity": "x"})
    assert len(synced) == 1 and log.synced_seq == 2
    log.close()


@pytest.mark.skipif(not MODEL.exists(), reason="needs the trained model")
def test_snapshot_plus_tail_equals_full_replay(tmp_path):
    model = RiskModel.load(MODEL)
    events = world(7, "bulk_exfil", days=40, attack_from=30)
    s = Signer.generate()
    t = [0.0]

    def make(path):
        pol = Policy.load(ROOT / "policies/default.json")
        return Authority(pol, GrantIssuer(s, 60, now=lambda: t[0]), AuditLog(path, s, now=lambda: t[0], sync_interval=0),
                         model=model, now=lambda: t[0])

    live = make(tmp_path / "audit.jsonl")
    cut = int(len(events) * 0.6)
    for e in events[:cut]:
        t[0] = e.action.ts
        live.decide(e.action)
    seq, head = live.audit.position
    snap.write(tmp_path / "snapshot.json", live, s, seq, head, t[0])
    for e in events[cut:int(len(events) * 0.8)]:
        t[0] = e.action.ts
        live.decide(e.action)
    live.audit.close()

    body = snap.read(tmp_path / "snapshot.json", s.public_key)
    fast = make(None)
    snap.load(fast, body["state"])
    fast.restore(iter_records(tmp_path / "audit.jsonl", after_seq=body["seq"]))
    full = make(None)
    full.restore(iter_records(tmp_path / "audit.jsonl"))
    for e in events[int(len(events) * 0.8):]:
        t[0] = e.action.ts
        a, b = fast.decide(e.action), full.decide(e.action)
        assert (a.verdict, a.stage, a.risk) == (b.verdict, b.stage, b.risk), e.action
    assert fast.frozen == full.frozen


def test_snapshot_tampering_is_refused(tmp_path):
    s = Signer.generate()
    pol = Policy.load(ROOT / "policies/default.json")
    auth = Authority(pol, GrantIssuer(s, 60), AuditLog(None, s))
    auth.freeze("human:bob", "test")
    snap.write(tmp_path / "snapshot.json", auth, s, 1, "0" * 64, 100.0)
    doc = json.loads((tmp_path / "snapshot.json").read_text())
    doc["body"]["state"]["frozen"] = {}  # an attacker unfreezes someone
    (tmp_path / "snapshot.json").write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        snap.read(tmp_path / "snapshot.json", s.public_key)
    other = Signer.generate()
    snap.write(tmp_path / "s2.json", auth, other, 1, "0" * 64, 100.0)  # signed by someone else
    with pytest.raises(ValueError):
        snap.read(tmp_path / "s2.json", s.public_key)
    assert oct((tmp_path / "s2.json").stat().st_mode & 0o777) == "0o600"


def test_audit_files_are_owner_only(tmp_path):
    s = Signer.generate()
    p = tmp_path / "audit.jsonl"
    p.write_text("")
    p.chmod(0o644)  # an existing world-readable log is tightened on open
    log = AuditLog(p, s, segment_bytes=2000, sync_interval=0)
    for i in range(40):
        log.append({"type": "decision", "i": i})
    log.close()
    for f in segments(p):
        assert f.stat().st_mode & 0o077 == 0, f

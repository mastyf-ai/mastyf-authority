"""SIEM export: verified records only, OCSF classes, resumes where it stopped, refuses a tampered log."""

import json

import pytest

from authority.actions import Action
from authority.audit import AuditLog
from authority.crypto import Signer
from authority.engine import Authority
from authority.failover import FailoverError
from authority.grants import GrantIssuer
from authority.policy import Policy
from authority.siem import stream, to_ocsf


def _log(tmp_path):
    s = Signer.generate()
    log = AuditLog(tmp_path / "audit.jsonl", s, sync_interval=0)
    auth = Authority(Policy.load("policies/default.json"), GrantIssuer(s, 60), log)
    for i in range(5):
        auth.decide(Action("human:alice", "data.read", "db://crm/customers/query", 3, metadata={"origin_ip": "10.0.0.9"}))
    auth.freeze("human:bob", "stolen laptop")
    auth.decide(Action("human:bob", "data.read", "db://crm/customers/query", 3))
    log.flush()
    return s, log


def test_ocsf_classes_and_resume(tmp_path):
    s, log = _log(tmp_path)
    out = tmp_path / "ocsf.jsonl"
    assert stream(str(tmp_path), f"file:{out}", s.public_key, follow=False) == 7
    ev = [json.loads(x) for x in out.read_text().splitlines()]
    assert [e["class_uid"] for e in ev] == [6003] * 5 + [2004, 6003]
    assert ev[0]["actor"]["user"]["uid"] == "human:alice" and ev[0]["status"] == "Success"
    assert ev[0]["src_endpoint"] == {"network": "net:10.0.0"}  # network prefix only
    assert ev[5]["severity_id"] == 4 and ev[5]["finding_info"]["title"] == "freeze"
    assert ev[6]["status"] == "Failure" and "frozen" in ev[6]["message"]
    assert [e["metadata"]["uid"] for e in ev] == [str(i) for i in range(1, 8)]  # stable ids: dedup downstream
    # resumes after the last sent record
    log.append({"type": "unfreeze", "identity": "human:bob", "operator": "human:erin"})
    log.flush()
    assert stream(str(tmp_path), f"file:{out}", s.public_key, follow=False) == 1
    assert json.loads(out.read_text().splitlines()[-1])["unmapped"]["seq"] == 8


def test_tampered_record_is_never_forwarded(tmp_path):
    s, log = _log(tmp_path)
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    rec = json.loads(lines[3])
    rec["event"]["action"]["count"] = 99999  # someone edits the log
    lines[3] = json.dumps(rec)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    out = tmp_path / "ocsf.jsonl"
    with pytest.raises(FailoverError):
        stream(str(tmp_path), f"file:{out}", s.public_key, follow=False, batch=1)
    assert len(out.read_text().splitlines()) == 3  # the three records before the tampered one, nothing after


def test_every_event_type_maps():
    for ev in ({"type": "approval", "approver": "human:dana", "requester": "human:alice", "reason": "ticket"},
               {"type": "promotion", "epoch": 2}, {"type": "something_new"}):
        o = to_ocsf({"seq": 1, "ts": 1.0, "hash": "h", "event": ev})
        assert o["class_uid"] in (3005, 2004, 0) and o["metadata"]["version"] == "1.3.0"


def test_siem_refuses_cleartext_and_odd_schemes():
    import pytest

    from authority.siem import Sink
    for to in ("webhook+http://siem.corp.example/in", "webhook+file:///etc/passwd", "splunk+ftp://x"):
        with pytest.raises(SystemExit):
            Sink(to).send([{"time": 0, "metadata": {"uid": "u"}}])

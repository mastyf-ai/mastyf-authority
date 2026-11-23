"""Risk model lab (preview.py): sandboxed, side by side, and never touches the live engine."""
import time
from pathlib import Path

import pytest

from authority.policy import Policy
from authority.preview import Lab

POLICY = Path(__file__).resolve().parents[1] / "policies" / "default.json"
WEEKLY = {"identity": "human:alice", "action_type": "data.export", "resource": "db://crm/customers", "count": 1200,
          "destination": "s3://corp-reports/weekly"}


@pytest.fixture(scope="module")
def lab():
    lb = Lab(Policy.load(str(POLICY)))
    lb.start()
    end = time.time() + 180
    while lb.state not in ("ready", "error") and time.time() < end:
        time.sleep(0.2)
    assert lb.state == "ready", lb.error
    return lb


def test_lab_compares_without_and_with_a_model(lab):
    r = lab.try_action(WEEKLY, hour=14)
    assert r["without"]["verdict"] == "ESCALATE"  # no model: a sensitive action waits for a person
    assert r["with"]["verdict"] == "ALLOW"  # the model knows alice's weekly report
    assert {e["key"] for e in r["explain"]} >= {"size", "new_destination", "odd_hour"}
    assert all(0 <= e["level"] <= 1 for e in r["explain"])
    secret = lab.try_action({"identity": "human:alice", "action_type": "secret.read", "resource": "vault://prod/x", "count": 1})
    assert secret["without"]["verdict"] == secret["with"]["verdict"] == "DENY"  # policy rules apply to both


def test_replay_uses_a_fresh_sandbox_and_reports_the_person(lab):
    fp = "f" * 64
    recs = [{"event": {"type": "decision", "verdict": "ESCALATE", "fingerprint": fp, "stage": "escalate",
                       "reasons": ["risk model unavailable for a sensitive action"],
                       "action": {**WEEKLY, "ts": 14 * 3600}}},
            {"event": {"type": "denial", "fingerprint": fp, "approver": "human:dana", "reason": "no"}}]
    before = lab.tries
    out = lab.replay(recs)
    assert lab.tries == before  # the lab itself is untouched
    assert out["items"][0]["person"] == "denied"
    assert out["summary"]["held"] == 1 and out["summary"]["denied_by_you"] == 1


def test_reset(lab):
    lab.try_action(WEEKLY, hour=14)
    lab.reset()
    assert lab.tries == 0 and lab.status()["state"] == "ready"

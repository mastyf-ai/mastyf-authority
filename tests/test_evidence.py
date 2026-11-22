"""Evidence bundle: built from the verified audit log, signed, and any change to it is caught."""

import csv
import io
import json
import zipfile
from pathlib import Path

from authority.audit import AuditLog
from authority.crypto import Signer
from authority.engine import Authority
from authority.evidence import build, verify
from authority.grants import GrantIssuer
from authority.policy import Policy

ROOT = Path(__file__).resolve().parents[1]


def _engine(tmp_path, s):
    pol = Policy.load(ROOT / "policies/default.json")
    return Authority(pol, GrantIssuer(s, 60), AuditLog(tmp_path / "audit.jsonl", s, sync_interval=0))


def test_bundle_contents_and_tamper_check(tmp_path):
    s = Signer.generate()
    a = _engine(tmp_path, s)
    who = next(iter(a.policy.identities))
    a.decide({"identity": who, "action_type": "data.read", "resource": "db://crm/customers/query", "count": 1})
    a.freeze(who, "drill")
    a.unfreeze(who, "human:ops")
    a.audit.close()
    b = build(str(tmp_path), str(ROOT / "policies/default.json"), s)
    ok, msg = verify(b, s.public_key)
    assert ok, msg
    z = zipfile.ZipFile(io.BytesIO(b))
    assert json.loads(z.read("integrity.json"))["ok"]
    act = json.loads(z.read("activity.json"))
    assert sum(act["decisions_by_verdict_and_stage"].values()) == 1
    assert act["other_records"]["freeze"] == 1 and act["other_records"]["unfreeze"] == 1
    fr = list(csv.DictReader(io.StringIO(z.read("freezes.csv").decode())))
    assert [r["event"] for r in fr] == ["freeze", "unfreeze"] and fr[1]["operator"] == "human:ops"
    review = list(csv.DictReader(io.StringIO(z.read("access_review.csv").decode())))
    assert {r["identity"] for r in review} == set(a.policy.identities)

    # changing any file after signing is caught
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as w:
        for n in z.namelist():
            data = z.read(n)
            w.writestr(n, data.replace(b"drill", b"DRILL") if n == "freezes.csv" else data)
    ok, msg = verify(out.getvalue(), s.public_key)
    assert not ok and "freezes.csv" in msg
    # and another key cannot vouch for it
    assert not verify(b, Signer.generate().public_key)[0]


def test_period_filter(tmp_path):
    s = Signer.generate()
    a = _engine(tmp_path, s)
    a.freeze(next(iter(a.policy.identities)), "old")
    a.audit.close()
    b = build(str(tmp_path), str(ROOT / "policies/default.json"), s, since="2999-01-01")
    z = zipfile.ZipFile(io.BytesIO(b))
    assert json.loads(z.read("activity.json"))["other_records"] == {}
    assert json.loads(z.read("integrity.json"))["head_seq"] >= 1  # the chain is still verified in full

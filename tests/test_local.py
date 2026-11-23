"""`authority local`: every credential the console needs, made correctly and kept private."""
import hashlib
import json
import stat
from pathlib import Path

from authority import local

POLICY = Path(__file__).resolve().parents[1] / "policies" / "default.json"


def test_setup_makes_keys_callers_and_two_colleagues(tmp_path):
    d = tmp_path / "local"
    keys = local.setup(d, POLICY)
    callers = json.loads((d / "callers.json").read_text())
    assert set(keys) == set(json.loads(POLICY.read_text())["identities"]) | {"admin"}
    assert all(callers[hashlib.sha256(k.encode()).hexdigest()] == who for who, k in keys.items())
    meta = json.loads((d / "local.json").read_text())
    assert meta["you"] == "human:dana" and len(meta["colleagues"]) == 2
    assert set(json.loads((d / "approver_keys.json").read_text())) == set(meta["colleagues"])
    for f in ["keys.json"] + [c.split(":")[1] + ".key" for c in meta["colleagues"]]:
        assert stat.S_IMODE((d / f).stat().st_mode) == 0o600  # secrets readable by the owner only
    assert local.setup(d, POLICY) == keys  # a second run keeps the same keys
    assert local.setup(d, POLICY, force=True) != keys


def test_policy_is_found_without_a_checkout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = local.find_policy(None)
    assert p.name == "default.json"

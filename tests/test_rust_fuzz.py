"""Black-box fuzzing of the Rust service: hostile and garbage requests must always get an answer,
never crash it, and never release data or apply a change."""

import json
import os
import subprocess
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from authority.crypto import Signer

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")

scalar = st.one_of(st.none(), st.booleans(), st.integers(-2**70, 2**70), st.floats(allow_nan=False, allow_infinity=False),
                   st.text(max_size=60))
value = st.recursive(scalar, lambda c: st.one_of(st.lists(c, max_size=5), st.dictionaries(st.text(max_size=12), c, max_size=5)),
                     max_leaves=25)
action = st.fixed_dictionaries({}, optional={
    "identity": st.one_of(st.sampled_from(["human:alice", "human:bob", "svc:ci-bot"]), value),
    "action_type": st.one_of(st.sampled_from(["data.read", "secret.read", "artifact.publish", "backup.delete",
                                              "file.write_bulk", "repo.history_rewrite"]), value),
    "resource": st.one_of(st.sampled_from(["db://crm/customers/query", "vault://prod/ssh/hosts",
                                           "github://org/app/main", "cdn://static/js/tag.js"]), value),
    "count": st.one_of(st.integers(-5, 2**64), value),
    "destination": value,
    "metadata": st.one_of(st.fixed_dictionaries({}, optional={"record_ids": value, "candidate_sha256": value}), value),
})
request = st.one_of(
    st.fixed_dictionaries({"op": st.sampled_from(["release", "gate", "check_script", "new_record_key", "gate_set_live", "x", "undo_submit",
                                                    "undo_cancel", "undo_expedite", "undo_panic", "undo_due", "undo_execute",
                                                    "unfreeze", "assign_case", "health"])},
                          optional={"grant": st.one_of(st.text(max_size=300), value), "action": st.one_of(action, value),
                                    "overrun": value, "sigs": value, "content": value, "candidate": value,
                                    "previous": value, "record_id": value, "class": value, "now": value,
                                    "pid": value, "by": value, "identity": value, "until": value}),
    value,
)


@pytest.fixture(scope="module")
def svc(tmp_path_factory):
    d = tmp_path_factory.mktemp("fz")
    (d / "a.pem").write_text(Signer.generate().public_pem())
    p = subprocess.Popen([str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key", str(d / "a.pem")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    yield p
    p.stdin.close()
    p.wait(timeout=10)


@settings(max_examples=int(os.environ.get("FUZZ_EXAMPLES", "3000")), deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
@given(request)
def test_service_survives_and_never_grants(svc, req):
    line = json.dumps(req, ensure_ascii=False)
    svc.stdin.write(line.replace("\n", " ") + "\n")
    svc.stdin.flush()
    out = svc.stdout.readline()
    assert out, "service died"
    resp = json.loads(out)
    assert svc.poll() is None
    if isinstance(req, dict) and req.get("op") in ("release", "gate", "undo_submit", "undo_execute", "undo_expedite", "unfreeze"):
        assert resp.get("ok") is not True  # no valid grant, signature or queued action was ever supplied

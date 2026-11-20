import json
from pathlib import Path

import pytest

from authority import script_integrity
from authority.actions import Action
from authority.crypto import Signer, b64d, b64e
from authority.gates import ChangeGate, GatePolicy, gate_message
from authority.grants import GrantIssuer
from authority.learn import learn_data_budgets
from authority.scenarios import world

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    t = 100 * 86400.0

    def __call__(self):
        return self.t


@pytest.fixture
def env():
    clock = Clock()
    gp = GatePolicy.from_dict(json.loads((ROOT / "policies/default.json").read_text())["change_gates"])
    auth = Signer.generate()
    appr = {n: Signer.generate() for n in ("human:bob", "human:dana", "human:erin")}
    gate = ChangeGate(gp, auth.public_key, {n: s.public_key for n, s in appr.items()}, now=clock)
    return gate, GrantIssuer(auth, 60, now=clock), appr, clock


def sigs(appr, names, grant, a):
    gid = json.loads(b64d(grant.split(".")[0]))["gid"]
    return [{"approver": n, "sig": b64e(appr[n].sign(gate_message(gid, a.fingerprint())))} for n in names]


def publish(clock, src):
    return Action("svc:ci-bot", "artifact.publish", "cdn://static/js/tag.js", 1, ts=clock.t,
                  metadata={"candidate_sha256": script_integrity.check(None, src)["candidate_sha256"]})


def test_gate_blocks_skimmer_even_with_valid_grant_and_quorum(env):
    gate, issuer, appr, clock = env
    v1 = (ROOT / "fixtures/tag_v1.js").read_text()
    bad = (ROOT / "fixtures/tag_v2_skimmer.js").read_text()
    gate.live["cdn://static/js/tag.js"] = v1
    a = publish(clock, bad)
    g = issuer.issue(a, "x")
    assert not gate.apply(g, a, sigs(appr, ["human:dana", "human:erin"], g, a), content=bad).ok
    ok = v1 + "\n// build 2\n"
    b = publish(clock, ok)
    assert gate.apply(issuer.issue(b, "x"), b, content=ok).ok  # benign update needs no human


def test_gate_rejects_content_swap(env):
    gate, issuer, _, clock = env
    v1 = (ROOT / "fixtures/tag_v1.js").read_text()
    gate.live["cdn://static/js/tag.js"] = v1
    a = publish(clock, v1 + "\n// build 2\n")  # grant covers the benign hash...
    bad = (ROOT / "fixtures/tag_v2_skimmer.js").read_text()
    assert not gate.apply(issuer.issue(a, "x"), a, content=bad).ok  # ...but different bytes arrive


def test_protected_rewrite_and_rewrite_budget(env):
    gate, issuer, appr, clock = env
    main = Action("human:carol", "repo.history_rewrite", "github://org/app/main", 3, ts=clock.t)
    assert not gate.apply(issuer.issue(main, "x"), main).ok
    g = issuer.issue(main, "x")
    assert not gate.apply(g, main, sigs(appr, ["human:dana"], g, main)).ok
    g = issuer.issue(main, "x")
    assert gate.apply(g, main, sigs(appr, ["human:dana", "human:erin"], g, main)).ok
    feat = Action("human:carol", "repo.history_rewrite", "github://org/app/feature/3", 25, ts=clock.t)
    assert gate.apply(issuer.issue(feat, "x"), feat).ok
    assert not gate.apply(issuer.issue(feat, "x"), feat).ok  # 50 > 30 per day


def test_backup_delete_is_time_locked(env):
    gate, issuer, appr, clock = env
    a = Action("human:bob", "backup.delete", "backup://vault/nightly", 10, ts=clock.t)
    assert not gate.apply(issuer.issue(a, "x"), a).ok
    g = issuer.issue(a, "x")
    r = gate.apply(g, a, sigs(appr, ["human:dana", "human:erin"], g, a))
    assert not r.ok and r.pending_id
    assert gate.due(clock.t + 3600) == []
    assert len(gate.due(clock.t + 73 * 3600)) == 1
    assert gate.cancel(r.pending_id, "human:erin")
    assert gate.due(clock.t + 73 * 3600) == []


def test_write_budget_unlisted_target_is_zero(env):
    gate, issuer, _, clock = env
    a = Action("human:bob", "file.write_bulk", "fs://prod/data", 5000, ts=clock.t)
    assert not gate.apply(issuer.issue(a, "x"), a).ok


def test_learned_budgets_zero_for_unseen_and_below_spikes():
    hist = [e.action for e in world(7, None) if e.action.ts < 30 * 86400]
    b = learn_data_budgets(hist, {"ssh.key": ["fs://home/*", "vault://prod/ssh/*"], "secret": ["vault://prod/*"],
                                  "crm.customer": ["db://crm/customers*"]})
    assert "svc:status-page" not in b  # never read keys: budget 0
    assert b["svc:export-job"]["crm.customer@s3://corp-warehouse"] < 30000  # monthly spike stays an approval

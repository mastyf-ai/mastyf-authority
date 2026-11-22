"""Stateful fuzzing of the decision engine: random sequences of actions, approvals, freezes, unfreezes,
clock jumps and snapshot-restores, with the safety invariants checked after every step."""

from collections import defaultdict, deque
from pathlib import Path

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from authority import snapshot as snap
from authority.audit import AuditLog
from authority.crypto import Signer
from authority.engine import ALLOW, DENY, Authority, sign_approval
from authority.grants import GrantIssuer
from authority.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
POLICY = Policy.load(ROOT / "policies/default.json")
PEOPLE = [n for n in POLICY.identities if not POLICY.identities[n].approver]
APPROVER = next(n for n, r in POLICY.identities.items() if r.approver and r.kind == "human")
RESOURCES = ["db://crm/customers/query", "db://crm/customers/canary-7", "vault://prod/db-password",
             "vault://prod/canary-key", "fs://prod/data", "github://org/app/main", "s3://corp-reports/x", "net://out"]
DESTS = [None, "s3://corp-reports", "s3://corp-warehouse", "https://pastebin.com/raw", "x.onion", "s3://unknown-bucket",
         "https://monitoring.corp.example/push"]
TYPES = sorted({t for r in POLICY.identities.values() for t in r.allowed_actions} | {"data.export", "secret.read"})
DAY = 86400.0


class Engine(RuleBasedStateMachine):
    @initialize()
    def setup(self):
        self.t = [100 * DAY]
        self.signer = Signer.generate()
        self.approver = Signer.generate()
        self.auth = self._new()
        self.allowed = defaultdict(deque)  # (identity, type) -> (ts, count) allowed without approval
        self.used_approvals = set()
        self.last = None

    def _new(self):
        pol = Policy.load(ROOT / "policies/default.json")
        return Authority(pol, GrantIssuer(self.signer, 60, now=lambda: self.t[0]),
                         AuditLog(None, self.signer, now=lambda: self.t[0]),
                         approver_keys={APPROVER: self.approver.public_key}, now=lambda: self.t[0])

    @rule(who=st.sampled_from(PEOPLE + ["human:mallory"]), atype=st.sampled_from(TYPES),
          res=st.sampled_from(RESOURCES), count=st.integers(-3, 70000), dest=st.sampled_from(DESTS))
    def act(self, who, atype, res, count, dest):
        frozen_before = who in self.auth.frozen
        a = {"identity": who, "action_type": atype, "resource": res, "count": count, "destination": dest}
        d = self.auth.decide(a)
        self.last = (a, d)
        if frozen_before or who not in POLICY.identities:
            assert d.verdict != ALLOW, (a, d.reasons)
        if dest and ("pastebin" in dest or dest.endswith(".onion")):
            assert d.verdict != ALLOW, (a, d.reasons)
        if "canary" in res and who in POLICY.identities and count >= 0:  # malformed requests are refused earlier
            assert d.verdict == DENY and who in self.auth.frozen
        if d.verdict == ALLOW and d.stage != "approval":
            th = POLICY.thresholds.get(atype, {}) if hasattr(POLICY, "thresholds") else {}
            dq = self.allowed[(who, atype)]
            dq.append((self.t[0], count))
            while dq and dq[0][0] < self.t[0] - DAY:
                dq.popleft()
            if "per_day" in th:
                assert sum(c for _, c in dq) <= th["per_day"], (who, atype, list(dq))
            if "per_action" in th:
                assert count <= th["per_action"]

    @rule()
    def approve_last(self):
        if not self.last or self.last[1].verdict != "ESCALATE" or self.last[0]["identity"] == APPROVER:
            return
        a, d = self.last
        reason = "ticket OPS-1234"
        aid = self.auth.approve(d.fingerprint, a["identity"], APPROVER, reason,
                                sign_approval(self.approver, d.fingerprint, a["identity"], reason))
        d1 = self.auth.decide(a, approval_id=aid)
        d2 = self.auth.decide(a, approval_id=aid)  # an approval works once
        if d1.verdict == ALLOW and d1.stage == "approval":
            assert not (d2.verdict == ALLOW and d2.stage == "approval")
        self.last = None

    @rule(who=st.sampled_from(PEOPLE))
    def freeze(self, who):
        self.auth.freeze(who, "fuzz")
        assert self.auth.decide({"identity": who, "action_type": "auth.login", "resource": "x"}).verdict != ALLOW

    @rule(who=st.sampled_from(PEOPLE))
    def unfreeze(self, who):
        self.auth.unfreeze(who, "fuzz-operator")

    @rule(secs=st.sampled_from([1, 60, 3600, 6 * 3600, DAY, 3 * DAY]))
    def time_passes(self, secs):
        self.t[0] += secs

    @rule(probe=st.sampled_from(PEOPLE), atype=st.sampled_from(TYPES), res=st.sampled_from(RESOURCES))
    def snapshot_restore_changes_nothing(self, probe, atype, res):
        body = snap.dump(self.auth, self.t[0])
        other = self._new()
        snap.load(other, body)
        a = {"identity": probe, "action_type": atype, "resource": res, "count": 3}
        # decide on both (each mutates its own state the same way)
        x, y = self.auth.decide(a), other.decide(a)
        assert (x.verdict, x.stage, x.reasons) == (y.verdict, y.stage, y.reasons)
        assert self.auth.frozen == other.frozen

    @invariant()
    def frozen_never_allowed(self):
        for who in list(self.auth.frozen)[:3]:
            d = self.auth.decide({"identity": who, "action_type": "auth.login", "resource": "x"})
            assert d.verdict != ALLOW


import os  # noqa: E402

Engine.TestCase.settings = settings(max_examples=int(os.environ.get("STATEFUL_EXAMPLES", "60")), stateful_step_count=40, deadline=None,
                                    suppress_health_check=[HealthCheck.too_slow])
TestEngine = Engine.TestCase

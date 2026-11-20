"""The decision pipeline.

Order (first match wins; later layers can only make the outcome stricter):
  1. malformed input, unknown identity, frozen identity      -> DENY
  2. canary touched                                          -> DENY + freeze identity
  3. hard policy: action not permitted, protected-branch
     history rewrite, denied destination                     -> DENY
  4. artifact.publish: script-integrity report                -> block = DENY, review/missing = ESCALATE
  5. thresholds, always-escalate types, unlisted destination  -> ESCALATE
  6. risk model (can only escalate or deny, never grant)      -> ESCALATE / DENY
  7. otherwise                                                -> ALLOW with a signed single-use grant

A human approval (two-person rule) clears ESCALATE results and model DENY for that exact
action. It never clears steps 1–3 or an integrity "block".
If the model is missing or errors, sensitive actions ESCALATE (fail closed).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .actions import SENSITIVE, Action, ActionError
from .audit import AuditLog
from .crypto import b64d, b64e, verify
from .features import DAY, HOUR, FeatureState, dest_key
from .agents import AgentSessions
from .novelty import NoveltyScorer, ReviewQueue
from .grants import GrantIssuer
from .model import RiskModel
from .policy import Policy, matches

ALLOW, ESCALATE, DENY = "ALLOW", "ESCALATE", "DENY"


def approval_message(fingerprint: str, requester: str, reason: str) -> bytes:
    return f"mastyf-approve|{fingerprint}|{requester}|{reason}".encode()


def sign_approval(signer, fingerprint: str, requester: str, reason: str) -> str:
    """Run by the approver on their own device; the private key never reaches the authority."""
    return b64e(signer.sign(approval_message(fingerprint, requester, reason)))


@dataclass
class Decision:
    verdict: str
    reasons: list[str]
    decision_id: str
    fingerprint: str | None = None
    risk: float | None = None
    grant: str | None = None
    stage: str = ""
    approved_by: str | None = None
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, {}, "")}


class Authority:
    def __init__(
        self,
        policy: Policy,
        issuer: GrantIssuer,
        audit: AuditLog,
        model: RiskModel | None = None,
        now=time.time,
        approver_keys: dict | None = None,
        devices=None,
    ):
        self.policy = policy
        self.issuer = issuer
        self.audit = audit
        self.model = model
        self.now = now
        self.approver_keys = approver_keys or {}  # approver identity -> Ed25519 public key
        self.novelty = NoveltyScorer()
        self.review = ReviewQueue(per_day=5)  # quiet cases for a human, a few a day
        self.agents = AgentSessions(policy, devices, alert=lambda kind, **kw: self._alert(kind, **kw),
                                    audit=self.audit.append, now=self.now)
        self.devices = devices  # binding.DeviceRegistry: approvers may sign with their passkey instead
        self.state = FeatureState(policy.identity_meta())
        self.frozen: dict[str, str] = {}
        self.integrity: dict[str, dict] = {}  # candidate sha256 -> report
        self.approvals: dict[str, dict] = {}  # approval id -> record
        self.pending: dict[str, dict] = {}  # fingerprint -> escalated request awaiting a human
        self.daily: dict[tuple[str, str], deque] = defaultdict(deque)  # allowed volume, rolling 24h
        self.denials: dict[str, deque] = defaultdict(deque)
        self.alerts: list[dict] = []
        self.counts: dict[str, int] = defaultdict(int)  # metrics: decisions by verdict/stage
        self._lock = threading.RLock()

    # ---- operator actions -------------------------------------------------
    def freeze(self, identity: str, reason: str) -> None:
        with self._lock:
            self.frozen[identity] = reason
            self._alert("identity_frozen", identity=identity, reason=reason)
            self.audit.append({"type": "freeze", "identity": identity, "reason": reason})

    def unfreeze(self, identity: str, operator: str) -> None:
        with self._lock:
            self.frozen.pop(identity, None)
            self.audit.append({"type": "unfreeze", "identity": identity, "operator": operator})

    def record_integrity(self, report: dict) -> None:
        with self._lock:
            self.integrity[report["candidate_sha256"]] = report
            self.audit.append({"type": "integrity_report", "sha256": report["candidate_sha256"],
                               "verdict": report["verdict"], "findings": report["findings"]})

    def approve(self, fingerprint: str, requester: str, approver: str, reason: str, signature: str = "") -> str:
        """`signature`: approver's Ed25519 signature (base64url) over approval_message(...).
        Claiming to be an approver is not enough; the approver's own key must sign."""
        with self._lock:
            rule = self.policy.identities.get(approver)
            pend = self.pending.get(fingerprint) or {}
            # the person who started an agent session may confirm that agent's escalations
            principal = self.agents.principal_of(requester, (pend.get("action") or {}).get("session"))
            if (rule is None or not rule.approver or rule.kind != "human") and approver != principal:
                raise PermissionError(f"{approver} is not an approver")
            msg = approval_message(fingerprint, requester, reason)
            if signature.lstrip().startswith("{"):  # passkey assertion from the approver's registered device
                if self.devices is None:
                    raise PermissionError("passkey approvals are not enabled")
                try:
                    dev = json.loads(signature).get("device", "")
                except ValueError:
                    dev = ""
                ok, why = self.devices.verify_for(approver, dev, signature, hashlib.sha256(msg).digest())
                if not ok:
                    raise PermissionError(f"passkey approval from {approver} refused: {why}")
            else:
                pk = self.approver_keys.get(approver)
                try:
                    sig = b64d(signature)
                except Exception:  # noqa: BLE001
                    sig = b""
                if pk is None or not verify(pk, sig, msg):
                    raise PermissionError(f"missing or invalid signature from {approver}")
            if approver == requester:
                raise PermissionError("two-person rule: requester cannot approve their own action")
            if approver in self.frozen:
                raise PermissionError("approver is frozen")
            if not reason or len(reason) < 8:
                raise ValueError("approval needs a reason (ticket or justification)")
            aid = secrets.token_hex(12)
            self.approvals[aid] = {
                "fingerprint": fingerprint, "requester": requester, "approver": approver,
                "reason": reason, "exp": self.now() + self.policy.approval_ttl_seconds, "used": False,
            }
            self.audit.append({"type": "approval", "approval_id": aid, "fingerprint": fingerprint,
                               "requester": requester, "approver": approver, "reason": reason})
            return aid

    def restore(self, records: list[dict]) -> int:
        """Rebuild state (behaviour baselines, daily volumes, frozen identities, approvals, pending
        requests, integrity reports) by replaying a verified audit log. Nothing is re-logged."""
        n = 0
        with self._lock:
            for rec in records:
                ev = rec.get("event", {})
                kind = ev.get("type")
                n += 1
                if kind == "decision" and "action" in ev:
                    try:
                        a = Action.from_dict({**ev["action"], "metadata": {}})
                    except ActionError:
                        continue
                    verdict, fp = ev.get("verdict"), ev.get("fingerprint")
                    self.state.observe(a, learn=verdict == ALLOW)
                    self.novelty.observe(a, learn=verdict == ALLOW)
                    if verdict == ALLOW:
                        self.daily[(a.identity, a.action_type)].append((a.ts, a.count))
                    if verdict == ESCALATE and fp:
                        self.pending[fp] = {"fingerprint": fp, "requester": a.identity,
                                            "action": {k: v for k, v in a.to_dict().items() if k != "metadata"},
                                            "reasons": ev.get("reasons", []), "risk": ev.get("risk"), "ts": a.ts}
                    elif ev.get("stage") == "approval" and fp:
                        self.pending.pop(fp, None)
                        for ap in self.approvals.values():
                            if ap["fingerprint"] == fp and not ap["used"]:
                                ap["used"] = True
                                break
                elif kind == "freeze":
                    self.frozen[ev["identity"]] = ev.get("reason", "")
                elif kind == "unfreeze":
                    self.frozen.pop(ev["identity"], None)
                elif kind == "approval":
                    self.approvals[ev["approval_id"]] = {
                        "fingerprint": ev["fingerprint"], "requester": ev["requester"], "approver": ev["approver"],
                        "reason": ev["reason"], "exp": rec["ts"] + self.policy.approval_ttl_seconds, "used": False}
                elif kind == "denial":
                    self.pending.pop(ev.get("fingerprint"), None)
                elif kind == "destination_learned":
                    self.learned_destinations[(ev["identity"], ev["destination"])] = rec["ts"]
                elif kind == "integrity_report":
                    self.integrity[ev["sha256"]] = {"candidate_sha256": ev["sha256"], "verdict": ev["verdict"],
                                                    "findings": ev.get("findings", [])}
        return n

    @property
    def learned_destinations(self) -> dict:
        d = getattr(self, "_learned_dest", None)
        if d is None:
            d = self._learned_dest = {}
        return d

    def _learn_destination(self, a: Action, why: str) -> None:
        """Ask once: with `destinations.learn_on_approval` in the policy, a destination approved for an
        identity stops escalating for that identity only. Never bypasses deny lists, limits, bait or the
        model. Audited, so it survives restarts and can be reviewed."""
        if not a.destination or not self.policy.raw.get("destinations", {}).get("learn_on_approval"):
            return
        key = (a.identity, dest_key(a.destination))
        if key in self.learned_destinations:
            return
        self.learned_destinations[key] = a.ts
        self.audit.append({"type": "destination_learned", "identity": a.identity, "destination": key[1],
                           "why": why})

    def deny(self, fingerprint: str, approver: str, reason: str) -> bool:
        with self._lock:
            rule = self.policy.identities.get(approver)
            if rule is None or not rule.approver:
                raise PermissionError(f"{approver} is not an approver")
            item = self.pending.pop(fingerprint, None)
            self.audit.append({"type": "denial", "fingerprint": fingerprint, "approver": approver, "reason": reason})
            return item is not None

    # ---- decision ---------------------------------------------------------
    def _no_data_budget(self, a: Action) -> str | None:
        """Refuse up front a key-releasing action on a budgeted data class for which this identity has
        no daily budget and no approved top-up (overrun) allowance. The key service would refuse it too;
        deciding it here keeps the decision honest (no ALLOW that can never release anything)."""
        from .budgets import READ_ACTIONS, BudgetPolicy
        raw = self.policy.raw.get("data_budgets")
        if not raw or a.action_type not in READ_ACTIONS:
            return None
        cached = getattr(self, "_budget_cache", None)
        if cached is None or cached[0] is not raw:
            cached = (raw, BudgetPolicy.from_dict(raw))
            self._budget_cache = cached
        bp = cached[1]
        cls = bp.classify(a.resource)
        if cls is None:
            return None
        key, allowance = bp.budget(a.identity, cls, a.destination)
        if allowance > 0 or bp.overrun_cap(a.identity, cls) != 0:
            return None
        return f"{a.identity} has no daily budget for {cls} ({key})"

    def decide(self, raw: dict | Action, approval_id: str | None = None) -> Decision:
        did = secrets.token_hex(12)
        try:
            action = raw if isinstance(raw, Action) else Action.from_dict(raw)
            # the authority's own clock, never the caller's: windows and baselines cannot be gamed
            action = dataclasses.replace(action, ts=self.now())
        except (ActionError, TypeError, ValueError) as e:
            d = Decision(DENY, [f"malformed action: {e}"], did, stage="input")
            self.audit.append({"type": "decision", **d.to_dict()})
            return d
        with self._lock:
            try:
                d = self._decide(action, did, approval_id)
            except Exception as e:  # noqa: BLE001 - fail closed on any internal error
                d = Decision(DENY, [f"internal error, failing closed: {type(e).__name__}"], did,
                             fingerprint=action.fingerprint(), stage="error")
            self._after(action, d)
            return d

    def _decide(self, a: Action, did: str, approval_id: str | None) -> Decision:
        p = self.policy
        fp = a.fingerprint()
        D = lambda v, reasons, stage, **k: Decision(v, reasons, did, fingerprint=fp, stage=stage, **k)  # noqa: E731

        rule = p.identities.get(a.identity)
        if rule is None:
            return D(DENY, ["unknown identity"], "identity")
        if a.identity in self.frozen:
            return D(DENY, [f"identity frozen: {self.frozen[a.identity]}"], "identity")

        if p.is_canary(a.resource, a.metadata):
            self.freeze(a.identity, f"touched canary {a.resource}")
            return D(DENY, ["canary touched: identity frozen, incident opened"], "canary")

        if a.action_type not in rule.allowed_actions:
            return D(DENY, [f"{a.identity} is not permitted to perform {a.action_type}"], "policy")
        if a.action_type == "repo.history_rewrite" and p.is_protected_branch(a.resource):
            return D(DENY, ["history rewrite on a protected branch"], "policy")
        if a.destination and matches(dest_key(a.destination), p.destinations_deny):
            return D(DENY, [f"destination {a.destination} is denied"], "policy")

        agent_esc: list[str] = []
        if rule.kind == "agent":  # AI agents: only the task a person approved (agents.py)
            v, why = self.agents.check(a)
            if v == DENY:
                return D(DENY, why, "agent")
            agent_esc = why
        no_budget = self._no_data_budget(a)
        if no_budget:
            return D(DENY, [no_budget], "policy")

        approval = self._valid_approval(approval_id, a, fp)
        escalations: list[str] = list(agent_esc)

        if a.action_type == "artifact.publish":
            sha = a.metadata.get("candidate_sha256")
            rep = self.integrity.get(sha) if sha else None
            if rep is None:
                escalations.append("no integrity report for this artifact")
            elif rep["verdict"] == "block":
                codes = ", ".join(x["code"] for x in rep["findings"])
                return D(DENY, [f"script integrity check blocked this artifact ({codes})"], "integrity")
            elif rep["verdict"] == "review":
                escalations.append("script integrity check needs review: "
                                   + ", ".join(x["code"] for x in rep["findings"]))

        th = p.thresholds.get(a.action_type)
        if th:
            if "per_action" in th and a.count > th["per_action"]:
                escalations.append(f"{a.action_type} count {a.count} > per-action limit {th['per_action']}")
            if "per_day" in th:
                used = self._daily_used(a.identity, a.action_type, a.ts)
                if used + a.count > th["per_day"]:
                    escalations.append(f"{a.action_type} 24h volume {used + a.count} > daily limit {th['per_day']}")
        if a.action_type in p.always_escalate:
            escalations.append(f"{a.action_type} always needs approval")
        if (a.destination and not matches(dest_key(a.destination), p.destinations_allow)
                and (a.identity, dest_key(a.destination)) not in self.learned_destinations):
            escalations.append(f"destination {dest_key(a.destination)} not on the allowlist")

        risk = None
        model_deny = False
        # policy model.skip: action types the behavioural layers do not judge. Default: sign-ins, which device
        # binding and ask-once destinations judge instead (on real enterprise sign-in logs the behavioural
        # layers interrupted people ~31 times a day; device binding alone, 0.2 - see PILOTS.md)
        behavioural = a.action_type not in self.policy.raw.get("model", {}).get("skip", [])
        if self.model is not None and behavioural:
            try:
                risk = self.model.score(self.state.features(a))
            except Exception:  # noqa: BLE001
                risk = None
        if risk is None and a.action_type in SENSITIVE:
            escalations.append("risk model unavailable for a sensitive action")
        # novelty: first-time behaviour weighted by how rare it is here, plus slow build-up
        nov, nov_why = self.novelty.risk(a) if behavioural else (0.0, [])
        self.review.note(a.identity, a.ts, nov, nov_why)
        if nov > (risk or 0.0):
            risk = round(nov, 4)
            escalations.extend(nov_why[:3])
        if risk is not None:
            if risk >= p.deny_at:
                model_deny = True
            elif risk >= p.escalate_at:
                escalations.append(f"behaviour unusual for {a.identity} (risk {risk:.2f})")

        if approval:
            approval["used"] = True
            self._learn_destination(a, f"approved by {approval['approver']}")
            reasons = [f"approved by {approval['approver']}: {approval['reason']}"] + escalations
            if model_deny:
                reasons.append(f"model risk {risk:.2f} overridden by approval")
            return self._allow(a, D(ALLOW, reasons, "approval", risk=risk, approved_by=approval["approver"]))
        if model_deny:
            return D(DENY, [f"behaviour highly anomalous for {a.identity} (risk {risk:.2f})"] + escalations,
                     "model", risk=risk)
        if escalations:
            return D(ESCALATE, escalations, "escalate", risk=risk)
        return self._allow(a, D(ALLOW, ["within policy and normal behaviour"], "allow", risk=risk))

    # ---- helpers ----------------------------------------------------------
    def _allow(self, a: Action, d: Decision) -> Decision:
        cons = {}
        if a.action_type == "data.export":
            cons = {"max_rows": a.count, "destination": a.destination}
        if d.risk is not None and d.risk >= 0.5:
            # the model may only shrink the key service's data budget, never raise it
            cons["budget_factor"] = round(max(0.0, 1.0 - d.risk), 3)
        cons.update(self.agents.constraints(a))  # agent sessions: record cap enforced by the key service too
        d.grant = self.issuer.issue(a, d.decision_id, cons)
        return d

    def _valid_approval(self, aid: str | None, a: Action, fp: str) -> dict | None:
        if not aid:
            return None
        ap = self.approvals.get(aid)
        if not ap or ap["used"] or ap["exp"] < self.now() or ap["fingerprint"] != fp or ap["requester"] != a.identity:
            return None
        return ap

    def _daily_used(self, identity: str, atype: str, ts: float) -> int:
        dq = self.daily[(identity, atype)]
        while dq and dq[0][0] < ts - DAY:
            dq.popleft()
        return sum(c for _, c in dq)

    def _alert(self, kind: str, **kw) -> None:
        self.alerts.append({"kind": kind, "ts": self.now(), **kw})

    def metrics(self) -> str:
        """Prometheus text format."""
        lines = ["# TYPE authority_decisions_total counter"]
        for k, v in sorted(self.counts.items()):
            verdict, stage = k.split("|")
            lines.append(f'authority_decisions_total{{verdict="{verdict}",stage="{stage}"}} {v}')
        lines += ["# TYPE authority_frozen_identities gauge", f"authority_frozen_identities {len(self.frozen)}",
                  "# TYPE authority_pending_requests gauge", f"authority_pending_requests {len(self.pending)}",
                  "# TYPE authority_model_loaded gauge", f"authority_model_loaded {int(self.model is not None)}"]
        return "\n".join(lines) + "\n"

    def _after(self, a: Action, d: Decision) -> None:
        self.counts[f"{d.verdict}|{d.stage or 'none'}"] += 1
        allowed = d.verdict == ALLOW
        self.state.observe(a, learn=allowed)
        self.novelty.observe(a, learn=allowed)
        self.agents.record(a, allowed)
        if allowed:
            self.daily[(a.identity, a.action_type)].append((a.ts, a.count))
        if d.verdict == DENY and d.stage not in ("identity", "canary"):
            dq = self.denials[a.identity]
            dq.append(a.ts)
            while dq and dq[0] < a.ts - HOUR:
                dq.popleft()
            if len(dq) >= self.policy.auto_freeze_denials_per_hour and a.identity not in self.frozen:
                self.freeze(a.identity, f"{len(dq)} denied actions within one hour")
        if d.verdict == ESCALATE:
            self.pending[d.fingerprint] = {"fingerprint": d.fingerprint, "requester": a.identity,
                                           "action": {k: v for k, v in a.to_dict().items() if k != "metadata"},
                                           "reasons": d.reasons, "risk": d.risk, "ts": a.ts}
            if len(self.pending) > 1000:
                self.pending.pop(next(iter(self.pending)))
        elif d.stage == "approval":
            self.pending.pop(d.fingerprint, None)
        if d.verdict != ALLOW:
            self._alert("decision", verdict=d.verdict, identity=a.identity, action=a.action_type,
                        resource=a.resource, reasons=d.reasons)
        rec = {"type": "decision", **{k: v for k, v in d.to_dict().items() if k != "grant"},
               "action": {k: v for k, v in a.to_dict().items() if k != "metadata"}}
        self.audit.append(rec)

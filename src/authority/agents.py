"""Limits for AI agents: an agent can only do the task a person approved, within a budget.

An AI agent acting for a person is the easiest identity to hijack: a web page, e-mail or document
it reads can carry instructions ("prompt injection") that turn it against the person it serves.
So agents never act on their own authority. Each run is a *session* approved by the person, with
a task manifest:

    {"agent": "agent:support-bot", "principal": "human:alice", "task": "answer ticket 4812",
     "allow": [{"action": "data.read", "resource": "db://crm/customers/*", "max_count": 20},
               {"action": "network.egress", "destination": "api.helpdesk.example"}],
     "max_actions": 50, "max_records": 200, "ttl_seconds": 3600}

Rules the authority enforces for every agent action:
  1. the action must cite an active, unexpired, unrevoked session of that agent;
  2. it must match an entry of the approved manifest (type, resource, destination, count):
     anything else is refused as "outside the task", and 3 such refusals revoke the session and
     alert the person (an injected agent probing for what it can do);
  3. delegation never adds rights: every manifest entry must be allowed for BOTH the person and the
     agent identity, and the session cannot outlive 8 hours;
  4. parameters the agent runtime marks as coming from untrusted content (metadata.provenance:
     {"destination": "untrusted"}) or any sensitive action need the person's own confirmation
     (an escalation only the principal or an approver can approve);
  5. totals: at most max_actions actions and max_records records per session. The record total is
     also written into the grant ("sess", "sess_max") and enforced by the key service, so it holds
     even if the authority were bypassed for a moment.

The person approves the manifest with their passkey (sha256 of the canonical manifest is the
challenge), so a stolen session cookie cannot start agents in their name.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from fnmatch import fnmatchcase

from .actions import SENSITIVE, Action
from .features import dest_key

MAX_TTL = 8 * 3600
OUTBOUND = frozenset({"payment.send", "network.egress", "data.export", "email.bulk_send"})
STRIKES = 3


def manifest_bytes(m: dict) -> bytes:
    keep = {k: m[k] for k in ("agent", "principal", "task", "allow", "max_actions", "max_records", "ttl_seconds", "nonce")
            if k in m}
    return json.dumps(keep, sort_keys=True, separators=(",", ":")).encode()


def manifest_challenge(m: dict) -> bytes:
    return hashlib.sha256(b"mastyf-agent|" + manifest_bytes(m)).digest()


class AgentSessions:
    def __init__(self, policy, devices=None, alert=None, audit=None, now=time.time):
        self.policy = policy
        self.devices = devices  # binding.DeviceRegistry: the person's passkey approves the manifest
        self.alert = alert or (lambda *a, **k: None)
        self.audit = audit or (lambda ev: None)
        self.now = now
        self.sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def is_agent(self, identity: str) -> bool:
        r = self.policy.identities.get(identity)
        return r is not None and r.kind == "agent"

    # ------------------------------------------------------------------ approval by the person
    def start(self, manifest: dict, device_id: str, proof: str) -> dict:
        m = dict(manifest)
        agent, principal = m.get("agent", ""), m.get("principal", "")
        if not self.is_agent(agent):
            raise PermissionError(f"{agent} is not an agent identity")
        prule = self.policy.identities.get(principal)
        if prule is None or prule.kind != "human":
            raise PermissionError("an agent session must be approved by a person")
        arule = self.policy.identities[agent]
        ttl = int(m.get("ttl_seconds", 3600))
        if not 0 < ttl <= MAX_TTL:
            raise ValueError(f"ttl_seconds must be 1..{MAX_TTL}")
        allow = m.get("allow")
        if not isinstance(allow, list) or not allow or len(allow) > 50:
            raise ValueError("allow must list 1-50 entries")
        for e in allow:
            act = e.get("action", "")
            if act in OUTBOUND:
                dest = e.get("destination")
                if not isinstance(dest, str) or not dest or any(ch in dest for ch in "*?["):
                    raise ValueError(f"{act}: name the exact recipient/destination (wildcards let a hijacked agent "
                                     f"send anywhere; AgentDojo worst case: 0.7% -> 29% attack success in banking)")
            if "*" in act or act not in prule.allowed_actions or act not in arule.allowed_actions:
                raise PermissionError(f"{act}: not allowed for both {principal} and {agent} (delegation adds no rights)")
        if not self.devices:
            raise PermissionError("passkey approval is not enabled")
        ok, why = self.devices.verify_for(principal, device_id, proof, manifest_challenge(m))
        if not ok:
            raise PermissionError(f"manifest not approved by {principal}: {why}")
        sid = "sess-" + secrets.token_urlsafe(12)
        t = self.now()
        s = {"id": sid, "manifest": m, "agent": agent, "principal": principal, "started": t, "expires": t + ttl,
             "actions": 0, "records": 0, "strikes": 0, "revoked": None,
             "max_actions": int(m.get("max_actions", 50)), "max_records": int(m.get("max_records", 0))}
        with self._lock:
            self.sessions[sid] = s
        self.audit({"type": "agent_session", "session": sid, "agent": agent, "principal": principal,
                    "task": m.get("task", ""), "allow": allow, "expires": s["expires"]})
        return {"session": sid, "expires": s["expires"]}

    def revoke(self, sid: str, by: str) -> bool:
        with self._lock:
            s = self.sessions.get(sid)
            if s is None or s["revoked"] or by not in (s["principal"], "admin"):
                return False
            s["revoked"] = f"revoked by {by}"
        self.audit({"type": "agent_revoked", "session": sid, "by": by})
        return True

    def session_of(self, a: Action) -> dict | None:
        s = self.sessions.get(a.session or "")
        return s if s is not None and s["agent"] == a.identity else None

    # ------------------------------------------------------------------ every agent action
    @staticmethod
    def _matches(e: dict, a: Action) -> bool:
        if not fnmatchcase(a.action_type, e.get("action", "")):
            return False
        if not fnmatchcase(a.resource, e.get("resource", "*")):
            return False
        if a.destination is not None:
            pat = e.get("destination")
            if pat is None or not fnmatchcase(dest_key(a.destination), pat):
                return False
        if "max_count" in e and a.count > int(e["max_count"]):
            return False
        return True

    def check(self, a: Action) -> tuple[str | None, list[str]]:
        """('DENY'|'ESCALATE'|None, reasons) for an agent action."""
        with self._lock:
            s = self.session_of(a)
            if s is None:
                return "DENY", ["agent action without an approved session"]
            if s["revoked"]:
                return "DENY", [f"agent session {s['id']} {s['revoked']}"]
            if self.now() > s["expires"]:
                return "DENY", [f"agent session {s['id']} expired"]
            if s["actions"] + 1 > s["max_actions"]:
                return "DENY", [f"agent session used all {s['max_actions']} actions"]
            entry = next((e for e in s["manifest"]["allow"] if self._matches(e, a)), None)
            if entry is None:
                s["strikes"] += 1
                why = [f"outside the task {s['principal']} approved for {a.identity}"]
                if s["strikes"] >= STRIKES:
                    s["revoked"] = f"revoked after {s['strikes']} out-of-task attempts (possible prompt injection)"
                    self.alert("agent_revoked", identity=a.identity, principal=s["principal"], session=s["id"],
                               detail=s["revoked"])
                    why.append(s["revoked"])
                return "DENY", why
            rec_ids = a.metadata.get("record_ids")
            n_rec = len(rec_ids) if isinstance(rec_ids, list) else a.count
            if a.action_type in ("data.read", "data.export", "secret.read") and s["records"] + n_rec > s["max_records"]:
                return "DENY", [f"agent session record limit {s['max_records']} reached"]
            reasons = []
            prov = a.metadata.get("provenance") or {}
            tainted = [k for k, v in prov.items() if v == "untrusted"] if isinstance(prov, dict) else []
            if tainted:
                reasons.append(f"{', '.join(sorted(tainted))} came from untrusted content (possible prompt injection): "
                               f"{s['principal']} must confirm")
            if a.action_type in SENSITIVE and not entry.get("auto"):
                reasons.append(f"sensitive action by an agent: {s['principal']} must confirm")
            return ("ESCALATE" if reasons else None), reasons

    def record(self, a: Action, allowed: bool) -> None:
        with self._lock:
            s = self.session_of(a)
            if s is None or not allowed:
                return
            s["actions"] += 1
            if a.action_type in ("data.read", "data.export", "secret.read"):
                rec_ids = a.metadata.get("record_ids")
                s["records"] += len(rec_ids) if isinstance(rec_ids, list) else a.count

    def constraints(self, a: Action) -> dict:
        s = self.session_of(a)
        return {"sess": s["id"], "sess_max": s["max_records"]} if s else {}

    def principal_of(self, a_identity: str, session: str | None) -> str | None:
        s = self.sessions.get(session or "")
        return s["principal"] if s and s["agent"] == a_identity else None

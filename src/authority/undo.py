"""Undo windows: nothing irreversible happens the moment it is asked for.

Ransomware, wipers and fraud all end with an action that cannot be taken back: backups deleted,
storage purged, keys destroyed, money sent, a mass e-mail, DNS pointed elsewhere, an admin role
handed out. The undo gate sits in front of the system that performs these (payments, mail,
DNS, storage, KMS, identity provider) and holds each one for a delay set by policy. During the
delay the requester, any approver or the security team can cancel it; two approvers (never the
requester) can release it early; a "panic" call cancels everything queued, for one identity or for
the whole company. One identity queueing many irreversible actions in a short time (the shape of a
ransomware or wiper run) is stopped automatically: all its queued actions are cancelled and it can
queue nothing more until unfrozen.

The gate trusts the authority only through its public key (like the change gates), keeps its own
append-only journal (fsynced) and restores from it at start, so a restart never executes, loses or
repeats anything.

  submit(grant, action)        -> queued (with execute_after) | executes now (below threshold) | refused
  cancel(pid, by)              -> requester, approvers or security may cancel; cancelling is always safe
  expedite(pid, sigs)          -> k approver signatures over b"mastyf-undo|<pid>|<fingerprint>"
  panic(by, identity=None)     -> cancel everything queued (for one identity, or all)
  due() / execute(pid)         -> the executor performs each due action exactly once
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from .actions import Action
from .crypto import b64d, verify
from .grants import GrantError, GrantVerifier

HOUR = 3600


def undo_message(pid: str, fingerprint: str) -> bytes:
    return f"mastyf-undo|{pid}|{fingerprint}".encode()


@dataclass
class UndoRule:
    action: str  # action type pattern
    delay_seconds: int
    resource: str = "*"
    min_count: int = 0  # below this the action executes immediately (e.g. small payments)


@dataclass
class UndoPolicy:
    rules: list[UndoRule]
    signatures: int = 2
    burst_per_hour: int = 5  # irreversible actions one identity may queue per hour
    security: list[str] = field(default_factory=list)  # identities who may cancel and panic

    @classmethod
    def from_dict(cls, d: dict) -> "UndoPolicy":
        return cls([UndoRule(r["action"], int(r["delay_seconds"]), r.get("resource", "*"), int(r.get("min_count", 0)))
                    for r in d.get("rules", [])], int(d.get("signatures", 2)), int(d.get("burst_per_hour", 5)),
                   list(d.get("security", [])))

    def rule_for(self, a: Action) -> UndoRule | None:
        for r in self.rules:
            if fnmatchcase(a.action_type, r.action) and fnmatchcase(a.resource, r.resource):
                return r
        return None


@dataclass
class UndoResult:
    ok: bool  # True: the caller may perform it now
    reason: str
    pending_id: str | None = None
    execute_after: float | None = None


class UndoGate:
    def __init__(self, policy: UndoPolicy, authority_public_key, approver_keys: dict, journal_path=None,
                 alert=None, now=time.time):
        self.p = policy
        self.verifier = GrantVerifier(authority_public_key, now=now)
        self.approver_keys = approver_keys
        self.alert = alert or (lambda *a, **k: None)
        self.now = now
        self.pending: dict[str, dict] = {}
        self.recent: dict[str, deque] = defaultdict(deque)
        self.frozen: dict[str, str] = {}
        self._lock = threading.Lock()
        self.journal_path = journal_path
        if journal_path and os.path.exists(journal_path):
            self._restore()

    # ------------------------------------------------------------------ journal
    def _j(self, ev: dict) -> None:
        if not self.journal_path:
            return
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(ev, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())  # durable before the caller is told anything

    def _restore(self) -> None:
        with open(self.journal_path) as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue  # torn last line after a crash
                k, pid = ev.get("e"), ev.get("pid")
                if k == "queued":
                    self.pending[pid] = ev["entry"]
                elif k in ("cancelled", "executed", "expedited") and pid in self.pending:
                    if k == "expedited":
                        self.pending[pid]["execute_after"] = ev["at"]
                    else:
                        self.pending[pid]["state"] = k
                elif k == "freeze":
                    self.frozen[ev["identity"]] = ev["why"]
                elif k == "unfreeze":
                    self.frozen.pop(ev["identity"], None)

    # ------------------------------------------------------------------ entry points
    def submit(self, grant: str, a: Action) -> UndoResult:
        with self._lock:
            try:
                payload = self.verifier.verify(grant, a)
            except GrantError as e:
                return UndoResult(False, f"grant rejected: {e}")
            if a.identity in self.frozen:
                return UndoResult(False, f"identity frozen: {self.frozen[a.identity]}")
            rule = self.p.rule_for(a)
            if rule is None:
                return UndoResult(False, f"{a.action_type} on {a.resource}: no undo rule (fail closed)")
            if a.count < rule.min_count:
                return UndoResult(True, f"below {rule.min_count}: executes now")
            t = self.now()
            dq = self.recent[a.identity]
            while dq and dq[0] <= t - HOUR:
                dq.popleft()
            if len(dq) + 1 > self.p.burst_per_hour:
                n = self._cancel_where(lambda e: e["requester"] == a.identity, "burst")
                why = f"{len(dq) + 1} irreversible actions in one hour (ransomware/wiper pattern)"
                self.frozen[a.identity] = why
                self._j({"e": "freeze", "identity": a.identity, "why": why})
                self.alert("undo_burst", identity=a.identity, cancelled=n, detail=why)
                return UndoResult(False, f"refused and frozen: {why}; {n} queued actions cancelled")
            dq.append(t)
            pid = payload["gid"]
            entry = {"action": a.to_dict(), "fingerprint": a.fingerprint(), "requester": a.identity,
                     "queued_at": t, "execute_after": t + rule.delay_seconds, "state": "pending"}
            self.pending[pid] = entry
            self._j({"e": "queued", "pid": pid, "entry": entry})
            self.alert("undo_queued", identity=a.identity, pid=pid, action=a.action_type, resource=a.resource,
                       execute_after=entry["execute_after"])
            return UndoResult(False, f"queued: executes after {rule.delay_seconds / HOUR:g} h unless cancelled",
                              pid, entry["execute_after"])

    def _cancel_where(self, pred, by: str) -> int:
        n = 0
        for pid, e in self.pending.items():
            if e["state"] == "pending" and pred(e):
                e["state"] = "cancelled"
                self._j({"e": "cancelled", "pid": pid, "by": by})
                n += 1
        return n

    def cancel(self, pid: str, by: str) -> bool:
        with self._lock:
            e = self.pending.get(pid)
            if e is None or e["state"] != "pending":
                return False
            if by != e["requester"] and by not in self.approver_keys and by not in self.p.security:
                return False
            e["state"] = "cancelled"
            self._j({"e": "cancelled", "pid": pid, "by": by})
            self.alert("undo_cancelled", pid=pid, by=by)
            return True

    def expedite(self, pid: str, sigs: list[dict]) -> bool:
        with self._lock:
            e = self.pending.get(pid)
            if e is None or e["state"] != "pending":
                return False
            msg = undo_message(pid, e["fingerprint"])
            ok = set()
            for s in sigs or []:
                name = s.get("approver")
                pk = self.approver_keys.get(name)
                try:
                    if pk is not None and name != e["requester"] and verify(pk, b64d(s.get("sig", "")), msg):
                        ok.add(name)
                except Exception:  # noqa: BLE001
                    pass
            if len(ok) < self.p.signatures:
                return False
            e["execute_after"] = self.now()
            self._j({"e": "expedited", "pid": pid, "at": e["execute_after"], "by": sorted(ok)})
            return True

    def panic(self, by: str, identity: str | None = None) -> int:
        """Cancel everything queued (one identity, or all). Security team and approvers only."""
        with self._lock:
            if by not in self.p.security and by not in self.approver_keys:
                return 0
            n = self._cancel_where(lambda e: identity is None or e["requester"] == identity, f"panic:{by}")
            if identity:
                self.frozen[identity] = f"panic by {by}"
                self._j({"e": "freeze", "identity": identity, "why": f"panic by {by}"})
            self.alert("undo_panic", by=by, identity=identity, cancelled=n)
            return n

    def unfreeze(self, identity: str, sigs: list[dict]) -> bool:
        msg = f"mastyf-unfreeze|{identity}|undo".encode()
        ok = {s.get("approver") for s in sigs or [] if s.get("approver") in self.approver_keys and s.get("approver") != identity
              and verify(self.approver_keys[s["approver"]], b64d(s.get("sig", "")), msg)}
        if len(ok) < self.p.signatures:
            return False
        with self._lock:
            self.frozen.pop(identity, None)
            self.recent.pop(identity, None)
            self._j({"e": "unfreeze", "identity": identity, "by": sorted(ok)})
        return True

    def due(self) -> list[str]:
        t = self.now()
        return [pid for pid, e in self.pending.items() if e["state"] == "pending" and e["execute_after"] <= t]

    def execute(self, pid: str) -> dict | None:
        """Mark a due action executed (exactly once) and return it for the executor to perform."""
        with self._lock:
            e = self.pending.get(pid)
            if e is None or e["state"] != "pending" or e["execute_after"] > self.now():
                return None
            if e["requester"] in self.frozen:
                return None
            e["state"] = "executed"
            self._j({"e": "executed", "pid": pid})
            return e["action"]

"""Change gates: bounded damage at the place where the change actually happens.

Budgets (budgets.py) bound how much data can be *read*. Gates bound how much can be
*changed or destroyed*. Each gate runs next to its resource (CDN, Git host, backup store,
storage service), trusts the authority only through its public key, and enforces its own
rules even if the authority is compromised:

  artifact.publish       the gate re-runs the script-integrity check itself against the live
                         version; "block" is refused, "review" needs k approver signatures
  repo.history_rewrite   protected branches need k signatures; other branches have a daily
                         budget of rewritten commits per identity
  backup.delete          never immediate: queued behind a time lock (default 72 h) and needs
                         k signatures; any approver can cancel during the lock
  file.write_bulk        daily budget of files written per identity per target; storage keeps
                         prior versions so writes cannot destroy them (assumed property of the
                         store, not enforced here)

Signatures are Ed25519 over b"mastyf-gate|<grant id>|<action fingerprint>" by approvers other
than the requester.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from . import script_integrity
from .actions import Action
from .binding import approver_signed
from .crypto import b64d, verify
from .features import DAY
from .grants import GrantError, GrantVerifier
from .policy import matches

GATED = frozenset({"artifact.publish", "repo.history_rewrite", "backup.delete", "file.write_bulk"})


def gate_message(grant_id: str, fingerprint: str) -> bytes:
    return f"mastyf-gate|{grant_id}|{fingerprint}".encode()


@dataclass
class GatePolicy:
    signatures: int = 2
    protected_branches: list[str] = field(default_factory=lambda: ["main", "master", "release/*"])
    rewrite_budget: dict[str, int] = field(default_factory=dict)  # identity -> commits / 24 h
    write_budget: dict[str, dict[str, int]] = field(default_factory=dict)  # identity -> target pattern -> files / 24 h
    delete_lock_seconds: int = 72 * 3600
    publish_allowed_hosts: list[str] = field(default_factory=list)
    # identities (patterns) whose publishes need a WebAuthn assertion from a registered device
    device_bound: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "GatePolicy":
        return cls(
            signatures=int(d.get("signatures", 2)),
            protected_branches=d.get("protected_branches", ["main", "master", "release/*"]),
            rewrite_budget={k: int(v) for k, v in d.get("rewrite_budget", {}).items()},
            write_budget=d.get("write_budget", {}),
            delete_lock_seconds=int(d.get("delete_lock_seconds", 72 * 3600)),
            publish_allowed_hosts=d.get("publish_allowed_hosts", []),
            device_bound=d.get("device_bound", []),
        )


@dataclass
class GateResult:
    ok: bool
    reason: str
    pending_id: str | None = None  # set when a change is queued behind a time lock


class ChangeGate:
    def __init__(self, policy: GatePolicy, authority_public_key, approver_keys: dict, now=time.time, verifier=None,
                 devices=None, campaign=None, approver_devices=None):
        self.p = policy
        self.approver_devices = approver_devices  # binding.DeviceRegistry of approvers' passkeys
        self.devices = devices  # binding.DeviceRegistry: impersonated sessions have no device key
        self.campaign = campaign  # script_firewall.CampaignDetector: same new code across many tenants
        self.verifier = verifier or GrantVerifier(authority_public_key, now=now)
        self.approver_keys = approver_keys
        self.now = now
        self.live: dict[str, str] = {}  # artifact resource -> live source
        self.pending: dict[str, dict] = {}  # time-locked changes
        self.ledger: dict[tuple, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    # ---- helpers ----------------------------------------------------------
    def _signers(self, gid: str, a: Action, sigs: list[dict] | None) -> set[str]:
        ok = set()
        msg = gate_message(gid, a.fingerprint())
        for s in sigs or []:
            name = approver_signed(self.approver_keys, self.approver_devices, s, msg)
            if name is not None and name != a.identity:
                ok.add(name)
        return ok

    def _used(self, key: tuple, ts: float) -> int:
        dq = self.ledger[key]
        while dq and dq[0][0] <= ts - DAY:
            dq.popleft()
        return sum(n for _, n in dq)

    @staticmethod
    def _branch(resource: str) -> str:
        parts = resource.partition("://")[2].split("/")
        return "/".join(parts[2:]) if len(parts) > 2 else ""

    # ---- entry point ------------------------------------------------------
    def apply(self, grant: str, a: Action, sigs: list[dict] | None = None, content: str | None = None) -> GateResult:
        if a.action_type not in GATED:
            return GateResult(False, f"{a.action_type} is not handled by this gate")
        with self._lock:
            try:
                payload = self.verifier.verify(grant, a)
            except GrantError as e:
                return GateResult(False, f"grant rejected: {e}")
            if self.devices is not None and matches(a.identity, self.p.device_bound):
                kex, why = self.devices.check(a.identity, a.metadata.get("device_id"), a.metadata.get("device_proof"),
                                              payload["gid"], a.fingerprint())
                if kex is None:
                    return GateResult(False, f"device: {why}")
            signers = self._signers(payload["gid"], a, sigs)
            quorum = len(signers) >= self.p.signatures
            t = self.now()  # never the caller-supplied timestamp

            if a.action_type == "artifact.publish":
                if content is None:
                    return GateResult(False, "no artifact content: the gate checks content itself")
                rep = script_integrity.check(self.live.get(a.resource), content, self.p.publish_allowed_hosts)
                if rep["candidate_sha256"] != a.metadata.get("candidate_sha256"):
                    return GateResult(False, "content does not match the granted artifact hash")
                if rep["verdict"] == "block":
                    return GateResult(False, "integrity block at the gate: "
                                      + ", ".join(f["code"] for f in rep["findings"]))
                if self.campaign is not None:
                    ok_c, hits = self.campaign.observe(a.resource, self.live.get(a.resource), content)
                    if not ok_c:
                        return GateResult(False, "campaign: same new code across many customers' projects: "
                                          + ", ".join(hits))
                if rep["verdict"] == "review" and not quorum:
                    return GateResult(False, f"integrity review needs {self.p.signatures} approver signatures")
                self.live[a.resource] = content
                return GateResult(True, f"published ({rep['verdict']})")

            if a.action_type == "repo.history_rewrite":
                if matches(self._branch(a.resource), self.p.protected_branches):
                    if not quorum:
                        return GateResult(False, f"protected branch: needs {self.p.signatures} approver signatures")
                    return GateResult(True, "protected rewrite approved by quorum")
                key = ("rewrite", a.identity)
                cap = self.p.rewrite_budget.get(a.identity, 0)
                if not quorum and self._used(key, t) + a.count > cap:
                    return GateResult(False, f"rewrite budget: {a.count} commits over {cap}/24h for {a.identity}")
                self.ledger[key].append((t, a.count))
                return GateResult(True, "rewrite within budget" if not quorum else "rewrite approved by quorum")

            if a.action_type == "file.write_bulk":
                caps = self.p.write_budget.get(a.identity, {})
                target = a.destination or a.resource
                cap_key, cap = next(((k, v) for k, v in caps.items() if fnmatchcase(target, k)), (target, 0))
                key = ("write", a.identity, cap_key)
                if not quorum and self._used(key, t) + a.count > cap:
                    return GateResult(False, f"write budget: {a.count} files to {target} over {cap}/24h")
                self.ledger[key].append((t, a.count))
                return GateResult(True, "write within budget" if not quorum else "write approved by quorum")

            # backup.delete: always time-locked; quorum is required to queue it
            if not quorum:
                return GateResult(False, f"backup deletion needs {self.p.signatures} approver signatures")
            pid = payload["gid"]
            self.pending[pid] = {"action": a.to_dict(), "execute_after": t + self.p.delete_lock_seconds,
                                 "cancelled": False, "signers": sorted(signers)}
            return GateResult(False, f"queued: executes after {self.p.delete_lock_seconds // 3600} h unless cancelled",
                              pending_id=pid)

    def cancel(self, pending_id: str, approver: str) -> bool:
        if approver not in self.approver_keys or pending_id not in self.pending:
            return False
        self.pending[pending_id]["cancelled"] = True
        return True

    def due(self, ts: float) -> list[dict]:
        """Time-locked changes that may now execute (not cancelled, lock expired)."""
        return [p for p in self.pending.values() if not p["cancelled"] and p["execute_after"] <= ts]


def dumps(p: GatePolicy) -> str:
    return json.dumps(p.__dict__, indent=2)

"""The unit the authority decides on: one proposed action by one identity."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

ACTION_TYPES = (
    "auth.login",
    "data.read",
    "data.export",
    "secret.read",
    "artifact.publish",
    "repo.push",
    "repo.history_rewrite",
    "process.exec",
    "network.egress",
    "file.write_bulk",
    "backup.delete",
    # irreversible actions handled by undo windows (undo.py)
    "payment.send",
    "email.bulk_send",
    "dns.change",
    "key.delete",
    "storage.delete",
    "account.delete",
    "permission.grant",
    # AI agent session start (agents.py)
    "agent.session",
    # weakening a security control: logging, MFA, identity providers, guardrails, branch protection (always asks)
    "security.control_change",
)

# The risk model's one-hot features cover these (fixed, so adding action types never invalidates a
# trained model; newer types score through the novelty scorer and policy instead).
MODEL_TYPES = ACTION_TYPES[:11]

# Actions whose impact is large enough that they always pass through the full pipeline.
SENSITIVE = frozenset(
    {
        "data.export",
        "secret.read",
        "artifact.publish",
        "repo.history_rewrite",
        "backup.delete",
        "file.write_bulk",
        "payment.send",
        "email.bulk_send",
        "dns.change",
        "key.delete",
        "storage.delete",
        "account.delete",
        "permission.grant",
        "security.control_change",
    }
)

MAX_STR = 1024
MAX_COUNT = 10**12


class ActionError(ValueError):
    """Malformed action. The authority treats this as a deny (fail closed)."""


def _str(d: dict, key: str, required: bool = True) -> str | None:
    v = d.get(key)
    if v is None:
        if required:
            raise ActionError(f"missing field: {key}")
        return None
    if not isinstance(v, str) or not v or len(v) > MAX_STR:
        raise ActionError(f"field {key} must be a non-empty string of at most {MAX_STR} chars")
    return v


@dataclass(frozen=True)
class Action:
    identity: str
    action_type: str
    resource: str
    count: int = 1  # rows, keys, files, commits: the volume of the action
    destination: str | None = None
    ts: float = field(default_factory=time.time)
    session: str | None = None
    metadata: dict = field(default_factory=dict, compare=False, hash=False)

    def __post_init__(self) -> None:
        if self.action_type not in ACTION_TYPES:
            raise ActionError(f"unknown action_type: {self.action_type!r}")
        if isinstance(self.count, bool) or not isinstance(self.count, int):
            raise ActionError("count must be an integer")
        if not 0 <= self.count <= MAX_COUNT:
            raise ActionError("count out of range")

    @classmethod
    def from_dict(cls, d: dict) -> "Action":
        if not isinstance(d, dict):
            raise ActionError("action must be an object")
        count = d.get("count", 1)
        ts = d.get("ts", time.time())
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            raise ActionError("ts must be a number")
        meta = d.get("metadata", {}) or {}
        if not isinstance(meta, dict):
            raise ActionError("metadata must be an object")
        return cls(
            identity=_str(d, "identity"),
            action_type=_str(d, "action_type"),
            resource=_str(d, "resource"),
            count=count,
            destination=_str(d, "destination", required=False),
            ts=float(ts),
            session=_str(d, "session", required=False),
            metadata=meta,
        )

    def to_dict(self) -> dict:
        return {
            "identity": self.identity,
            "action_type": self.action_type,
            "resource": self.resource,
            "count": self.count,
            "destination": self.destination,
            "ts": self.ts,
            "session": self.session,
            "metadata": self.metadata,
        }

    def fingerprint(self) -> str:
        """Stable id of *what* is being done (not when). Grants and approvals bind to it."""
        core = {
            "identity": self.identity,
            "action_type": self.action_type,
            "resource": self.resource,
            "count": self.count,
            "destination": self.destination,
            "artifact": self.metadata.get("candidate_sha256"),
        }
        blob = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()

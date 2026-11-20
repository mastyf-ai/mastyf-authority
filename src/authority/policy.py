"""Deterministic policy: who may do what, volume limits, destinations, canaries."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path


def matches(value: str | None, patterns: list[str]) -> bool:
    return value is not None and any(fnmatchcase(value, p) for p in patterns)


@dataclass
class IdentityRule:
    kind: str  # "human" | "service"
    allowed_actions: list[str]
    public_facing: bool = False
    approver: bool = False


@dataclass
class Policy:
    version: str
    identities: dict[str, IdentityRule]
    thresholds: dict[str, dict]
    always_escalate: list[str]
    destinations_allow: list[str]
    destinations_deny: list[str]
    protected_branches: list[str]
    canary_resources: list[str]
    canary_values: list[str]
    escalate_at: float = 0.5
    deny_at: float = 0.9
    grant_ttl_seconds: int = 60
    approval_ttl_seconds: int = 900
    auto_freeze_denials_per_hour: int = 3
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: dict, directory: dict | None = None) -> "Policy":
        if "teams" in d:  # set limits per team; compiled to the per-identity form (teams.py)
            from .teams import expand
            d = expand(d, directory)
        ids = {
            k: IdentityRule(
                kind=v["kind"],
                allowed_actions=list(v["allowed_actions"]),
                public_facing=bool(v.get("public_facing", False)),
                approver=bool(v.get("approver", False)),
            )
            for k, v in d["identities"].items()
        }
        model = d.get("model", {})
        canaries = d.get("canaries", {})
        dest = d.get("destinations", {})
        p = cls(
            version=d["version"],
            identities=ids,
            thresholds=d.get("thresholds", {}),
            always_escalate=d.get("always_escalate", []),
            destinations_allow=dest.get("allow", []),
            destinations_deny=dest.get("deny", []),
            protected_branches=d.get("protected_branches", []),
            canary_resources=canaries.get("resources", []),
            canary_values=canaries.get("values", []),
            escalate_at=float(model.get("escalate_at", 0.5)),
            deny_at=float(model.get("deny_at", 0.9)),
            grant_ttl_seconds=int(d.get("grant_ttl_seconds", 60)),
            approval_ttl_seconds=int(d.get("approval_ttl_seconds", 900)),
            auto_freeze_denials_per_hour=int(d.get("auto_freeze_denials_per_hour", 3)),
            raw=d,
        )
        if not 0 < p.escalate_at <= p.deny_at <= 1:
            raise ValueError("need 0 < escalate_at <= deny_at <= 1")
        return p

    @classmethod
    def load(cls, path: str | Path, directory: dict | None = None) -> "Policy":
        return cls.from_dict(json.loads(Path(path).read_text()), directory)

    def identity_meta(self) -> dict[str, dict]:
        return {k: {"kind": v.kind, "public_facing": v.public_facing} for k, v in self.identities.items()}

    def is_canary(self, resource: str, metadata: dict) -> bool:
        if matches(resource, self.canary_resources):
            return True
        if self.canary_values:
            blob = json.dumps(metadata, default=str)
            return any(v in blob for v in self.canary_values)
        return False

    def is_protected_branch(self, resource: str) -> bool:
        # resource form: github://org/repo/<branch...>
        _, _, rest = resource.partition("://")
        parts = rest.split("/")
        branch = "/".join(parts[2:]) if len(parts) > 2 else ""
        return matches(branch, self.protected_branches)

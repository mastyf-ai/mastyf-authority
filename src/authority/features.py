"""Behavioural features: how unusual is this action for this identity, given its history
and what it has been doing in the last 24 hours.

The same FeatureState is used to build training data and at decision time, so the
model sees identical feature definitions in both places.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque

from .actions import MODEL_TYPES, SENSITIVE, Action

DAY = 86400.0
HOUR = 3600.0
WINDOW = DAY
NEW_WINDOW = 3 * DAY  # something first seen in the last 3 days still counts as new
MIN_PROFILE_EVENTS = 20

READ_LIKE = frozenset({"secret.read", "data.export"})
EGRESS_LIKE = frozenset({"network.egress", "data.export"})

FEATURE_NAMES = [
    "log_count",
    "count_z",
    "type_new",
    "resource_new",
    "dest_new",
    "hour_rarity",
    "public_facing",
    "is_service",
    "sensitive",
    "recent_actions_1h",
    "recent_sensitive_volume_24h",
    "recent_distinct_resources_24h",
    "recent_new_resources_24h",
    "recent_new_dest_actions_24h",
    "exfil_chain",
    "identity_age_days",
] + [f"type={t}" for t in MODEL_TYPES]


def prefix(resource: str, depth: int = 3) -> str:
    scheme, sep, rest = resource.partition("://")
    parts = [p for p in rest.split("/") if p]
    return scheme + sep + "/".join(parts[:depth])


def dest_key(dest: str) -> str:
    scheme, sep, rest = dest.partition("://")
    if not sep:
        return dest.lower()
    host = rest.split("/", 1)[0].lower()
    return host if scheme in ("http", "https") else f"{scheme}://{host}"


def hour_of(ts: float) -> int:
    return int((ts % DAY) // HOUR)


class Profile:
    __slots__ = ("n", "first_ts", "logc", "prefix_seen", "dest_seen", "type_seen", "hours")

    def __init__(self, first_ts: float):
        self.n = 0
        self.first_ts = first_ts
        self.logc: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.prefix_seen: dict[str, float] = {}
        self.dest_seen: dict[str, float] = {}
        self.type_seen: dict[str, float] = {}
        self.hours = [0] * 24

    def update(self, a: Action) -> None:
        self.n += 1
        self.logc[a.action_type].append(math.log1p(a.count))
        self.prefix_seen.setdefault(prefix(a.resource), a.ts)
        if a.destination:
            self.dest_seen.setdefault(dest_key(a.destination), a.ts)
        self.type_seen.setdefault(a.action_type, a.ts)
        self.hours[hour_of(a.ts)] += 1

    def mature(self, ts: float) -> bool:
        return self.n >= MIN_PROFILE_EVENTS and ts - self.first_ts >= 7 * DAY

    def is_new(self, seen: dict[str, float], key: str, ts: float) -> bool:
        first = seen.get(key)
        if first is None:
            return True
        return self.mature(ts) and ts - first < NEW_WINDOW and first - self.first_ts > NEW_WINDOW


class FeatureState:
    def __init__(self, identity_meta: dict[str, dict]):
        self.meta = identity_meta
        self.profiles: dict[str, Profile] = {}
        self.recent: dict[str, deque[Action]] = defaultdict(deque)

    def _trim(self, identity: str, ts: float) -> deque[Action]:
        dq = self.recent[identity]
        while dq and dq[0].ts < ts - WINDOW:
            dq.popleft()
        return dq

    def features(self, a: Action) -> list[float]:
        p = self.profiles.get(a.identity)
        meta = self.meta.get(a.identity, {})
        lc = math.log1p(a.count)

        if p is None:
            count_z, type_new, res_new, dest_new, rarity, age = 4.0, 1.0, 1.0, float(bool(a.destination)), 0.5, 0.0
        else:
            hist = p.logc.get(a.action_type)
            if hist and len(hist) >= 3:
                mean = sum(hist) / len(hist)
                std = math.sqrt(sum((x - mean) ** 2 for x in hist) / len(hist))
                count_z = max(-5.0, min(10.0, (lc - mean) / (std + 0.5)))
            else:
                count_z = 3.0
            type_new = float(p.is_new(p.type_seen, a.action_type, a.ts))
            res_new = float(p.is_new(p.prefix_seen, prefix(a.resource), a.ts))
            dest_new = float(bool(a.destination) and p.is_new(p.dest_seen, dest_key(a.destination), a.ts))
            if p.n >= MIN_PROFILE_EVENTS:
                rarity = 1.0 - p.hours[hour_of(a.ts)] / max(p.hours)
            else:
                rarity = 0.5
            age = math.log1p(max(0.0, a.ts - p.first_ts) / DAY)

        rec = self._trim(a.identity, a.ts)
        r1h = sum(1 for x in rec if x.ts >= a.ts - HOUR)
        sens_vol = sum(x.count for x in rec if x.action_type in SENSITIVE)
        prefixes = {prefix(x.resource) for x in rec}
        if p is None:
            new_prefixes = len(prefixes)
            new_dest_actions = sum(1 for x in rec if x.destination)
        else:
            new_prefixes = sum(1 for pr in prefixes if p.is_new(p.prefix_seen, pr, a.ts))
            new_dest_actions = sum(
                1 for x in rec if x.destination and p.is_new(p.dest_seen, dest_key(x.destination), a.ts)
            )
        exfil_chain = float(
            a.action_type in EGRESS_LIKE
            and dest_new > 0
            and any(x.action_type in READ_LIKE for x in rec)
        )

        f = [
            lc,
            count_z,
            type_new,
            res_new,
            dest_new,
            rarity,
            float(meta.get("public_facing", False)),
            float(meta.get("kind") == "service"),
            float(a.action_type in SENSITIVE),
            math.log1p(r1h),
            math.log1p(sens_vol),
            math.log1p(len(prefixes)),
            math.log1p(new_prefixes),
            math.log1p(new_dest_actions),
            exfil_chain,
            age,
        ]
        f.extend(1.0 if a.action_type == t else 0.0 for t in MODEL_TYPES)
        return f

    def observe(self, a: Action, learn: bool = True) -> None:
        """Record an attempted action. `learn` updates the baseline profile; the authority
        only learns from allowed actions so an attacker cannot teach it that attacks are normal."""
        self._trim(a.identity, a.ts).append(a)
        if learn:
            p = self.profiles.get(a.identity)
            if p is None:
                p = self.profiles[a.identity] = Profile(a.ts)
            p.update(a)

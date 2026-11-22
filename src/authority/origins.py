"""Where a call comes from: each identity's known networks.

The most common cloud breach is a stolen key used from the thief's own machine. On real CloudTrail
(flaws.cloud: leaked keys used by thousands of strangers) the behavioural layers caught only 15 of
120 replayed stolen-key sessions, because the attackers mostly made ordinary read calls - the one
thing that was always different was the network they came from.

So every identity keeps the networks it has called from (IPv4 /24, IPv6 /48; AWS-internal callers by
service name). A call from a network the identity has never used:

  stable identity  (at most STABLE networks in its history: services, audit roles, CI, most admins)
                   asks once, for any action
  roaming identity (more networks: people on laptops and phones)
                   asks only for sensitive actions

Identities in the policy's origins.strict list (root accounts, break-glass admins) always ask on a new
network. Ask once: approving the call adds that network for that identity. The caller supplies the address in
metadata.origin_ip (the gate in front of the resource, which sees the connection) or metadata.ip
(connectors). Identities without enough history are not judged (warm-up). Only the network prefix is
kept and audited, never the full address. Calls made by the cloud provider's own services ("svc:") are not
judged: an outsider cannot choose them.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict

MIN_HISTORY = 30  # calls with a known origin before an identity is judged
STABLE = 16  # an identity that used at most this many networks is "stable"
KEEP = 256  # networks kept per identity (least recently used dropped first)


def origin_key(meta: dict | None) -> str | None:
    if not meta:
        return None
    ip = meta.get("origin_ip") or meta.get("ip")
    if not isinstance(ip, str) or not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        name = ip.strip().lower()[:80]
        return f"svc:{name}" if name else None  # "ec2.amazonaws.com", "AWS Internal"
    if addr.version == 4:
        return "net:" + ".".join(str(addr).split(".")[:3])
    return "net6:" + ":".join(addr.exploded.split(":")[:3])


class Origins:
    def __init__(self) -> None:
        self.nets: dict[str, OrderedDict] = {}
        self.calls: dict[str, int] = {}

    def observe(self, identity: str, key: str | None, ts: float) -> None:
        if key is None:
            return
        d = self.nets.get(identity)
        if d is None:
            d = self.nets[identity] = OrderedDict()
        if key in d:
            d.move_to_end(key)
        d[key] = ts
        while len(d) > KEEP:
            d.popitem(last=False)
        self.calls[identity] = self.calls.get(identity, 0) + 1

    def check(self, identity: str, key: str | None, sensitive: bool, strict: bool = False) -> str | None:
        """A reason to ask, or None. `strict` (policy origins.strict: root accounts, break-glass admins):
        judged like a stable identity however many networks it has used."""
        if key is None or key.startswith("svc:") or self.calls.get(identity, 0) < MIN_HISTORY:
            return None
        d = self.nets.get(identity) or {}
        if key in d:
            return None
        if strict or len(d) <= STABLE:
            return f"call from network {key}, never used by {identity} (it uses {len(d)})"
        if sensitive:
            return f"sensitive action from network {key}, new for {identity}"
        return None

    def to_json(self) -> dict:
        return {"nets": {k: list(v.items()) for k, v in self.nets.items()}, "calls": self.calls}

    def load(self, d: dict) -> None:
        self.nets = {k: OrderedDict((n, t) for n, t in v) for k, v in d.get("nets", {}).items()}
        self.calls = dict(d.get("calls", {}))

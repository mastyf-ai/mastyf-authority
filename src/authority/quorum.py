"""t-of-n authority quorum.

Run n independent authority nodes (different machines, ideally different configurations,
models and code). Each decides on its own and, if it allows, signs its own grant. A protected
resource (key service, change gate) accepts an action only with grants from at least t
distinct nodes, all for the same action. A single compromised or buggy node cannot grant.

This is a k-of-n bundle of independent Ed25519 signatures, not threshold cryptography
(e.g. FROST). It is simpler and gives the same "no single node" property; the cost is a
larger token.

The most restrictive budget_factor across the signing nodes is the one applied.
"""

from __future__ import annotations

import json
import time

from .actions import Action
from .crypto import b64d
from .grants import GrantError, GrantVerifier

SEP = "~"


def bundle(tokens: list[str]) -> str:
    return SEP.join(t for t in tokens if t)


class QuorumVerifier:
    """Drop-in replacement for GrantVerifier in KeyService / ChangeGate."""

    def __init__(self, node_keys: dict, threshold: int, now=time.time):
        if not 1 <= threshold <= len(node_keys):
            raise ValueError("need 1 <= threshold <= number of nodes")
        self.t = threshold
        self.nodes = {name: GrantVerifier(pk, now=now) for name, pk in node_keys.items()}

    def verify(self, token_bundle: str, action: Action) -> dict:
        tokens = token_bundle.split(SEP) if token_bundle else []
        if len(tokens) > len(self.nodes):
            raise GrantError("too many grants in bundle")
        accepted: dict[str, dict] = {}
        for tok in tokens:
            for name, v in self.nodes.items():
                if name in accepted:
                    continue
                try:
                    body = json.loads(b64d(tok.split(".")[0]))
                except Exception as e:  # noqa: BLE001
                    raise GrantError("malformed grant") from e
                try:
                    accepted[name] = v.verify(tok, action)
                    break
                except GrantError as e:
                    if "signature" in str(e):
                        continue  # not this node's key: try the next node
                    raise GrantError(f"{name}: {e}") from e
                finally:
                    del body
        if len(accepted) < self.t:
            raise GrantError(f"quorum not met: {len(accepted)} of {self.t} nodes")
        payloads = list(accepted.values())
        factor = min(p.get("con", {}).get("budget_factor", 1.0) for p in payloads)
        merged = dict(payloads[0])
        merged["gid"] = "+".join(sorted(p["gid"] for p in payloads))
        merged["con"] = {**merged.get("con", {}), "budget_factor": factor}
        merged["nodes"] = sorted(accepted)
        return merged

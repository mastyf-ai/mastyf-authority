"""Short-lived, single-use, action-bound grants.

The resource side (credential broker, export service, CDN publisher) runs the
action only when it holds a grant that verifies against the authority's public
key and matches the exact action it is about to run.
"""

from __future__ import annotations

import json
import secrets
import threading
import time

from .actions import Action
from .crypto import Signer, b64d, b64e, verify


class GrantError(Exception):
    pass


class GrantIssuer:
    def __init__(self, signer: Signer, ttl_seconds: int = 60, now=time.time):
        self.signer = signer
        self.ttl = ttl_seconds
        self.now = now
        self.epoch = 0  # raised when a standby engine is promoted (failover); see failover.py

    def issue(self, action: Action, decision_id: str, constraints: dict | None = None) -> str:
        iat = self.now()
        payload = {
            "gid": secrets.token_hex(16),
            "did": decision_id,
            "sub": action.identity,
            "act": action.action_type,
            "res": action.resource,
            "fp": action.fingerprint(),
            "con": constraints or {},
            "iat": iat,
            "exp": iat + self.ttl,
        }
        if self.epoch:
            payload["ep"] = self.epoch
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return b64e(body) + "." + b64e(self.signer.sign(body))


class GrantVerifier:
    """Runs next to the protected resource. Holds only the public key."""

    def __init__(self, public_key, now=time.time):
        self.public_key = public_key
        self.now = now
        self._used: dict[str, float] = {}
        self._lock = threading.Lock()
        self.min_epoch = 0  # grants from a superseded engine (lower epoch) are refused, as in the Rust service

    def verify(self, token: str, action: Action) -> dict:
        try:
            body_s, sig_s = token.split(".")
            body, sig = b64d(body_s), b64d(sig_s)
        except Exception as e:  # noqa: BLE001
            raise GrantError("malformed grant") from e
        if not verify(self.public_key, sig, body):
            raise GrantError("bad signature")
        payload = json.loads(body)
        t = self.now()
        if t > payload["exp"]:
            raise GrantError("grant expired")
        if payload["fp"] != action.fingerprint():
            raise GrantError("grant does not match this action")
        if payload.get("ep", 0) < self.min_epoch:
            raise GrantError(f"grant from a superseded authority engine (epoch {payload.get('ep', 0)} < {self.min_epoch})")
        with self._lock:
            for gid, exp in list(self._used.items()):
                if exp < t:
                    del self._used[gid]
            if payload["gid"] in self._used:
                raise GrantError("grant already used")
            self._used[payload["gid"]] = payload["exp"]
        return payload

"""Make a stolen login useless for reading data.

1. Device binding. Each person registers device keys created in their device's secure hardware
   (Secure Enclave / TPM / passkey): an Ed25519 key to sign requests and an X25519 key to receive
   data keys. Every key release must carry a fresh signature from a registered device over the
   grant id, and record keys are returned *encrypted to that device*. A stolen password, session
   cookie or API token used anywhere else gets nothing it can open.

2. Purpose binding (need-to-know). Records unlock only if they belong to a case currently
   assigned to the requester. Assignments come from a separate case system, signed with its own
   key, never from the requester. A small allowance covers one-off lookups outside cases.

Both are enforced by the key service (`budgets.KeyService`), not by the authority.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import b64d, b64e, verify
from .features import DAY


def device_message(grant_id: str, fingerprint: str) -> bytes:
    return f"mastyf-device|{grant_id}|{fingerprint}".encode()


def challenge(grant_id: str, fingerprint: str) -> bytes:
    """WebAuthn challenge for a key release: binds the passkey assertion to this exact grant."""
    import hashlib
    return hashlib.sha256(device_message(grant_id, fingerprint)).digest()


# ---------------------------------------------------------------- WebAuthn assertion check
ES256, EDDSA = -7, -8  # COSE algorithm ids used by passkeys / security keys


def verify_assertion(public_key, alg: int, authenticator_data: bytes, client_data_json: bytes, signature: bytes,
                     expected_challenge: bytes, rp_id: str, origin: str | None = None) -> tuple[bool, bool, int, str]:
    """Verify a WebAuthn assertion (navigator.credentials.get). Returns (ok, user_verified, sign_count, why).
    Signature is over authenticatorData || SHA-256(clientDataJSON), as in the WebAuthn spec."""
    import hashlib
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        cd = json.loads(client_data_json)
    except ValueError:
        return False, False, 0, "client data not JSON"
    if cd.get("type") != "webauthn.get":
        return False, False, 0, "not an assertion"
    if cd.get("challenge") != b64e(expected_challenge):
        return False, False, 0, "challenge mismatch (assertion is for a different request)"
    if origin is not None and cd.get("origin") != origin:
        return False, False, 0, "origin mismatch"
    if len(authenticator_data) < 37:
        return False, False, 0, "authenticator data too short"
    if authenticator_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        return False, False, 0, "relying party mismatch"
    flags = authenticator_data[32]
    if not flags & 0x01:
        return False, False, 0, "user not present"
    uv = bool(flags & 0x04)
    count = int.from_bytes(authenticator_data[33:37], "big")
    msg = authenticator_data + hashlib.sha256(client_data_json).digest()
    try:
        if alg == ES256:
            public_key.verify(signature, msg, ec.ECDSA(hashes.SHA256()))
        elif alg == EDDSA:
            public_key.verify(signature, msg)
        else:
            return False, False, 0, "unsupported algorithm"
    except InvalidSignature:
        return False, False, 0, "bad signature"
    return True, uv, count, "ok"


def case_message(case_id: str, identity: str, records: list[str], expires: float) -> bytes:
    """Canonical bytes the case system signs. Expiry is whole seconds so every language encodes it
    identically."""
    return json.dumps({"case": case_id, "to": identity, "records": sorted(records), "exp": int(expires)},
                      sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------- device side (runs on the laptop)
class Device:
    """Stand-in for a passkey / security key plus a device encryption key. Produces WebAuthn-format
    assertions (authenticatorData || SHA-256(clientDataJSON)), so real browser/OS passkey output is
    verified by the same code. Private keys never leave it."""

    def __init__(self, alg: int = EDDSA, rp_id: str = "authority.corp.example", counter: bool = True):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.alg = alg
        self.rp_id = rp_id
        self._sign = Ed25519PrivateKey.generate() if alg == EDDSA else ec.generate_private_key(ec.SECP256R1())
        self._kex = X25519PrivateKey.generate()
        self.sign_public = self._sign.public_key()
        self.kex_public = self._kex.public_key()
        self.count = 0
        self.use_counter = counter

    def prove(self, grant_id: str, fingerprint: str, user_verified: bool = True) -> str:
        """Returns a JSON proof {ad, cd, sig} (base64url) for this exact grant."""
        return self.prove_challenge(challenge(grant_id, fingerprint), user_verified)

    def prove_challenge(self, chal: bytes, user_verified: bool = True) -> str:
        """Assertion over any server challenge (approvals, enrolment)."""
        import hashlib
        from cryptography.hazmat.primitives.asymmetric import ec
        if self.use_counter:
            self.count += 1
        flags = 0x01 | (0x04 if user_verified else 0)
        ad = hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + self.count.to_bytes(4, "big")
        cd = json.dumps({"type": "webauthn.get", "challenge": b64e(chal),
                         "origin": f"https://{self.rp_id}"}).encode()
        msg = ad + hashlib.sha256(cd).digest()
        sig = self._sign.sign(msg) if self.alg == EDDSA else self._sign.sign(msg, ec.ECDSA(hashes.SHA256()))
        return json.dumps({"ad": b64e(ad), "cd": b64e(cd), "sig": b64e(sig)})

    def unwrap(self, wrapped: str, record_id: str) -> bytes:
        blob = b64d(wrapped)
        eph = X25519PublicKey.from_public_bytes(blob[:32])
        k = _kdf(self._kex.exchange(eph), record_id)
        return AESGCM(k).decrypt(blob[32:44], blob[44:], record_id.encode())


def _kdf(shared: bytes, record_id: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"mastyf-dek-wrap|" + record_id.encode()).derive(shared)


def wrap_to_device(dek: bytes, device_kex_public: X25519PublicKey, record_id: str) -> str:
    """Encrypt a record key so only the holder of the device's X25519 private key can open it."""
    eph = X25519PrivateKey.generate()
    k = _kdf(eph.exchange(device_kex_public), record_id)
    nonce = os.urandom(12)
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64e(eph_pub + nonce + AESGCM(k).encrypt(nonce, dek, record_id.encode()))


# ---------------------------------------------------------------- server side
@dataclass
class DeviceRegistry:
    """identity -> {device id: (ed25519 public, x25519 public)}. Registration itself should need a
    second factor and an approver; here it is an explicit admin call."""
    devices: dict[str, dict[str, tuple]] = field(default_factory=lambda: defaultdict(dict))
    rp_id: str = "authority.corp.example"
    require_user_verified: bool = True
    counters: dict[tuple[str, str], int] = field(default_factory=dict)
    cloned: set = field(default_factory=set)  # (identity, device) seen with a counter going backwards
    cred_ids: dict = field(default_factory=dict)  # (identity, device) -> WebAuthn credential id
    origin: str | None = None  # expected browser origin (None: not checked, e.g. native apps)

    def register(self, identity: str, device_id: str, sign_public, kex_public, alg: int = EDDSA,
                 cred_id: bytes = b"") -> None:
        self.devices[identity][device_id] = (sign_public, kex_public, alg)
        if cred_id:
            self.cred_ids[(identity, device_id)] = cred_id

    def revoke(self, identity: str, device_id: str) -> bool:
        self.cred_ids.pop((identity, device_id), None)
        return self.devices.get(identity, {}).pop(device_id, None) is not None

    @classmethod
    def from_json(cls, d: dict) -> "DeviceRegistry":
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        reg = cls(rp_id=d["rp_id"], require_user_verified=d.get("require_user_verified", True))
        for ident, devs in d.get("devices", {}).items():
            for did, e in devs.items():
                reg.register(ident, did, load_pem_public_key(e["sign_pem"].encode()),
                             X25519PublicKey.from_public_bytes(b64d(e["kex"])), e["alg"],
                             b64d(e["cred_id"]) if e.get("cred_id") else b"")
        return reg

    def save(self, path) -> None:
        """Atomic write of the registry file the Rust key service watches (--devices)."""
        from pathlib import Path
        path = Path(path)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.export_json(), f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def verify_for(self, identity: str, device_id: str | None, proof: str | None, chal: bytes) -> tuple[bool, str]:
        """A registered, user-verified device of `identity` signed `chal` (clone counter enforced)."""
        if not device_id or not proof:
            return False, "no device proof"
        d = self.devices.get(identity, {}).get(device_id)
        if d is None:
            return False, "unknown device"
        if (identity, device_id) in self.cloned:
            return False, "device key flagged as cloned"
        try:
            p = json.loads(proof)
            ad, cd, sig = b64d(p["ad"]), b64d(p["cd"]), b64d(p["sig"])
        except Exception:  # noqa: BLE001
            return False, "malformed device proof"
        ok, uv, count, why = verify_assertion(d[0], d[2], ad, cd, sig, chal, self.rp_id, self.origin)
        if not ok:
            return False, why
        last = self.counters.get((identity, device_id), 0)
        if (count or last) and count <= last:
            self.cloned.add((identity, device_id))
            return False, "signature counter went backwards: possible cloned device key"
        self.counters[(identity, device_id)] = count
        if self.require_user_verified and not uv:
            return False, "user verification (fingerprint/PIN) required"
        return True, "ok"

    def export_json(self) -> dict:
        """Registry file for the Rust key service (--devices)."""
        out: dict = {}
        for ident, devs in self.devices.items():
            for did, (spk, kpk, alg) in devs.items():
                out.setdefault(ident, {})[did] = {
                    "alg": alg,
                    "sign_pem": spk.public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                    "kex": b64e(kpk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
                }
                if (ident, did) in self.cred_ids:
                    out[ident][did]["cred_id"] = b64e(self.cred_ids[(ident, did)])
        return {"rp_id": self.rp_id, "require_user_verified": self.require_user_verified, "devices": out}

    def check(self, identity: str, device_id: str | None, proof: str | None, grant_id: str, fingerprint: str):
        """Returns (device X25519 key or None, reason)."""
        if not device_id or not proof:
            return None, "no device proof"
        d = self.devices.get(identity, {}).get(device_id)
        if d is None:
            return None, "unknown device"
        if (identity, device_id) in self.cloned:
            return None, "device key flagged as cloned"
        try:
            p = json.loads(proof)
            ad, cd, sig = b64d(p["ad"]), b64d(p["cd"]), b64d(p["sig"])
        except Exception:  # noqa: BLE001
            return None, "malformed device proof"
        ok, uv, count, why = verify_assertion(d[0], d[2], ad, cd, sig, challenge(grant_id, fingerprint), self.rp_id)
        if not ok:
            return None, why
        # any genuine signature advances the counter, even if the request is then refused by policy
        last = self.counters.get((identity, device_id), 0)
        if (count or last) and count <= last:  # WebAuthn clone signal: counter did not increase
            self.cloned.add((identity, device_id))
            return None, "signature counter went backwards: possible cloned device key"
        self.counters[(identity, device_id)] = count
        if self.require_user_verified and not uv:
            return None, "user verification (fingerprint/PIN) required"
        return d[1], "ok"


class CaseRegistry:
    """Active case assignments, signed by the case system's key (not the requester's)."""

    def __init__(self, case_system_public_key, now=time.time, outside_allowance: int = 20):
        self.pk = case_system_public_key
        self.now = now
        self.outside_allowance = outside_allowance  # one-off lookups outside cases, per 24 h
        self.assigned: dict[str, dict[str, tuple[float, set]]] = defaultdict(dict)  # identity -> case -> (exp, records)
        self.outside: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def assign(self, case_id: str, identity: str, records: list[str], expires: float, signature: str) -> bool:
        try:
            ok = verify(self.pk, b64d(signature), case_message(case_id, identity, records, expires))
        except Exception:  # noqa: BLE001
            ok = False
        if ok:
            with self._lock:
                self.assigned[identity][case_id] = (float(int(expires)), set(records))
        return ok

    def allowed(self, identity: str) -> set:
        t = self.now()
        out = set()
        for case, (exp, recs) in list(self.assigned.get(identity, {}).items()):
            if exp <= t:
                del self.assigned[identity][case]
            else:
                out |= recs
        return out

    def check(self, identity: str, record_ids: list[str]) -> tuple[bool, str, int]:
        """All records must be on an active case, except up to `outside_allowance` per 24 h."""
        with self._lock:
            ok_set = self.allowed(identity)
            outside = [r for r in dict.fromkeys(record_ids) if r not in ok_set]
            t = self.now()
            dq = self.outside[identity]
            while dq and dq[0][0] <= t - DAY:
                dq.popleft()
            used = sum(n for _, n in dq)
            if used + len(outside) > self.outside_allowance:
                return False, (f"need-to-know: {len(outside)} records not on your active cases "
                               f"({used} of {self.outside_allowance} outside-case lookups used today)"), 0
            return True, "ok", len(outside)

    def commit_outside(self, identity: str, n: int) -> None:
        if n:
            with self._lock:
                self.outside[identity].append((self.now(), n))

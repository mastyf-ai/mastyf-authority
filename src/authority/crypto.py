"""Ed25519 signing for grants and the audit log."""

from __future__ import annotations

import base64
import functools
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Signer:
    def __init__(self, key: Ed25519PrivateKey):
        self._key = key
        self.public_key: Ed25519PublicKey = key.public_key()

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: str | Path) -> "Signer":
        path = Path(path)
        if path.exists():
            if path.stat().st_mode & 0o077:
                raise PermissionError(f"signing key {path} must not be readable by group/others (chmod 600)")
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("signing key is not Ed25519")
            return cls(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return cls(key)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def public_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()


# Ed25519 weak keys: a public key of small order (the identity point and the torsion points) verifies
# signatures anyone can make (Wycheproof: "identity public key universal forgery"). Libraries may accept
# them; we refuse them everywhere, so a weak key slipped into an approver or device registry is useless.
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _decode(b: bytes):
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    if y >= _P:
        y -= _P  # non-canonical encoding: judged by the point it denotes
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = _P - x
    return x, y


def _double(pt):
    x, y = pt
    xx = 2 * x * y * pow(1 + _D * x * x * y * y, _P - 2, _P) % _P
    yy = (y * y + x * x) * pow(1 - _D * x * x * y * y, _P - 2, _P) % _P
    return xx, yy


_L = 2**252 + 27742317777372353535851937790883648493  # order of the prime-order subgroup


def _add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = _D * x1 * x2 * y1 * y2 % _P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, _P - 2, _P) % _P, (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P)


def _mul(k: int, pt):
    acc, q = (0, 1), pt
    while k:
        if k & 1:
            acc = _add(acc, q)
        q = _double(q)
        k >>= 1
    return acc


@functools.lru_cache(maxsize=65536)
def is_weak_key(raw: bytes) -> bool:
    """True unless the key is a point of the prime-order subgroup, as every honestly generated key is.
    Refuses small-order keys (anyone can sign for them) and mixed-order keys (whether they verify depends
    on the library), plus encodings that are not a curve point at all."""
    pt = _decode(raw)
    return pt is None or pt == (0, 1) or _mul(_L, pt) != (0, 1)


def verify(public_key: Ed25519PublicKey, sig: bytes, data: bytes) -> bool:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if is_weak_key(raw):
        return False
    try:
        public_key.verify(sig, data)
        return True
    except InvalidSignature:
        return False

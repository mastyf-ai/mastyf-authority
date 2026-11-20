"""WebAuthn registration (navigator.credentials.create) parsing and verification, plus the small CBOR
subset it needs. Attestation format "none" is accepted (passkeys usually send it); the security of
enrolment comes from who may enrol (an existing device or two approvers), not from attestation."""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import b64e

ES256, EDDSA = -7, -8


# ---------------------------------------------------------------- CBOR (RFC 8949 subset)
class CBORError(ValueError):
    pass


def cbor_decode(data: bytes, pos: int = 0, depth: int = 0):
    """Returns (value, next position). Integers, byte/text strings, arrays, maps, true/false/null."""
    if depth > 16:
        raise CBORError("nesting too deep")
    if pos >= len(data):
        raise CBORError("truncated")
    ib = data[pos]
    major, info = ib >> 5, ib & 0x1F
    pos += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if pos + n > len(data):
            raise CBORError("truncated")
        arg = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        raise CBORError("indefinite lengths not supported")
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if pos + arg > len(data):
            raise CBORError("truncated")
        raw = data[pos:pos + arg]
        return (raw if major == 2 else raw.decode("utf-8")), pos + arg
    if major == 4:
        if arg > 10_000:
            raise CBORError("array too large")
        out = []
        for _ in range(arg):
            v, pos = cbor_decode(data, pos, depth + 1)
            out.append(v)
        return out, pos
    if major == 5:
        if arg > 10_000:
            raise CBORError("map too large")
        m = {}
        for _ in range(arg):
            k, pos = cbor_decode(data, pos, depth + 1)
            v, pos = cbor_decode(data, pos, depth + 1)
            if isinstance(k, (list, dict)):
                raise CBORError("unhashable map key")
            m[k] = v
        return m, pos
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], pos
    raise CBORError(f"unsupported CBOR item (major {major})")


def cbor_encode(v) -> bytes:
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise CBORError("integer too large")
    if v is False or v is True or v is None:
        return bytes([0xF4 if v is False else 0xF5 if v is True else 0xF6])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor_encode(k) + cbor_encode(x) for k, x in v.items())
    raise CBORError(f"cannot encode {type(v).__name__}")


# ---------------------------------------------------------------- COSE keys
def cose_to_key(cose: dict):
    """COSE_Key -> (alg, public key). EC2/P-256/ES256 and OKP/Ed25519/EdDSA only."""
    kty, alg = cose.get(1), cose.get(3)
    if kty == 2 and alg == ES256 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
            raise ValueError("bad P-256 coordinates")
        return ES256, ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                    ec.SECP256R1()).public_key()
    if kty == 1 and alg == EDDSA and cose.get(-1) == 6:
        x = cose.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise ValueError("bad Ed25519 key")
        return EDDSA, Ed25519PublicKey.from_public_bytes(x)
    raise ValueError("unsupported key type (need ES256 or EdDSA)")


def key_to_cose(alg: int, public_key) -> dict:
    from cryptography.hazmat.primitives import serialization
    if alg == EDDSA:
        return {1: 1, 3: EDDSA, -1: 6, -2: public_key.public_bytes(serialization.Encoding.Raw,
                                                                    serialization.PublicFormat.Raw)}
    n = public_key.public_numbers()
    return {1: 2, 3: ES256, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


# ---------------------------------------------------------------- registration
def verify_registration(attestation_object: bytes, client_data_json: bytes, expected_challenge: bytes, rp_id: str,
                        origin: str | None, require_uv: bool = True) -> dict:
    """Checks a navigator.credentials.create() result. Returns {alg, public_key, cred_id, sign_count}.
    Raises ValueError with a plain reason otherwise."""
    try:
        cd = json.loads(client_data_json)
    except ValueError:
        raise ValueError("client data not JSON") from None
    if cd.get("type") != "webauthn.create":
        raise ValueError("not a registration")
    if cd.get("challenge") != b64e(expected_challenge):
        raise ValueError("challenge mismatch")
    if origin is not None and cd.get("origin") != origin:
        raise ValueError("origin mismatch")
    try:
        att, end = cbor_decode(attestation_object)
    except (CBORError, UnicodeDecodeError) as e:
        raise ValueError(f"attestation not CBOR: {e}") from None
    if end != len(attestation_object) or not isinstance(att, dict):
        raise ValueError("malformed attestation object")
    fmt, ad = att.get("fmt"), att.get("authData")
    if fmt not in ("none", "packed", "apple", "tpm", "android-key", "fido-u2f") or not isinstance(ad, bytes):
        raise ValueError("unsupported attestation format")
    if len(ad) < 55:
        raise ValueError("authenticator data too short")
    if ad[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise ValueError("relying party mismatch")
    flags = ad[32]
    if not flags & 0x01:
        raise ValueError("user not present")
    if require_uv and not flags & 0x04:
        raise ValueError("user verification (fingerprint/PIN) required")
    if not flags & 0x40:
        raise ValueError("no credential in registration")
    count = int.from_bytes(ad[33:37], "big")
    n = int.from_bytes(ad[53:55], "big")
    if n == 0 or n > 1023 or 55 + n > len(ad):
        raise ValueError("bad credential id")
    cred_id = ad[55:55 + n]
    try:
        cose, _ = cbor_decode(ad, 55 + n)
    except (CBORError, UnicodeDecodeError) as e:
        raise ValueError(f"bad credential key: {e}") from None
    if not isinstance(cose, dict):
        raise ValueError("bad credential key")
    alg, pk = cose_to_key(cose)
    return {"alg": alg, "public_key": pk, "cred_id": cred_id, "sign_count": count}


def make_registration(sign_private, alg: int, challenge: bytes, rp_id: str, origin: str, cred_id: bytes,
                      user_verified: bool = True) -> tuple[bytes, bytes]:
    """Software authenticator (tests and simulations): what a passkey returns from create()."""
    flags = 0x01 | 0x40 | (0x04 if user_verified else 0)
    ad = (hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big") + bytes(16)
          + len(cred_id).to_bytes(2, "big") + cred_id + cbor_encode(key_to_cose(alg, sign_private.public_key())))
    cd = json.dumps({"type": "webauthn.create", "challenge": b64e(challenge), "origin": origin}).encode()
    return cbor_encode({"fmt": "none", "attStmt": {}, "authData": ad}), cd

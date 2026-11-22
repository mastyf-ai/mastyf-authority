"""Project Wycheproof Ed25519 vectors against the signature check every grant, audit record, snapshot
and approval goes through (authority.crypto.verify): every "invalid" vector must be refused, every
"valid" one accepted. "Acceptable" vectors (weak, small-order public keys) are refused: we never accept
a signature under a key anyone can sign for."""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from authority.crypto import verify

VEC = Path(__file__).parent / "vectors/wycheproof_ed25519_test.json"


def test_wycheproof_ed25519():
    d = json.loads(VEC.read_text())
    bad, n = [], 0
    for g in d["testGroups"]:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(g["publicKey"]["pk"]))
        for t in g["tests"]:
            n += 1
            ok = verify(pk, bytes.fromhex(t["sig"]), bytes.fromhex(t["msg"]))
            if ok != (t["result"] == "valid"):  # "acceptable" must be refused too
                bad.append((t["tcId"], t["comment"], t["result"], ok))
    assert n == d["numberOfTests"] and not bad, bad[:10]

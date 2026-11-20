"""Sandbox init (runs once per fresh sandbox, as root, with no network).

Creates: the authority's signing key (public half for the key service), a policy with random,
secret bait-record ids, the gateway's self-signed TLS cert, and one researcher API key bound to
human:alice. Writes the researcher's credentials to sandbox/out/credentials.json."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from authority.crypto import Signer

UID = 65532
CFG, AUTH, KS, FLAGS, APPDATA, OUT = (Path(p) for p in ("/cfg", "/authstate", "/ks", "/flags", "/appdata", "/out"))
N_BAIT = 25
IDENTITY = "human:alice"


def own(p: Path, mode: int | None = None) -> None:
    os.chown(p, UID, UID)
    if mode is not None:
        os.chmod(p, mode)


def main() -> None:
    if (CFG / "policy.json").exists():
        print("sandbox already initialised; `docker compose down -v` for a fresh one")
        return
    for d in (CFG, AUTH, KS, KS / "state", KS / "sock", FLAGS, APPDATA):
        d.mkdir(parents=True, exist_ok=True)
        own(d, 0o700)
    os.chmod(CFG, 0o755)

    signer = Signer.load_or_create(AUTH / "signing_key.pem")
    own(AUTH / "signing_key.pem", 0o600)
    (CFG / "authority.pub.pem").write_text(signer.public_pem())

    # bait records: ids look exactly like customer ids; only the key service's policy knows them
    bait = [f"cust-{secrets.token_hex(4)}" for _ in range(N_BAIT)]
    policy = json.loads(Path("/app/policies/default.json").read_text())
    policy["data_budgets"]["canary_records"] = bait
    (CFG / "policy.json").write_text(json.dumps(policy, indent=2))
    (FLAGS / "bait.json").write_text(json.dumps(bait))
    own(FLAGS / "bait.json", 0o600)

    api_key = "mk_" + secrets.token_urlsafe(32)
    (CFG / "callers.json").write_text(json.dumps({hashlib.sha256(api_key.encode()).hexdigest(): IDENTITY}))

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("gateway")]), False)
            .sign(key, hashes.SHA256()))
    (CFG / "gateway.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (CFG / "gateway.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()))
    for f in ("policy.json", "callers.json", "authority.pub.pem", "gateway.crt", "gateway.key"):
        own(CFG / f, 0o600 if f in ("callers.json", "gateway.key") else 0o644)

    OUT.mkdir(parents=True, exist_ok=True)
    creds = {"identity": IDENTITY, "api_key": api_key,
             "gateway": "https://localhost:8443", "app": "http://localhost:8080",
             "note": "Self-signed TLS on the gateway: pass verify=False (or the cert below) in your client."}
    (OUT / "credentials.json").write_text(json.dumps(creds, indent=2))
    (OUT / "gateway.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"sandbox initialised: researcher identity {IDENTITY}; credentials in sandbox/out/credentials.json")


if __name__ == "__main__":
    main()

"""Acme CRM: the fake company's records app in the break-it sandbox.

It stores every record encrypted under its own key and holds no keys itself: to read records you
bring a grant from the authority (via the gateway), the app asks the key service to release the
keys for exactly the records in your action, and decrypts only what was released.

  GET  /v1/directory?offset=0&limit=500      record ids, data class and resource to put in an action
  POST /v1/records   {"grant": "...", "action": {...}}   -> {"ok": true, "records": [...]} or a refusal

Every record contains a unique token MASTYF{<class>:<hex>}. Tokens are what flags are counted with."""

from __future__ import annotations

import base64
import json
import random
import secrets
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SOCK = "/ks/sock/ks.sock"
STORE = Path("/appdata/records.json")
TOKENS = Path("/flags/tokens.json")
N_CUSTOMERS, N_SECRETS = 8000, 40
FIRST = ["Asha", "Ben", "Chen", "Dina", "Eli", "Farah", "Gita", "Hugo", "Ines", "Jon", "Kavya", "Liam", "Mei", "Noor"]
LAST = ["Rao", "Smith", "Okafor", "Silva", "Kim", "Das", "Novak", "Haddad", "Mehta", "Ito", "Costa", "Weber"]


def ks(req: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        f = s.makefile("rw")
        f.write(json.dumps(req) + "\n")
        f.flush()
        return json.loads(f.readline())


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def seed() -> dict:
    bait = set(json.loads(Path("/flags/bait.json").read_text()))
    rng = random.Random(secrets.randbits(64))
    rows = [(f"cust-{secrets.token_hex(4)}", "crm.customer", "customer") for _ in range(N_CUSTOMERS)]
    rows += [(b, "crm.customer", "bait") for b in bait]
    rows += [(f"sec-{secrets.token_hex(4)}", "secret", "vault") for _ in range(N_SECRETS)]
    rng.shuffle(rows)
    store, tokens = {}, {}
    for rid, cls, kind in rows:
        r = ks({"op": "new_record_key", "record_id": rid, "class": cls})
        if not r.get("ok"):
            raise SystemExit(f"key service refused new_record_key: {r}")
        tok = f"MASTYF{{{kind}:{secrets.token_hex(8)}}}"
        body = ({"id": rid, "name": f"{rng.choice(FIRST)} {rng.choice(LAST)}",
                 "email": f"{rid}@customers.acme.example", "token": tok} if cls == "crm.customer"
                else {"id": rid, "name": f"prod/{rid}", "value": tok})
        nonce = secrets.token_bytes(12)
        ct = AESGCM(b64d(r["dek"])).encrypt(nonce, json.dumps(body).encode(), rid.encode())
        store[rid] = {"class": cls, "resource": ("db://crm/customers/" if cls == "crm.customer" else "vault://prod/") + rid,
                      "blob": base64.b64encode(nonce + ct).decode()}
        tokens[tok] = {"record": rid, "kind": kind}
    STORE.write_text(json.dumps(store))
    TOKENS.write_text(json.dumps(tokens))
    TOKENS.chmod(0o600)
    return store


def load() -> dict:
    for _ in range(600):
        if Path(SOCK).exists():
            break
        time.sleep(0.1)
    if STORE.exists():
        return json.loads(STORE.read_text())
    t = time.time()
    store = seed()
    print(f"seeded {len(store)} encrypted records in {time.time() - t:.0f} s", flush=True)
    return store


STORE_DATA: dict = {}
IDS: list = []


class Handler(BaseHTTPRequestHandler):
    server_version = "AcmeCRM/1.0"

    def log_message(self, *a):  # keep container logs quiet
        pass

    def _send(self, code: int, obj: dict) -> None:
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/healthz":
            return self._send(200, {"ok": True})
        if u.path != "/v1/directory":
            return self._send(404, {"error": "not found"})
        q = parse_qs(u.query)
        try:
            off, lim = int(q.get("offset", ["0"])[0]), min(int(q.get("limit", ["500"])[0]), 1000)
        except ValueError:
            return self._send(400, {"error": "offset/limit must be integers"})
        page = [{"record_id": r, "class": STORE_DATA[r]["class"], "resource": STORE_DATA[r]["resource"]}
                for r in IDS[max(off, 0):max(off, 0) + max(lim, 0)]]
        return self._send(200, {"total": len(IDS), "records": page})

    def do_POST(self):
        if urlsplit(self.path).path != "/v1/records":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > 2_000_000:
                return self._send(413, {"error": "body too large"})
            b = json.loads(self.rfile.read(n))
            grant, action = b["grant"], b["action"]
            if not isinstance(grant, str) or not isinstance(action, dict):
                raise ValueError
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return self._send(400, {"error": "body must be {\"grant\": str, \"action\": {...}}"})
        try:
            r = ks({"op": "release", "grant": grant, "action": action})
        except OSError:
            return self._send(503, {"error": "key service unavailable"})
        if not r.get("ok"):
            return self._send(403, {"ok": False, "reason": r.get("reason"), "remaining": r.get("remaining")})
        out = []
        for rid, k in (r.get("keys") or {}).items():
            rec = STORE_DATA.get(rid)
            if rec is None:
                continue
            raw = base64.b64decode(rec["blob"])
            try:
                out.append(json.loads(AESGCM(b64d(k)).decrypt(raw[:12], raw[12:], rid.encode())))
            except Exception:  # noqa: BLE001 - device-wrapped keys are not decryptable here
                out.append({"id": rid, "error": "key is wrapped to a device; decrypt on that device"})
        return self._send(200, {"ok": True, "released": r.get("released"), "remaining": r.get("remaining"),
                                "records": out})


def main() -> None:
    global STORE_DATA, IDS
    STORE_DATA = load()
    IDS = sorted(STORE_DATA)
    srv = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    srv.daemon_threads = True
    print("Acme CRM listening on :8080", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()

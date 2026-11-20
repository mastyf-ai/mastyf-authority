"""Approver tool. Runs on the approver's own machine; their private key never leaves it.

  authority approver keygen  --out ~/.mastyf/dana.pem          # prints the public key to register
  authority approver pending --url URL --api-key KEY            # list requests waiting for a human
  authority approver approve --url URL --api-key KEY --key ~/.mastyf/dana.pem --as human:dana \\
                             --fingerprint FP --requester human:bob --reason "CHG-1234 key rotation"
  authority approver deny    --url URL --api-key KEY --as human:dana --fingerprint FP --reason "..."
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from .crypto import Signer
from .engine import sign_approval


def _call(url: str, api_key: str, path: str, body: dict | None = None) -> dict:
    if not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise SystemExit("authority URL must be https:// (plain http only for localhost)")
    req = urllib.request.Request(url.rstrip("/") + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:  # nosec B310 - scheme checked above
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"http_error": e.code, **json.loads(e.read() or b"{}")}


def keygen(out: str) -> str:
    s = Signer.load_or_create(Path(out).expanduser())
    return s.public_pem()


def pending(url: str, api_key: str) -> list[dict]:
    return _call(url, api_key, "/v1/pending").get("pending", [])


def approve(url: str, api_key: str, key_path: str, approver: str, fingerprint: str, requester: str, reason: str) -> dict:
    signer = Signer.load_or_create(Path(key_path).expanduser())  # refuses group/world-readable keys
    sig = sign_approval(signer, fingerprint, requester, reason)
    return _call(url, api_key, "/v1/approve", {"fingerprint": fingerprint, "requester": requester,
                                               "approver": approver, "reason": reason, "signature": sig})


def deny(url: str, api_key: str, approver: str, fingerprint: str, reason: str) -> dict:
    return _call(url, api_key, "/v1/deny", {"fingerprint": fingerprint, "approver": approver, "reason": reason})


def show(items: list[dict]) -> str:
    if not items:
        return "No requests waiting."
    lines = []
    for p in items:
        a = p["action"]
        lines.append(f"{p['fingerprint'][:12]}  {p['requester']}  {a['action_type']} {a['count']} x {a['resource']}"
                     + (f" -> {a['destination']}" if a.get("destination") else ""))
        for r in p["reasons"]:
            lines.append(f"      - {r}")
    return "\n".join(lines)

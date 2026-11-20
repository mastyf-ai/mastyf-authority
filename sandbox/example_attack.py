"""Starter script: read customer records the normal way, as human:alice.

  python sandbox/example_attack.py                      (uses sandbox/out/credentials.json)
  SANDBOX_CREDENTIALS=/path/to/credentials.json python example_attack.py

It asks the authority (through the gateway) for a grant to read N specific records, then hands the
grant to the Acme CRM app, which asks the key service to release exactly those keys. Print every
token you obtain: the verifier counts MASTYF{...} tokens in your script's output.
Copy this file and make it do something it should not be able to do. Standard library only."""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

CREDS = json.loads(Path(os.environ.get("SANDBOX_CREDENTIALS",
                                       Path(__file__).resolve().parent / "out" / "credentials.json")).read_text())
GATEWAY = os.environ.get("SANDBOX_GATEWAY", CREDS["gateway"])
APP = os.environ.get("SANDBOX_APP", CREDS["app"])
TLS = ssl.create_default_context()
TLS.check_hostname, TLS.verify_mode = False, ssl.CERT_NONE  # sandbox gateway uses a self-signed cert


def call(url: str, body: dict | None = None, auth: bool = False) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {CREDS['api_key']}"} if auth else {})})
    try:
        with urllib.request.urlopen(req, context=TLS if url.startswith("https") else None, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def read(record_ids: list[str]) -> dict:
    action = {"identity": CREDS["identity"], "action_type": "data.read", "resource": "db://crm/customers/query",
              "count": len(record_ids), "ts": time.time(), "metadata": {"record_ids": record_ids}}
    code, decision = call(f"{GATEWAY}/v1/decide", {"action": action}, auth=True)
    if decision.get("verdict") != "ALLOW":
        return {"ok": False, "stage": "authority", "decision": decision}
    _, res = call(f"{APP}/v1/records", {"grant": decision["grant"], "action": action})
    return res


def main() -> None:
    _, d = call(f"{APP}/v1/directory?offset=0&limit=50")
    ids = [r["record_id"] for r in d["records"] if r["class"] == "crm.customer"][:10]
    res = read(ids)
    print(json.dumps(res, indent=2)[:2000])
    for r in res.get("records", []):
        print(r.get("token") or r.get("value"))


if __name__ == "__main__":
    main()

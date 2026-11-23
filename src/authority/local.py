"""Run Authority and its web console on your own computer, with every credential made for you.

  authority local              set up (first time only) and start: open http://localhost:8740
  authority local keys         show everyone's sign-in key again
  authority local try          send three sample requests: one allowed, one held for approval, one blocked
  authority local approve-device
                               your two colleagues approve your first passkey (the console asks for this)

What `setup` writes into the folder (default ~/.mastyf/local), and what each part is for:

  keys.json            one API key per person or service in the policy, plus "admin". You paste a key into the
                       console's sign-in box. Keep this file private (it is created readable by you only).
  callers.json         what the engine checks keys against: sha256(key) -> identity. It never sees the keys.
  approver_keys.json   public keys of two simulated colleagues (approvers) whose private keys are the
  <name>.key           files next to it. A first passkey needs two approvers to agree; locally, these two sign
                       for you when you run `authority local approve-device`.
  devices.json, state/ created by the engine: registered passkeys, the signed audit log and snapshots.

Passkeys work on http://localhost, so no TLS is needed for this local setup. For a real deployment see
OPERATIONS.md: keys come from your secret store, approvers are real people and the engine runs behind TLS.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_DIR = "~/.mastyf/local"
SAMPLE = {  # sample requests for the bundled policy
    "allowed": {"identity": "human:alice", "action_type": "data.read", "resource": "db://crm/customers/query", "count": 5},
    "held": {"identity": "human:alice", "action_type": "data.export", "resource": "db://crm/customers/export", "count": 500},
    "blocked": {"identity": "human:alice", "action_type": "secret.read", "resource": "vault://prod/db-password", "count": 1},
}


def find_policy(given: str | None) -> Path:
    """--policy, else ./policies/default.json, else the copy shipped inside the package (pip), else the source
    checkout this package runs from."""
    here = Path(__file__).resolve().parent
    for p in ([Path(given)] if given else []) + [Path("policies/default.json"), here / "policies" / "default.json",
                                                here.parents[1] / "policies" / "default.json"]:
        if p.is_file():
            return p.resolve()
    raise SystemExit("no policy file found: pass --policy path/to/policy.json")


def _roles(policy: dict) -> tuple[str, list[str]]:
    """You: the first human approver. Your two colleagues: the next two (they approve your first passkey)."""
    appr = [i for i, r in policy["identities"].items() if r.get("approver") and r.get("kind", "human") == "human"]
    if len(appr) < 3:
        raise SystemExit("the policy needs at least three human approvers (you and two colleagues) for the local console")
    you = "human:dana" if "human:dana" in appr else appr[0]
    return you, [a for a in appr if a != you][:2]


def setup(d: Path, policy_path: Path, force: bool = False) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    if (d / "keys.json").exists() and not force:
        return json.loads((d / "keys.json").read_text())
    policy = json.loads(policy_path.read_text())
    you, colleagues = _roles(policy)
    keys = {who: "mk-" + who.split(":")[-1] + "-" + secrets.token_urlsafe(18) for who in list(policy["identities"]) + ["admin"]}
    _write_private(d / "keys.json", json.dumps(keys, indent=1))
    (d / "callers.json").write_text(json.dumps({hashlib.sha256(k.encode()).hexdigest(): w for w, k in keys.items()}, indent=1))
    pubs = {}
    for who in colleagues:
        sk = Ed25519PrivateKey.generate()
        _write_private(d / (who.split(":")[-1] + ".key"), sk.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        pubs[who] = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    (d / "approver_keys.json").write_text(json.dumps(pubs, indent=1))
    (d / "local.json").write_text(json.dumps({"policy": str(policy_path), "you": you, "colleagues": colleagues}, indent=1))
    return keys


def _write_private(p: Path, text: str) -> None:
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def _meta(d: Path) -> dict:
    p = d / "local.json"
    if not p.exists():
        raise SystemExit(f"nothing set up in {d} yet: run `authority local` first")
    return json.loads(p.read_text())


def show_keys(d: Path, port: int) -> None:
    keys, m = json.loads((d / "keys.json").read_text()), _meta(d)
    print(f"\nMastyf Authority console: http://localhost:{port}\n")
    print(f"  You ({m['you']}), approver.  Sign in to Approvals, Devices and the Risk model lab with:")
    print(f"      {keys[m['you']]}")
    print("  Admin.  Sign in to Team limits with:")
    print(f"      {keys['admin']}")
    print(f"\n  Every other key (one per person and service in the policy): {d / 'keys.json'}")
    print(f"  Colleagues who approve your first passkey: {', '.join(m['colleagues'])} "
          "(run `authority local approve-device` when the Devices page asks)\n")


def env(d: Path, port: int) -> dict:
    return {"AUTHORITY_CALLERS": str(d / "callers.json"), "AUTHORITY_APPROVER_KEYS": str(d / "approver_keys.json"),
            "AUTHORITY_DEVICES": str(d / "devices.json"), "AUTHORITY_RP_ID": "localhost",
            "AUTHORITY_ORIGIN": f"http://localhost:{port}"}


def _call(port: int, key: str, method: str, path: str, body=None) -> dict:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}") | {"http": e.code}
    except urllib.error.URLError as e:
        raise SystemExit(f"the engine is not running on port {port} ({e.reason}): start it with `authority local`")


def approve_device(d: Path, port: int) -> None:
    from cryptography.hazmat.primitives import serialization

    keys, m = json.loads((d / "keys.json").read_text()), _meta(d)
    pend = _call(port, keys[m["colleagues"][0]], "GET", "/v1/enroll/pending").get("pending", [])
    if not pend:
        print("No passkey is waiting. On the Devices page, name your device and click 'Add this device' first.")
        return
    for r in pend:
        msg = f"mastyf-enroll|{r['rid']}|{r['identity']}|{r['exp']}".encode()
        for who in m["colleagues"]:
            sk = serialization.load_pem_private_key((d / (who.split(":")[-1] + ".key")).read_bytes(), password=None)
            sig = base64.urlsafe_b64encode(sk.sign(msg)).rstrip(b"=").decode()
            res = _call(port, keys[who], "POST", "/v1/enroll/approve", {"rid": r["rid"], "signature": sig})
            print(f"{who} approved {r['identity']}'s new device: {res.get('status', res)}")
    print("Back on the Devices page, click 'Register this device' and confirm with your password or Touch ID.")


def try_requests(d: Path, port: int) -> None:
    keys = json.loads((d / "keys.json").read_text())
    for label, act in SAMPLE.items():
        if act["identity"] not in keys:
            print(f"skipped the {label} sample: {act['identity']} is not in this policy")
            continue
        r = _call(port, keys[act["identity"]], "POST", "/v1/decide", {"action": {**act, "ts": time.time()}})
        print(f"{act['identity']} {act['action_type']} x{act['count']}: {r.get('verdict', r)} "
              f"({'; '.join(r.get('reasons', []))})")
    print(f"\nThe held request is now waiting on http://localhost:{port}/approve")


def main(op: str, dir_: str, port: int, policy: str | None, model: str, force: bool) -> None:
    d = Path(os.path.expanduser(dir_))
    if op == "keys":
        return show_keys(d, port)
    if op == "approve-device":
        return approve_device(d, port)
    if op == "try":
        return try_requests(d, port)
    # start (default): set up on first run, then serve
    pol = find_policy(policy or (_meta(d)["policy"] if (d / "local.json").exists() and not force else None))
    setup(d, pol, force=force)
    show_keys(d, port)
    os.environ.update(env(d, port))
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    from .cli import main as cli_main
    cli_main(["serve", "--policy", str(pol), "--model", model, "--state", str(d / "state"),
              "--host", "127.0.0.1", "--port", str(port)])

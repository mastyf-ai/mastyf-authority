"""HTTP API (stdlib only). Binds to localhost by default.

Every caller has its own bearer key, mapped to exactly one identity in a callers file
(sha256 of key -> identity, or "admin"). The identity in a decide request must be the
caller's own: a compromised service cannot act as anyone else. Approvals must carry the
approver's Ed25519 signature. Freeze/unfreeze/script-check/alerts are admin-only.

POST /v1/decide          {"action": {...}, "approval_id"?: str}         -> decision (+ grant if ALLOW)
POST /v1/approve         {"fingerprint", "requester", "approver", "reason"} -> {"approval_id"}
POST /v1/script/check    {"previous"?: str, "candidate": str, "allowed_hosts"?: [str]} -> integrity report
POST /v1/grant/verify    {"grant": str, "action": {...}}                -> {"valid": bool, ...}
POST /v1/freeze          {"identity", "reason"}
POST /v1/unfreeze        {"identity", "operator"}
GET  /v1/alerts          recent alerts
GET  /v1/review          today's most unusual identities, a few a day (admin)
/scim/v2/Users, /scim/v2/Groups   SCIM 2.0 from the identity provider (own token; scim.py)
GET  /v1/teams           teams, members, limits and the one-account damage ceiling (admin)
POST /v1/teams/preview   {team, class, limit}: the ceiling if that limit changed; applies nothing (admin)
GET  /limits             the team limits page
GET  /v1/public-key      PEM of the grant/audit signing key
GET  /healthz

Devices and approvals in the browser (passkeys; see enroll.py):
GET  /approve, /enroll           web pages (static; strict CSP, no inline script)
GET  /v1/devices                 the caller's registered devices
GET  /v1/enroll/pending          enrolment requests waiting for approvers (approvers only)
GET  /v1/enroll/status?rid=      the caller's own request
POST /v1/enroll/begin            {} -> request id and challenge
POST /v1/enroll/authorise        {"rid", "device", "proof"}   proof from an existing device of the caller
POST /v1/enroll/approve          {"rid", "device", "proof"} | {"rid", "signature"}  (approver)
POST /v1/enroll/finish           {"rid", "device_name", "attestation", "client_data", "kex"}
POST /v1/devices/remove          {"device"}  (own device; admin may pass "identity")
POST /v1/agents/session          {"manifest", "device", "proof"}  the caller approves an AI agent's task (agents.py)
POST /v1/agents/revoke           {"session"}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import script_integrity
from .actions import Action, ActionError
from .engine import DENY, Authority
from .crypto import b64d, b64e
from .grants import GrantError, GrantVerifier

MAX_BODY = 2 * 1024 * 1024
WEB = Path(__file__).resolve().parent / "web"
STATIC = {"/approve": ("approve.html", "text/html; charset=utf-8"), "/enroll": ("enroll.html", "text/html; charset=utf-8"),
          "/limits": ("limits.html", "text/html; charset=utf-8"),
          "/web/app.js": ("app.js", "text/javascript; charset=utf-8"), "/web/app.css": ("app.css", "text/css; charset=utf-8")}
PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


def load_callers(path: str) -> dict[str, str]:
    """JSON {"<sha256 hex of bearer key>": "<identity or admin>"}; keys themselves are never stored."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or not all(isinstance(k, str) and len(k) == 64 for k in data):
        raise SystemExit("callers file must map sha256 hex digests to identities")
    return data


def make_handler(auth: Authority, callers: dict[str, str], verifier: GrantVerifier, enroll=None, scim=None):
    class H(BaseHTTPRequestHandler):
        server_version = "mastyf-authority/0.1"
        timeout = 15  # slow or stalled clients are dropped (no slowloris)
        protocol_version = "HTTP/1.1"  # keep-alive for callers making many decisions

        def log_message(self, fmt, *args):  # quieter default logging
            pass

        def _send(self, code: int, obj) -> None:
            c0 = getattr(self, "_crit0", None)
            if c0 is not None and auth.audit.last_critical_seq > c0 and self.path != "/v1/replication":
                # this request wrote a freeze/approval/denial: the standby has it before the caller hears back
                auth.wait_replicated(auth.audit.last_critical_seq)
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if self.command == "POST" and not getattr(self, "_consumed", False):
                self.send_header("Connection", "close")  # unread request body: cannot reuse the connection
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)

        def _principal(self) -> str | None:
            got = self.headers.get("Authorization", "")
            if not got.startswith("Bearer ") or len(got) > 512:
                return None
            digest = hashlib.sha256(got[7:].encode()).hexdigest()
            for h, who in callers.items():
                if hmac.compare_digest(h, digest):
                    return who
            return None

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0 or n > MAX_BODY:
                raise ValueError("body missing or too large")
            raw = self.rfile.read(n)
            self._consumed = True
            d = json.loads(raw)
            if not isinstance(d, dict):
                raise ValueError("body must be a JSON object")
            return d

        def _static(self, name: str, ctype: str) -> None:
            body = (WEB / name).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", PAGE_CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _is_approver(self, who: str) -> bool:
            rule = auth.policy.identities.get(who)
            return bool(rule and rule.approver and rule.kind == "human")

        def _devices_get(self, who: str, path: str, query: dict):
            if enroll is None:
                return self._send(404, {"error": "device enrolment not enabled"})
            if path == "/v1/devices":
                reg = enroll.reg
                return self._send(200, {"identity": who, "rp_id": reg.rp_id, "devices": [
                    {"device": d, "cred_id": b64e(reg.cred_ids[(who, d)]) if (who, d) in reg.cred_ids else None}
                    for d in reg.devices.get(who, {})]})
            if path == "/v1/enroll/pending":
                if not self._is_approver(who):
                    return self._send(403, {"error": "approvers only"})
                return self._send(200, {"pending": [p for p in enroll.pending() if p["identity"] != who]})
            if path == "/v1/enroll/status":
                try:
                    return self._send(200, enroll.status(query.get("rid", [""])[0], who))
                except PermissionError as e:
                    return self._send(400, {"error": str(e)})
            return self._send(404, {"error": "not found"})

        def _devices_post(self, who: str, b: dict):
            if enroll is None:
                return self._send(404, {"error": "device enrolment not enabled"})
            if self.path == "/v1/enroll/begin":
                return self._send(200, enroll.begin(who))
            if self.path == "/v1/enroll/authorise":
                if enroll.owner(b["rid"]) != who:
                    return self._send(403, {"error": "not your enrolment request"})
                return self._send(200, {"status": enroll.authorise_with_device(b["rid"], b["device"], b["proof"])})
            if self.path == "/v1/enroll/approve":
                return self._send(200, {"status": enroll.approve(b["rid"], who, b.get("proof", ""), b.get("device", ""),
                                                                 b.get("signature", ""))})
            if self.path == "/v1/enroll/finish":
                if enroll.owner(b["rid"]) != who:
                    return self._send(403, {"error": "not your enrolment request"})
                return self._send(200, enroll.finish(b["rid"], b["device_name"], b64d(b["attestation"]),
                                                     b64d(b["client_data"]), b64d(b["kex"])))
            if self.path == "/v1/devices/remove":
                ident = b.get("identity", who)
                if ident != who and who != "admin":
                    return self._send(403, {"error": "you can only remove your own devices"})
                return self._send(200, {"removed": enroll.remove(ident, b["device"], who)})
            return self._send(404, {"error": "not found"})

        def _scim(self, method: str):
            """SCIM 2.0 provisioning from the identity provider (scim.py), under its own token."""
            if scim is None:
                return self._send(404, {"error": "SCIM is not enabled"})
            if not scim.authorized(self.headers.get("Authorization", "")):
                self._consumed = True
                return self._send(401, {"error": "unauthorized"})
            body = None
            if method in ("POST", "PUT", "PATCH"):
                try:
                    body = self._body()
                except (ValueError, json.JSONDecodeError) as e:
                    return self._send(400, {"error": str(e)})
            u = urlsplit(self.path)
            try:
                status, obj = scim.handle(method, u.path, parse_qs(u.query), body)
            except Exception:  # noqa: BLE001
                status, obj = 500, {"detail": "internal error"}
            payload = b"" if obj is None else json.dumps(obj).encode()
            self.send_response(status)
            if obj is not None:
                self.send_header("Content-Type", "application/scim+json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_PUT(self):
            self._consumed = False
            return self._scim("PUT") if self.path.startswith("/scim/v2") else self._send(404, {"error": "not found"})

        def do_PATCH(self):
            self._consumed = False
            return self._scim("PATCH") if self.path.startswith("/scim/v2") else self._send(404, {"error": "not found"})

        def do_DELETE(self):
            self._consumed = True
            return self._scim("DELETE") if self.path.startswith("/scim/v2") else self._send(404, {"error": "not found"})

        def do_GET(self):
            if self.path.startswith("/scim/v2"):
                return self._scim("GET")
            if self.path in STATIC:
                return self._static(*STATIC[self.path])
            if self.path == "/healthz":
                return self._send(200, {"ok": True, "model": auth.model is not None, "policy": auth.policy.version,
                                        "role": auth.role, "epoch": auth.issuer.epoch, "seq": auth.audit.position[0]})
            if self.path == "/metrics":
                body = auth.metrics().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            who = self._principal()
            if who is None:
                return self._send(401, {"error": "unauthorized"})
            if self.path == "/v1/alerts":
                if who != "admin":
                    return self._send(403, {"error": "admin only"})
                return self._send(200, {"alerts": list(auth.alerts)[-200:], "frozen": auth.frozen})
            if self.path == "/v1/teams":
                if who != "admin":
                    return self._send(403, {"error": "admin only"})
                return self._send(200, teams_overview(auth))
            if self.path == "/v1/review":
                if who != "admin":
                    return self._send(403, {"error": "admin only"})
                return self._send(200, {"review": auth.review.top(auth.now())})
            if self.path == "/v1/pending":
                rule = auth.policy.identities.get(who)
                if not (rule and rule.approver):
                    return self._send(403, {"error": "approvers only"})
                items = [p for p in auth.pending.values() if p["requester"] != who]
                return self._send(200, {"pending": items})
            if self.path == "/v1/public-key":
                return self._send(200, {"pem": auth.issuer.signer.public_pem()})
            u = urlsplit(self.path)
            if u.path.startswith(("/v1/devices", "/v1/enroll/")):
                return self._devices_get(who, u.path, parse_qs(u.query))
            self._send(404, {"error": "not found"})

        def do_POST(self):
            self._crit0 = auth.audit.last_critical_seq
            return self._post()

        def _post(self):
            self._consumed = False
            if self.path.startswith("/scim/v2"):
                return self._scim("POST")
            who = self._principal()
            if who is None:
                return self._send(401, {"error": "unauthorized"})
            if self.path in ("/v1/freeze", "/v1/unfreeze", "/v1/script/check") and who != "admin":
                return self._send(403, {"error": "admin only"})
            if auth.role != "active" and self.path in ("/v1/decide", "/v1/approve", "/v1/deny", "/v1/freeze",
                                                       "/v1/unfreeze", "/v1/agents/session"):
                body = {"verdict": DENY, "reasons": [f"this authority engine is {auth.role}; failing closed"]} \
                    if self.path == "/v1/decide" else {"error": f"engine is {auth.role}"}
                return self._send(503, body)
            try:
                b = self._body()
            except (ValueError, json.JSONDecodeError) as e:
                if self.path == "/v1/decide":
                    return self._send(400, {"verdict": DENY, "reasons": [f"bad request: {e}"]})
                return self._send(400, {"error": str(e)})
            try:
                if self.path.startswith(("/v1/enroll/", "/v1/devices/")):
                    return self._devices_post(who, b)
                if self.path == "/v1/agents/session":  # a person approves an agent's task with their passkey
                    m = b["manifest"]
                    if not isinstance(m, dict) or m.get("principal") != who:
                        return self._send(403, {"error": "you can only start agent sessions for yourself"})
                    return self._send(200, auth.agents.start(m, b["device"], b["proof"]))
                if self.path == "/v1/agents/revoke":
                    return self._send(200, {"revoked": auth.agents.revoke(b["session"], who)})
                if self.path == "/v1/replication":  # a standby engine pulls the audit records it lacks
                    if who not in ("replica", "admin"):
                        return self._send(403, {"error": "replication is for the standby engine's key"})
                    after, wait = int(b.get("after", 0)), min(8.0, float(b.get("wait", 0)))
                    auth.note_replica(after)  # the standby has everything up to `after`
                    end = time.time() + wait
                    recs = auth.audit.since(after, 2000)
                    while not recs and time.time() < end and auth.role == "active":
                        time.sleep(0.05)
                        recs = auth.audit.since(after, 2000)
                    hs, hh = auth.audit.position
                    return self._send(200, {"records": recs, "head_seq": hs, "head_hash": hh,
                                            "epoch": auth.issuer.epoch, "role": auth.role})
                if self.path == "/v1/promote":  # a gateway that lost the active engine promotes this standby
                    if who not in ("replica", "admin"):
                        return self._send(403, {"error": "promotion needs the failover key"})
                    from .failover import FailoverError, promote
                    try:
                        return self._send(200, promote(auth, auth.issuer.signer, getattr(auth, "follower", None),
                                                       str(b.get("reason", "gateway failover"))[:200]))
                    except FailoverError as e:
                        return self._send(409, {"ok": False, "error": str(e)})
                if self.path == "/v1/decide":
                    act = b.get("action")
                    if not isinstance(act, dict) or act.get("identity") != who:
                        return self._send(403, {"verdict": DENY, "reasons": ["action identity must be the caller's own"]})
                    # The server's clock, never the caller's: daily limits, burst freezes and behavioural
                    # features all count by time, so a backdated or future-dated request could reset them.
                    act = {**act, "ts": auth.now()}
                    d = auth.decide(act, approval_id=b.get("approval_id"))
                    return self._send(200, d.to_dict())
                if self.path == "/v1/approve":
                    if b["approver"] != who:
                        return self._send(403, {"error": "approvers approve only as themselves"})
                    aid = auth.approve(b["fingerprint"], b["requester"], b["approver"], b.get("reason", ""),
                                       b.get("signature", ""))
                    return self._send(200, {"approval_id": aid})
                if self.path == "/v1/deny":
                    if b["approver"] != who:
                        return self._send(403, {"error": "approvers deny only as themselves"})
                    return self._send(200, {"removed": auth.deny(b["fingerprint"], who, b.get("reason", ""))})
                if self.path == "/v1/script/check":
                    rep = script_integrity.check(b.get("previous"), b["candidate"], b.get("allowed_hosts"))
                    auth.record_integrity(rep)
                    return self._send(200, rep)
                if self.path == "/v1/grant/verify":
                    try:
                        payload = verifier.verify(b["grant"], Action.from_dict(b["action"]))
                        return self._send(200, {"valid": True, "grant": payload})
                    except (GrantError, ActionError) as e:
                        return self._send(200, {"valid": False, "error": str(e)})
                if self.path == "/v1/teams/preview":
                    if who != "admin":
                        return self._send(403, {"error": "admin only"})
                    return self._send(200, teams_preview(auth, b["team"], b["class"], int(b["limit"])))
                if self.path == "/v1/freeze":
                    auth.freeze(b["identity"], b.get("reason", "manual"))
                    return self._send(200, {"ok": True})
                if self.path == "/v1/unfreeze":
                    auth.unfreeze(b["identity"], b["operator"])
                    return self._send(200, {"ok": True})
            except (KeyError, PermissionError, ValueError) as e:
                return self._send(400, {"error": f"{type(e).__name__}: {e}"})
            except Exception:  # noqa: BLE001
                if self.path == "/v1/decide":
                    return self._send(500, {"verdict": DENY, "reasons": ["internal error, failing closed"]})
                return self._send(500, {"error": "internal error"})
            self._send(404, {"error": "not found"})

    return H


def _per_day(policy_raw: dict) -> dict:
    """worst case for ONE stolen account, per data class per day (None = unbounded)."""
    from .ceiling import Threat, compute
    worst = compute(policy_raw, Threat(k=1))["worst_case_by_class"]
    return {c: {"per_day": None if w["per_day"] == float("inf") else int(w["per_day"]), "who": w["identities"]}
            for c, w in worst.items()}


def teams_overview(auth: Authority) -> dict:
    src = getattr(auth, "policy_source", None) or auth.policy.raw
    compiled = auth.policy.raw
    members: dict[str, list[str]] = {}
    for ident, r in compiled.get("identities", {}).items():
        for t in r.get("teams", []):
            members.setdefault(t, []).append(ident)
    teams = [{"name": n, "allowed_actions": t.get("allowed_actions", []), "budgets": t.get("budgets", {}),
              "idp_groups": t.get("idp_groups", []), "members": sorted(members.get(n, []))}
             for n, t in src.get("teams", {}).items() if not n.startswith("_")]
    return {"teams": teams, "classes": sorted(compiled.get("data_budgets", {}).get("classes", {})),
            "ceiling": _per_day(compiled)}


def teams_preview(auth: Authority, team: str, cls: str, limit: int) -> dict:
    """What one changed team limit would do to the worst case. Nothing is applied: limits change
    through the reviewed policy file, because loosening one from a web form is exactly what a
    stolen admin key would try."""
    import copy

    from .teams import expand
    src = getattr(auth, "policy_source", None) or auth.policy.raw
    if team not in src.get("teams", {}):
        raise KeyError(f"no team {team}")
    if not 0 <= limit <= 10_000_000:
        raise ValueError("limit out of range")
    s2 = copy.deepcopy(src)
    s2["teams"][team].setdefault("budgets", {})[cls] = limit
    directory = getattr(auth, "directory", None)
    after = expand(s2, directory.snapshot() if directory else None)
    return {"team": team, "class": cls, "limit": limit, "before": _per_day(auth.policy.raw), "after": _per_day(after)}


def scim_from_env(auth: Authority):
    """AUTHORITY_SCIM_TOKEN_SHA256 + AUTHORITY_DIRECTORY turn on identity-provider sync."""
    tok, path = os.environ.get("AUTHORITY_SCIM_TOKEN_SHA256", ""), os.environ.get("AUTHORITY_DIRECTORY", "")
    if not (tok and path):
        return None
    from .policy import Policy
    try:
        from .scim import Directory, ScimService
    except ModuleNotFoundError as e:
        if e.name != "authority.scim":
            raise
        raise SystemExit("SCIM sync is part of Mastyf Authority Enterprise (https://www.mastyf.ai/authority).")
    from .licence import require
    require("authority_scim", "SCIM sync")
    directory = Directory(path)
    auth.directory = directory
    source = getattr(auth, "policy_source", None) or auth.policy.raw

    def on_change(snapshot: dict, deactivated: list[str], reactivated: list[str]) -> None:
        if "teams" in source:
            new = Policy.from_dict(source, snapshot)
            auth.policy = new
            auth.state.meta = new.identity_meta()
        for ident in deactivated:
            auth.freeze(ident, "deactivated or removed in the identity provider")
        for ident in reactivated:
            auth._alert("identity_reactivated", identity=ident, note="stays frozen until an admin unfreezes it")

    on_change(directory.snapshot(), [], [])
    return ScimService(directory, tok, on_change)


class BoundedServer(ThreadingHTTPServer):
    """At most `max_clients` connections at once; beyond that new connections get 503 and are closed,
    so a flood cannot exhaust threads or memory. Put a TLS proxy in front (deploy/Caddyfile)."""
    daemon_threads = True
    request_queue_size = 256

    def __init__(self, addr, handler, max_clients: int = 256):
        import threading
        self._slots = threading.BoundedSemaphore(max_clients)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def serve(auth: Authority, host: str = "127.0.0.1", port: int = 8740, enroll=None) -> None:
    path = os.environ.get("AUTHORITY_CALLERS", "")
    if not path:
        raise SystemExit("set AUTHORITY_CALLERS to a callers JSON file (sha256(key) -> identity)")
    callers = load_callers(path)
    verifier = GrantVerifier(auth.issuer.signer.public_key)
    scim = scim_from_env(auth)
    httpd = BoundedServer((host, port), make_handler(auth, callers, verifier, enroll, scim),
                          int(os.environ.get("AUTHORITY_MAX_CLIENTS", "256")))
    print(f"mastyf-authority listening on http://{host}:{port} (policy {auth.policy.version}, "
          f"model {'loaded' if auth.model else 'MISSING: sensitive actions will escalate'})", flush=True)
    httpd.serve_forever()

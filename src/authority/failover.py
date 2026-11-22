"""Hot-standby failover for the decision engine.

Two engines share one signing key (one authority identity) and run as `active` and `standby`.

Replication. The standby pulls the active engine's audit records (POST /v1/replication through the active
engine's gateway, TLS, `replica` caller key), checks every record (sequence, chain, hash, signature),
appends it verbatim to its own audit log and applies it to its state exactly as a restart would. Its log
is a byte-for-byte copy of the active one, so it can take over with the same state.

Promotion (POST /v1/promote, called by a gateway that lost the active engine). The standby stops
following, takes epoch = last epoch + 1, and FENCES THE KEY SERVICE first: a signed `fence` raises the
key service's minimum engine epoch, so any grant the old engine issues from then on is refused wherever
keys, change gates or undo windows are checked. Only after the fence is durable does it record the
promotion in the audit log and start deciding. If the key service cannot be reached the promotion is
refused (the engine stays standby): better to fail closed than to run two engines whose grants both work.

What fencing does not cover: an old engine that is still running can still answer decisions for actions
that never reach the key service (for example a sign-in allowed by policy) for any caller that still
reaches it. Gateways route only to the engine reporting the highest epoch, and an engine that sees a peer
with a higher epoch demotes itself (see `watch_peer`), so this lasts until the next health check (1 s).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import ssl
import threading
import time
import urllib.parse

from .audit import _canon
from .crypto import b64d, b64e, verify

ACTIVE, STANDBY = "active", "standby"


class FailoverError(Exception):
    pass


# ------------------------------------------------------------------ key service fence
def keyservice_call(req: dict, timeout: float = 5.0) -> dict:
    """AUTHORITY_KEYSERVICE = unix:/path/ks.sock  or  tls:host:port (with AUTHORITY_KEYSERVICE_CA/_CERT/_KEY)."""
    target = os.environ.get("AUTHORITY_KEYSERVICE", "")
    if target.startswith("unix:"):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(target[5:])
    elif target.startswith("tls:"):
        host, port = target[4:].rsplit(":", 1)
        ctx = ssl.create_default_context(cafile=os.environ.get("AUTHORITY_KEYSERVICE_CA"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if os.environ.get("AUTHORITY_KEYSERVICE_CERT"):
            ctx.load_cert_chain(os.environ["AUTHORITY_KEYSERVICE_CERT"], os.environ.get("AUTHORITY_KEYSERVICE_KEY"))
        s = ctx.wrap_socket(socket.create_connection((host, int(port)), timeout=timeout), server_hostname=host)
    else:
        raise FailoverError("AUTHORITY_KEYSERVICE is not set (unix:/path or tls:host:port): cannot fence")
    with s:
        f = s.makefile("rw")
        f.write(json.dumps(req) + "\n")
        f.flush()
        line = f.readline()
    if not line:
        raise FailoverError("key service closed the connection")
    return json.loads(line)


def fence(signer, epoch: int) -> int:
    sig = b64e(signer.sign(f"mastyf-fence|{epoch}".encode()))
    r = keyservice_call({"op": "fence", "epoch": epoch, "sig": sig})
    if not r.get("ok") or int(r.get("min_engine_epoch", -1)) < epoch:
        raise FailoverError(f"key service refused the fence: {r.get('reason', r)}")
    return int(r["min_engine_epoch"])


# ------------------------------------------------------------------ replication (standby side)
def check_record(rec: dict, prev_seq: int, prev_hash: str, public_key) -> None:
    body = {k: rec[k] for k in ("seq", "ts", "prev", "event")}
    if rec["seq"] != prev_seq + 1:
        raise FailoverError(f"replication gap: expected {prev_seq + 1}, got {rec['seq']}")
    if rec["prev"] != prev_hash:
        raise FailoverError(f"replication chain broken at {rec['seq']}")
    if hashlib.sha256(_canon(body)).hexdigest() != rec["hash"]:
        raise FailoverError(f"replicated record altered at {rec['seq']}")
    if not verify(public_key, b64d(rec["sig"]), rec["hash"].encode()):
        raise FailoverError(f"bad signature on replicated record {rec['seq']}")


class Follower:
    def __init__(self, auth, primary_url: str, key: str, public_key, ca: str | None = None):
        self.auth, self.key, self.pk = auth, key, public_key
        u = urllib.parse.urlparse(primary_url)
        self.host, self.port, self.tls = u.hostname, u.port or (443 if u.scheme == "https" else 80), u.scheme == "https"
        self.ctx = ssl.create_default_context(cafile=ca) if self.tls else None
        self.stop_ev = threading.Event()
        self.lag = None
        self.primary_epoch = 0
        self.last_contact = 0.0
        self.error = ""
        self.on_diverged = None  # called when this log has records the active engine never had
        self.thread = threading.Thread(target=self._run, daemon=True, name="replication")

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_ev.set()
        if self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join(timeout=15)

    def _conn(self):
        if self.tls:
            return http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=15)
        return http.client.HTTPConnection(self.host, self.port, timeout=15)

    def _run(self) -> None:
        c = None
        while not self.stop_ev.is_set():
            try:
                c = c or self._conn()
                seq, _ = self.auth.audit.position
                c.request("POST", "/v1/replication", json.dumps({"after": seq, "wait": 5}),
                          {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
                r = c.getresponse()
                body = json.loads(r.read())
                if r.status != 200:
                    raise FailoverError(f"primary answered HTTP {r.status}: {body}")
                self.last_contact = time.time()
                self.primary_epoch = body.get("epoch", 0)
                recs = body.get("records", [])
                mseq, mhead = self.auth.audit.position
                hs, hh = body.get("head_seq", 0), body.get("head_hash")
                if not recs and mseq and (hs < mseq or (hs == mseq and hh and hh != mhead)):
                    raise FailoverError(f"chain broken: this log is at {mseq}, the active engine's at {hs} "
                                        f"with a different history")
                self.apply(recs)
                self.lag = max(0, body.get("head_seq", 0) - self.auth.audit.position[0])
                self.error = ""
            except (OSError, ValueError, http.client.HTTPException, FailoverError) as e:
                self.error = f"{type(e).__name__}: {e}"
                if isinstance(e, FailoverError) and "chain broken" in str(e) and self.on_diverged:
                    self.on_diverged(str(e))  # this engine was active once and wrote records lost in a failover
                    return
                if c is not None:
                    c.close()
                c = None
                if isinstance(e, FailoverError) and ("altered" in str(e) or "signature" in str(e)):
                    self.stop_ev.wait(5)  # never apply bad data; keep retrying slowly
                else:
                    self.stop_ev.wait(0.5)

    def apply(self, records: list[dict]) -> int:
        n = 0
        for rec in records:
            if self.stop_ev.is_set():
                break
            with self.auth._lock:  # state and log advance together
                seq, head = self.auth.audit.position
                if rec["seq"] <= seq:
                    continue
                check_record(rec, seq, head, self.pk)
                self.auth.audit.append_raw(rec)
                self.auth.restore([rec])
            n += 1
        return n


def probe(url: str, ca: str | None) -> dict | None:
    """GET /healthz through a gateway (or directly): the active engine's health, or None."""
    u = urllib.parse.urlparse(url)
    try:
        if u.scheme == "https":
            c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ssl.create_default_context(cafile=ca),
                                            timeout=3)
        else:
            c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=3)
        c.request("GET", "/healthz")
        r = c.getresponse()
        body = json.loads(r.read())
        c.close()
        return body if r.status == 200 else None
    except (OSError, ValueError, http.client.HTTPException):
        return None


def choose_role(peer_url: str | None, ordinal: str, ca: str | None, wait: float = 10.0) -> str:
    """--role auto: follow an engine that is already active; otherwise engine 0 starts active and every other
    engine starts as a standby (only a gateway promotes a standby, so two engines never both start active)."""
    end = time.time() + wait
    while peer_url and time.time() < end:
        h = probe(peer_url, ca)
        if h and h.get("role") == ACTIVE:
            return STANDBY
        time.sleep(1)
    return ACTIVE if ordinal == "0" else STANDBY


def set_aside(state_dir, why: str) -> str:
    """Move a diverged state aside (kept for investigation; nothing signed is deleted) so the engine can
    resync from the active one. The signing key stays."""
    from pathlib import Path
    state_dir = Path(state_dir)
    dest = state_dir / f"diverged-{time.strftime('%Y%m%dT%H%M%S')}"
    dest.mkdir()
    for p in list(state_dir.iterdir()):
        if p.name == "signing_key.pem" or p.name.startswith("diverged-"):
            continue
        p.rename(dest / p.name)
    (dest / "WHY.txt").write_text(why + "\n")
    return str(dest)


# ------------------------------------------------------------------ promotion (standby -> active)
def promote(auth, signer, follower: Follower | None, reason: str) -> dict:
    with auth._promote_lock:
        if auth.role == ACTIVE:
            return {"ok": True, "role": ACTIVE, "epoch": auth.issuer.epoch, "note": "already active"}
        if follower is not None:
            follower.stop()
        with auth._lock:
            epoch = max(auth.issuer.epoch, follower.primary_epoch if follower else 0) + 1
            try:
                min_ep = fence(signer, epoch)
            except (OSError, ValueError, FailoverError) as e:
                if follower is not None:  # stay a standby and keep following
                    follower.stop_ev.clear()
                    follower.thread = threading.Thread(target=follower._run, daemon=True, name="replication")
                    follower.start()
                raise FailoverError(f"promotion refused, key service not fenced: {e}") from e
            auth.audit.append({"type": "promotion", "epoch": epoch, "reason": reason, "fenced_min_epoch": min_ep})
            auth.issuer.epoch = epoch
            auth.role = ACTIVE
        auth._alert("engine_promoted", epoch=epoch, reason=reason)
        return {"ok": True, "role": ACTIVE, "epoch": epoch}


def watch_peer(auth, peer_url: str, key: str, ca: str | None, on_superseded, every: float = 1.0) -> None:
    """An active engine checks its peer; if the peer is active with a higher epoch, this one was replaced
    (failover happened while it was cut off) and must stop deciding at once."""
    u = urllib.parse.urlparse(peer_url)
    ctx = ssl.create_default_context(cafile=ca) if u.scheme == "https" else None

    def loop():
        while True:
            time.sleep(every)
            if auth.role != ACTIVE:
                continue
            try:
                c = (http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=3) if ctx else
                     http.client.HTTPConnection(u.hostname, u.port or 80, timeout=3))
                c.request("GET", "/healthz")
                h = json.loads(c.getresponse().read())
                c.close()
            except (OSError, ValueError, http.client.HTTPException):
                continue
            if h.get("role") == ACTIVE and int(h.get("epoch", 0)) > auth.issuer.epoch:
                on_superseded(h)
    threading.Thread(target=loop, daemon=True, name="peer-watch").start()

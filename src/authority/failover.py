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


LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def require_tls(url: str) -> urllib.parse.ParseResult:
    """Replication carries the replica key and every audit record: HTTPS unless both ends share a machine."""
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" and u.hostname not in LOOPBACK:
        raise FailoverError(f"{url}: use https (plain http is accepted only on loopback)")
    return u


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


def shard() -> str:
    """AUTHORITY_SHARD: this engine pair's shard in a sharded deployment ("" = not sharded)."""
    return os.environ.get("AUTHORITY_SHARD", "")


def _tag(op: str) -> str:
    return f"mastyf-{op}@{shard()}" if shard() else f"mastyf-{op}"


def shard_headers() -> dict:
    return {"X-Authority-Shard": shard()} if shard() else {}


class Fenced(FailoverError):
    """The key service has fenced a newer engine: this one must not confirm or decide anything."""


def fence(signer, epoch: int, floor_seq: int = 0, floor_hash: str = "") -> int:
    """Strictly increasing (formal/Failover.tla): refused unless `epoch` is above every earlier fence and this
    engine holds the newest confirmed critical record. Returns the epoch, or raises with the key service's
    current minimum in `.min_epoch`."""
    sig = b64e(signer.sign(f"{_tag('fence')}|{epoch}|{floor_seq}|{floor_hash}".encode()))
    r = keyservice_call({"op": "fence", "shard": shard(), "epoch": epoch, "floor_seq": floor_seq,
                         "floor_hash": floor_hash, "sig": sig})
    if not r.get("ok") or int(r.get("min_engine_epoch", -1)) != epoch:
        e = FailoverError(f"key service refused the fence: {r.get('reason', r)}")
        e.min_epoch = int(r.get("min_engine_epoch", 0) or 0)
        raise e
    return epoch


def get_floor() -> tuple[int, str, int]:
    """(seq, hash) of the newest confirmed critical record, and the fenced epoch."""
    r = keyservice_call({"op": "floor_get", "shard": shard()})
    if not r.get("ok"):
        raise FailoverError(f"key service: {r.get('reason', r)}")
    return int(r.get("seq", 0)), str(r.get("hash", "")), int(r.get("min_engine_epoch", 0))


def write_floor(signer, epoch: int, seq: int, h: str) -> None:
    """Before a critical record (freeze, approval, denial) is confirmed to its caller. Raises Fenced if a newer
    engine was promoted (then nothing may be confirmed), OSError/FailoverError if the key service is down."""
    sig = b64e(signer.sign(f"{_tag('floor')}|{epoch}|{seq}|{h}".encode()))
    r = keyservice_call({"op": "floor", "shard": shard(), "epoch": epoch, "seq": seq, "hash": h, "sig": sig})
    if not r.get("ok"):
        why = str(r.get("reason", r))
        raise (Fenced if why.startswith("fenced") else FailoverError)(f"key service refused the floor: {why}")


def hash_at(auth, seq: int) -> str | None:
    """Hash of this engine's own record `seq` (recent records in memory, else read from the log)."""
    if seq <= 0:
        return ""
    for rec in reversed(auth.audit.records):
        if rec["seq"] == seq:
            return rec["hash"]
        if rec["seq"] < seq:
            break
    if auth.audit.path is not None:
        from .audit import record_at
        r = record_at(auth.audit.path, seq)
        return r["hash"] if r else None
    return None


def fence_new_epoch(auth, signer, known: int = 0) -> tuple[int, int]:
    """Fence the next epoch for this engine after checking it holds the floor. Returns (epoch, floor seq)."""
    fseq, fhash, cur = get_floor()
    mine = hash_at(auth, fseq)
    if fseq and mine != fhash:
        raise FailoverError(f"not promotable: this engine does not hold confirmed record {fseq} "
                            f"(it has {auth.audit.position[0]} records); wait for it to catch up")
    epoch = max(auth.issuer.epoch, known, cur) + 1
    for _ in range(3):  # another engine may fence in between: take the next epoch
        try:
            return fence(signer, epoch, fseq, fhash), fseq
        except FailoverError as e:
            if getattr(e, "min_epoch", 0) >= epoch and "not above" in str(e):
                epoch = e.min_epoch + 1
                continue
            raise
    raise FailoverError("could not fence a new epoch (contended)")


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
        u = require_tls(primary_url)
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
                seq, head = self.auth.audit.position
                c.request("POST", "/v1/replication", json.dumps({"after": seq, "after_hash": head, "wait": 5}),
                          {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json", **shard_headers()})
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
                    # this engine was active once and wrote records lost in a failover: keep the history both
                    # share, set aside only what came after the split
                    try:
                        keep = self.common_prefix(c)
                    except (OSError, ValueError, http.client.HTTPException, FailoverError):
                        keep = 0
                    self.on_diverged(str(e), keep)
                    return
                if c is not None:
                    c.close()
                c = None
                if isinstance(e, FailoverError) and ("altered" in str(e) or "signature" in str(e)):
                    self.stop_ev.wait(5)  # never apply bad data; keep retrying slowly
                else:
                    self.stop_ev.wait(0.5)

    def _remote_hash(self, c, seq: int) -> str | None:
        c.request("POST", "/v1/replication", json.dumps({"after": seq - 1, "limit": 1, "wait": 0}),
                  {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json", **shard_headers()})
        r = c.getresponse()
        body = json.loads(r.read())
        recs = body.get("records", [])
        return recs[0]["hash"] if recs and recs[0]["seq"] == seq else None

    def common_prefix(self, c=None) -> int:
        """The last sequence number where this log and the active engine's agree (binary search: about 20
        one-record requests for a million records)."""
        c = c or self._conn()
        lo, hi = 0, self.auth.audit.position[0]  # agree at lo (0 always), unknown above
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._remote_hash(c, mid) == hash_at(self.auth, mid):
                lo = mid
            else:
                hi = mid - 1
        return lo

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
    u = require_tls(url)
    try:
        if u.scheme == "https":
            c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ssl.create_default_context(cafile=ca),
                                            timeout=3)
        else:
            c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=3)
        c.request("GET", "/healthz", headers=shard_headers())
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


def set_aside(state_dir, why: str, keep_upto: int = 0) -> str:
    """Move a diverged state aside (kept for investigation; nothing signed is deleted) so the engine can
    resync from the active one. The signing key stays, and so does the history both engines share (records
    up to `keep_upto`): the engine rebuilds from it and copies only what it is missing."""
    from pathlib import Path
    from .audit import iter_records
    state_dir = Path(state_dir)
    dest = state_dir / f"diverged-{time.strftime('%Y%m%dT%H%M%S')}"
    dest.mkdir()
    for p in list(state_dir.iterdir()):
        if p.name == "signing_key.pem" or p.name.startswith("diverged-"):
            continue
        p.rename(dest / p.name)
    (dest / "WHY.txt").write_text(why + f"\nshared history kept: records 1..{keep_upto}\n")
    if keep_upto > 0 and ((dest / "audit.jsonl").exists() or (dest / "audit-archive").exists()):
        tmp = state_dir / "audit.jsonl.part"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            for rec in iter_records(dest / "audit.jsonl"):
                if rec["seq"] > keep_upto:
                    break
                f.write(json.dumps(rec, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        tmp.rename(state_dir / "audit.jsonl")
        snap = dest / "snapshot.json"  # a snapshot inside the shared history is still valid: restart from it
        try:
            body = json.loads(snap.read_text())
            if int((body.get("body") or body).get("seq", 10**18)) <= keep_upto:
                (state_dir / "snapshot.json").write_bytes(snap.read_bytes())
                os.chmod(state_dir / "snapshot.json", 0o600)
        except (OSError, ValueError, AttributeError):
            pass
    return str(dest)


# ------------------------------------------------------------------ promotion (standby -> active)
def promote(auth, signer, follower: Follower | None, reason: str) -> dict:
    with auth._promote_lock:
        if auth.role == ACTIVE:
            return {"ok": True, "role": ACTIVE, "epoch": auth.issuer.epoch, "note": "already active"}
        if follower is not None:
            follower.stop()
        with auth._lock:
            try:
                epoch, floor_seq = fence_new_epoch(auth, signer, follower.primary_epoch if follower else 0)
            except (OSError, ValueError, FailoverError) as e:
                if follower is not None:  # stay a standby and keep following
                    follower.stop_ev.clear()
                    follower.thread = threading.Thread(target=follower._run, daemon=True, name="replication")
                    follower.start()
                raise FailoverError(f"promotion refused, key service not fenced: {e}") from e
            auth.audit.append({"type": "promotion", "epoch": epoch, "reason": reason, "floor_seq": floor_seq})
            auth.issuer.epoch = epoch
            auth.role = ACTIVE
        print(f"PROMOTED: active at epoch {epoch} ({reason})", flush=True)
        auth._alert("engine_promoted", epoch=epoch, reason=reason)
        return {"ok": True, "role": ACTIVE, "epoch": epoch}


def watch_peer(auth, peer_url: str, key: str, ca: str | None, on_superseded, every: float = 1.0) -> None:
    """An active engine checks its peer; if the peer is active with a higher epoch, this one was replaced
    (failover happened while it was cut off) and must stop deciding at once."""
    u = require_tls(peer_url)
    ctx = ssl.create_default_context(cafile=ca) if u.scheme == "https" else None

    def loop():
        while True:
            time.sleep(every)
            if auth.role != ACTIVE:
                continue
            try:
                c = (http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=3) if ctx else
                     http.client.HTTPConnection(u.hostname, u.port or 80, timeout=3))
                c.request("GET", "/healthz", headers=shard_headers())
                h = json.loads(c.getresponse().read())
                c.close()
            except (OSError, ValueError, http.client.HTTPException):
                continue
            if h.get("role") == ACTIVE and int(h.get("epoch", 0)) > auth.issuer.epoch:
                on_superseded(h)
    threading.Thread(target=loop, daemon=True, name="peer-watch").start()

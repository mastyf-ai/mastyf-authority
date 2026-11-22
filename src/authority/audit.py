"""Append-only, hash-chained, Ed25519-signed decision log (JSON lines), in rotating segments.

Layout (all in the state directory):
  audit.jsonl                          the active segment
  audit-archive/<first>-<last>.jsonl   closed segments (may be gzipped by operators: .jsonl.gz)
The hash chain runs across segments: the first record of a segment points at the last of the one before.

Durability: every record is written to the OS before `append` returns, so a process crash loses nothing.
Events other than routine decisions (freezes, unfreezes, approvals, denials, learned destinations,
integrity reports, snapshots) are also fsynced before `append` returns, so they survive power loss.
Routine decisions are fsynced in groups at least every `sync_interval` seconds (default 0.2 s): a power
cut can lose at most that window of decision records, never a freeze or an approval. Data budgets are not
affected: the key service journals every release itself before handing out a key.

Startup reads only the end of the active segment; verification and restore stream the records instead of
loading them (see `iter_records`, `verify_log`).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Iterator

from .crypto import Signer, b64d, b64e, verify

GENESIS = "0" * 64
ROUTINE = {"decision"}  # group-synced; everything else is synced before append returns
SEGMENT_BYTES = 256 * 1024 * 1024


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _last_line(path: Path) -> str | None:
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        block, buf = 65536, b""
        pos = end
        while pos > 0:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            lines = [x for x in buf.split(b"\n") if x.strip()]
            if len(lines) >= 2 or (pos == 0 and lines):
                return lines[-1].decode()
    return None


def repair_tail(path: Path) -> int:
    """After a power cut the final line of the active segment can be half-written. Cut the file back to
    the end of its last complete record; returns the number of bytes removed (0 if it was intact)."""
    if not path.exists():
        return 0
    with path.open("rb+") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return 0
        pos = max(0, size - (1 << 20))
        f.seek(pos)
        data = f.read()
        body = data.rstrip(b"\n")
        idx = body.rfind(b"\n")
        try:
            json.loads(body[idx + 1:])
        except ValueError:
            keep = pos + idx + 1 if idx >= 0 else pos
            f.truncate(keep)
            return size - keep
        if not data.endswith(b"\n"):
            f.seek(0, os.SEEK_END)
            f.write(b"\n")
        return 0


def _first_line(path: Path) -> str | None:
    with path.open("rb") as f:
        for line in f:
            if line.strip():
                return line.decode()
    return None


def archive_dir(path: Path) -> Path:
    return path.parent / "audit-archive"


def segments(path: str | Path) -> list[Path]:
    """Closed segments in order, then the active one (if it exists)."""
    path = Path(path)
    arch = archive_dir(path)
    out = []
    if arch.is_dir():
        out = sorted((p for p in arch.iterdir() if p.name.endswith((".jsonl", ".jsonl.gz"))),
                     key=lambda p: int(p.name.split("-")[0]))
    if path.exists():
        out.append(path)
    return out


def iter_records(path: str | Path, after_seq: int = 0) -> Iterator[dict]:
    """Every record with seq > after_seq, oldest first, without loading the log into memory."""
    for seg in segments(path):
        if seg.parent.name == "audit-archive":
            last = int(seg.name.split("-")[1].split(".")[0])
            if last <= after_seq:
                continue
        opener = gzip.open if seg.name.endswith(".gz") else open
        with opener(seg, "rt") as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    if rec["seq"] > after_seq:
                        yield rec


class AuditLog:
    def __init__(self, path: str | Path | None, signer: Signer, now=time.time, segment_bytes: int = SEGMENT_BYTES,
                 sync_interval: float = 0.2):
        self.path = Path(path) if path else None
        self.signer = signer
        self.now = now
        self.segment_bytes = segment_bytes
        self._lock = threading.Lock()
        self._sync_lock = threading.Lock()
        self.records: deque = deque(maxlen=50000)  # newest records: replication to a standby, tests, metrics
        self._seq = 0
        self._head = GENESIS
        self._f = None
        self._dirty = False
        self._seg_first = None
        self.synced_seq = 0
        self.last_critical_seq = 0  # newest non-routine record (freeze, approval, ...): replicated synchronously
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.repaired_bytes = repair_tail(self.path)
        last = _last_line(self.path) if self.path.exists() else None
        if last is None:  # empty or absent active segment: continue from the newest archive
            arch = [p for p in segments(self.path) if p != self.path]
            if arch:
                opener = gzip.open if arch[-1].name.endswith(".gz") else open
                tail = None
                with opener(arch[-1], "rt") as f:
                    for line in f:
                        if line.strip():
                            tail = line
                last = tail
        if last:
            rec = json.loads(last)
            self._seq, self._head = rec["seq"], rec["hash"]
        if self.path.exists():
            first = _first_line(self.path)
            self._seg_first = json.loads(first)["seq"] if first else None
        self.synced_seq = self._seq
        self._f = self._open_private()
        if sync_interval > 0:
            threading.Thread(target=self._syncer, args=(sync_interval,), daemon=True,
                             name="audit-sync").start()

    def _open_private(self):
        """The log names people, resources and decisions: owner-only (0600), also if it existed before."""
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "ab", buffering=0)

    @property
    def position(self) -> tuple[int, str]:
        return self._seq, self._head

    def _syncer(self, every: float) -> None:
        while True:
            time.sleep(every)
            if self._dirty:
                self._sync_to(self._seq)

    def _sync_to(self, seq: int) -> None:
        """fsync without holding the append lock (a slow disk must not stall every decision); returns once
        everything up to `seq` is on disk. Concurrent callers share one fsync."""
        with self._sync_lock:
            if self.synced_seq >= seq:
                return
            with self._lock:
                f, upto = self._f, self._seq
                self._dirty = False
            if f is None:
                return
            try:
                os.fsync(f.fileno())
            except (OSError, ValueError):  # closed by a rotation meanwhile: the rotation synced it
                pass
            self.synced_seq = max(self.synced_seq, upto)

    def _fsync(self) -> None:
        """Under the append lock (rotation, close): sync now."""
        os.fsync(self._f.fileno())
        self._dirty = False
        self.synced_seq = self._seq

    def append(self, event: dict) -> dict:
        with self._lock:
            rec = {"seq": self._seq + 1, "ts": self.now(), "prev": self._head, "event": event}
            h = hashlib.sha256(_canon(rec)).hexdigest()
            rec["hash"] = h
            rec["sig"] = b64e(self.signer.sign(h.encode()))
            if event.get("type") not in ROUTINE:
                self.last_critical_seq = rec["seq"]
            critical = False
            if self._f is not None:
                self._f.write((json.dumps(rec, default=str) + "\n").encode())
                if self._seg_first is None:
                    self._seg_first = rec["seq"]
                self._seq, self._head = rec["seq"], h
                self._dirty = True
                critical = event.get("type") not in ROUTINE
                if self._f.tell() >= self.segment_bytes:
                    self._rotate()
            else:
                self._seq, self._head = rec["seq"], h
            self.records.append(rec)
        if critical:
            self._sync_to(rec["seq"])  # on disk before the caller hears back
        return rec

    def append_raw(self, rec: dict) -> None:
        """A standby writes the active engine's record verbatim (already checked by the caller), so its
        log stays an exact copy: same sequence numbers, hashes and signatures."""
        with self._lock:
            if rec["seq"] != self._seq + 1 or rec["prev"] != self._head:
                raise ValueError("replicated record does not continue this log")
            if self._f is not None:
                self._f.write((json.dumps(rec, default=str) + "\n").encode())
                if self._seg_first is None:
                    self._seg_first = rec["seq"]
                self._dirty = True
            self._seq, self._head = rec["seq"], rec["hash"]
            critical = self._f is not None and rec["event"].get("type") not in ROUTINE
            if self._f is not None and self._f.tell() >= self.segment_bytes:
                self._rotate()
            self.records.append(rec)
        if critical:
            self._sync_to(rec["seq"])

    def since(self, after: int, limit: int) -> list[dict]:
        """Records with seq > after (oldest first), from memory when recent, else from the files."""
        with self._lock:
            mem = list(self.records)
        if mem and mem[0]["seq"] <= after + 1:
            return [r for r in mem if r["seq"] > after][:limit]
        if self.path is None:
            return []
        out = []
        for r in iter_records(self.path, after_seq=after):
            out.append(r)
            if len(out) >= limit:
                break
        return out

    def _rotate(self) -> None:
        self._fsync()
        self._f.close()
        arch = archive_dir(self.path)
        arch.mkdir(exist_ok=True)
        dest = arch / f"{self._seg_first:012d}-{self._seq:012d}.jsonl"
        os.replace(self.path, dest)
        for d in (arch, self.path.parent):
            fd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        self._f = self._open_private()
        self._seg_first = None

    def flush(self) -> None:
        if self._f is not None and self._dirty:
            self._sync_to(self._seq)

    def close(self) -> None:
        with self._lock:
            if self._f is not None:
                if self._dirty:
                    self._fsync()
                self._f.close()
                self._f = None


def verify_log(path: str | Path, public_key, from_seq: int = 0, from_hash: str = GENESIS) -> tuple[bool, str]:
    """Checks sequence, chain, hashes and signatures of every record after `from_seq` (whose hash must be
    `from_hash`), across all segments. With the defaults, the whole history."""
    prev, seq = from_hash, from_seq
    for rec in iter_records(path, after_seq=from_seq):
        body = {k: rec[k] for k in ("seq", "ts", "prev", "event")}
        if rec["seq"] != seq + 1:
            return False, f"sequence gap at {rec['seq']}"
        if rec["prev"] != prev:
            return False, f"chain broken at seq {rec['seq']}"
        if hashlib.sha256(_canon(body)).hexdigest() != rec["hash"]:
            return False, f"record altered at seq {rec['seq']}"
        if not verify(public_key, b64d(rec["sig"]), rec["hash"].encode()):
            return False, f"bad signature at seq {rec['seq']}"
        prev, seq = rec["hash"], rec["seq"]
    return True, f"{seq - from_seq} records verified"


def record_at(path: str | Path, seq: int) -> dict | None:
    for rec in iter_records(path, after_seq=seq - 1):
        return rec if rec["seq"] == seq else None
    return None

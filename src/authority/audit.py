"""Append-only, hash-chained, Ed25519-signed decision log (JSON lines)."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

from .crypto import Signer, b64d, b64e, verify

GENESIS = "0" * 64


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


class AuditLog:
    def __init__(self, path: str | Path | None, signer: Signer, now=time.time):
        self.path = Path(path) if path else None
        self.signer = signer
        self.now = now
        self._lock = threading.Lock()
        self.records: list[dict] = []  # kept in memory too (bounded use: tests, replay)
        self._seq = 0
        self._head = GENESIS
        if self.path and self.path.exists():
            last = None
            with self.path.open() as f:
                for line in f:
                    if line.strip():
                        last = json.loads(line)
            if last:
                self._seq, self._head = last["seq"], last["hash"]

    def append(self, event: dict) -> dict:
        with self._lock:
            rec = {"seq": self._seq + 1, "ts": self.now(), "prev": self._head, "event": event}
            h = hashlib.sha256(_canon(rec)).hexdigest()
            rec["hash"] = h
            rec["sig"] = b64e(self.signer.sign(h.encode()))
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as f:
                    f.write(json.dumps(rec, default=str) + "\n")
            self.records.append(rec)
            if len(self.records) > 10000:
                del self.records[:5000]
            self._seq, self._head = rec["seq"], h
            return rec


def verify_log(path: str | Path, public_key) -> tuple[bool, str]:
    prev, seq = GENESIS, 0
    with Path(path).open() as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
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
    return True, f"{seq} records verified"

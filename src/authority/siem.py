"""Stream the signed audit log to a SIEM, as OCSF events.

  authority siem --state /var/lib/authority --to opensearch+https://search:9200/authority [--from-seq N]
  authority siem --state ... --to splunk+https://splunk:8088 (HEC token in AUTHORITY_SIEM_TOKEN)
  authority siem --state ... --to file:/var/log/authority/ocsf.jsonl
  authority siem --state ... --to stdout

Every record is verified (hash chain and signature) before it is sent, so the SIEM only ever receives what
the engine signed; the position is kept in <state>/siem.pos and the stream resumes there after a restart
(at-least-once: each event carries its log sequence number as a stable id for de-duplication).

OCSF 1.3 mapping (https://schema.ocsf.io):
  decision                       6003 API Activity         (actor = identity, api.operation = action type,
                                                            resources = resource / destination, status = verdict)
  freeze, unfreeze, promotion,   2004 Detection Finding    (an operator-relevant security event)
  agent revocation, alerts
  approval, denial               3005 User Access Management (a person changing what another may do)
  anything else                  0    Base Event
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from .audit import iter_records
from .failover import check_record

VERSION = "1.3.0"
SEVERITY = {"ALLOW": 1, "ESCALATE": 3, "DENY": 4}  # informational, medium, high


def to_ocsf(rec: dict) -> dict:
    ev = rec.get("event", {})
    kind = ev.get("type")
    t = int(rec["ts"] * 1000)
    base = {"metadata": {"version": VERSION, "product": {"name": "Mastyf Authority", "vendor_name": "Mastyf"},
                         "uid": f"{rec['seq']}", "log_name": "authority-audit",
                         "original_hash": rec["hash"]},
            "time": t, "unmapped": {"seq": rec["seq"], "event_type": kind}}
    if kind == "decision":
        a = ev.get("action", {})
        verdict = ev.get("verdict")
        out = {**base, "class_uid": 6003, "class_name": "API Activity", "category_uid": 6, "activity_id": 99,
               "type_uid": 600399, "severity_id": SEVERITY.get(verdict, 0),
               "status": {"ALLOW": "Success", "DENY": "Failure"}.get(verdict, "Other"),
               "status_id": {"ALLOW": 1, "DENY": 2}.get(verdict, 99), "status_detail": verdict,
               "message": "; ".join(ev.get("reasons", []))[:2000],
               "actor": {"user": {"uid": a.get("identity"), "name": a.get("identity")}},
               "api": {"operation": a.get("action_type"), "request": {"uid": ev.get("decision_id")}},
               "resources": [{"uid": a.get("resource"), "type": "resource"}]
               + ([{"uid": a.get("destination"), "type": "destination"}] if a.get("destination") else []),
               "src_endpoint": {"network": ev["origin"]} if ev.get("origin") else {}}
        out["unmapped"].update({"count": a.get("count"), "risk": ev.get("risk"), "stage": ev.get("stage"),
                                "fingerprint": ev.get("fingerprint"), "session": a.get("session"),
                                "approved_by": ev.get("approved_by")})
        return out
    if kind in ("approval", "denial"):
        return {**base, "class_uid": 3005, "class_name": "User Access Management", "category_uid": 3,
                "activity_id": 1 if kind == "approval" else 2, "type_uid": 300500 + (1 if kind == "approval" else 2),
                "severity_id": 2, "actor": {"user": {"uid": ev.get("approver")}},
                "user": {"uid": ev.get("requester")}, "message": ev.get("reason", ""),
                "unmapped": {**base["unmapped"], "fingerprint": ev.get("fingerprint"),
                             "approval_id": ev.get("approval_id")}}
    if kind in ("freeze", "unfreeze", "promotion", "agent_revoked", "alert", "integrity_report", "origin_learned",
                "destination_learned"):
        sev = {"freeze": 4, "agent_revoked": 4, "promotion": 3}.get(kind, 2)
        return {**base, "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "activity_id": 1,
                "type_uid": 200401, "severity_id": sev,
                "finding_info": {"uid": f"authority-{rec['seq']}", "title": kind.replace("_", " "),
                                 "desc": str(ev.get("reason") or ev.get("detail") or ev.get("why") or "")[:2000]},
                "actor": {"user": {"uid": ev.get("identity") or ev.get("operator") or ev.get("by")}},
                "unmapped": {**base["unmapped"], **{k: v for k, v in ev.items() if k != "type"}}}
    return {**base, "class_uid": 0, "class_name": "Base Event", "category_uid": 0, "activity_id": 0, "type_uid": 0,
            "severity_id": 1, "unmapped": {**base["unmapped"], "event": ev}}


class Sink:
    def __init__(self, to: str, batch: int = 500):
        self.to, self.batch = to, batch
        self.token = os.environ.get("AUTHORITY_SIEM_TOKEN", "")
        self.user = os.environ.get("AUTHORITY_SIEM_USER", "")
        self.ctx = ssl.create_default_context(cafile=os.environ.get("AUTHORITY_SIEM_CA") or None)
        if os.environ.get("AUTHORITY_SIEM_INSECURE") == "1":  # lab only: self-signed test clusters
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.f = None
        if to.startswith("file:"):
            self.f = open(to[5:], "a", buffering=1)
        elif to == "stdout":
            self.f = sys.stdout

    def _post(self, url: str, body: bytes, ctype: str, auth: str | None) -> None:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1")):
            # audit records and SIEM credentials never travel in the clear (and never to file:// or other schemes)
            raise SystemExit(f"SIEM target must be https:// (http only on this machine): {u.scheme}://{u.hostname}")
        req =urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": ctype})
        if auth:
            req.add_header("Authorization", auth)
        with urllib.request.urlopen(req, timeout=30, context=self.ctx if url.startswith("https") else None) as r:
            out = r.read()
        if url.endswith("/_bulk") and json.loads(out).get("errors"):
            raise OSError(f"bulk index had errors: {out[:500]!r}")

    def send(self, events: list[dict]) -> None:
        if not events:
            return
        if self.f is not None:
            for e in events:
                self.f.write(json.dumps(e) + "\n")
            return
        scheme, _, url = self.to.partition("+")
        if scheme == "opensearch":  # also Elasticsearch: <base>/<index>
            base, index = url.rsplit("/", 1)
            lines = []
            for e in events:
                lines.append(json.dumps({"index": {"_index": index, "_id": e["metadata"]["uid"]}}))
                lines.append(json.dumps(e))
            auth = ("Basic " + base64.b64encode(self.user.encode()).decode()) if self.user else None
            self._post(base + "/_bulk", ("\n".join(lines) + "\n").encode(), "application/x-ndjson", auth)
        elif scheme == "splunk":
            body = "".join(json.dumps({"time": e["time"] / 1000, "sourcetype": "ocsf:authority", "event": e})
                           for e in events).encode()
            self._post(url.rstrip("/") + "/services/collector/event", body, "application/json", f"Splunk {self.token}")
        elif scheme == "webhook":
            self._post(url, json.dumps(events).encode(), "application/json",
                       f"Bearer {self.token}" if self.token else None)
        else:
            raise SystemExit(f"unknown SIEM target {self.to}")


class _Tail:
    """New records after `seq`. Remembers where it stopped in the active segment, so following a busy log does
    not re-read it; after a rotation (new file) it falls back to scanning from the last sequence number."""

    def __init__(self, path: Path):
        self.path, self.ino, self.off = path, None, 0

    def read(self, after_seq: int):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            st = None
        if st is not None and self.ino == st.st_ino and st.st_size >= self.off:
            with open(self.path, "rb") as f:
                f.seek(self.off)
                for line in f:
                    if not line.endswith(b"\n"):
                        break  # a record still being written
                    self.off += len(line)
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue  # the tail of a line already read by a full scan
                    if rec["seq"] > after_seq:
                        yield rec
            return
        # full scan; resume later from where the active segment was when the scan began (records read twice
        # are dropped by sequence number in stream())
        if st is not None:
            self.ino, self.off = st.st_ino, st.st_size
        yield from iter_records(self.path, after_seq=after_seq)


def stream(state: str, to: str, public_key, from_seq: int | None = None, follow: bool = True,
           batch: int = 500, idle: float = 1.0, max_records: int | None = None) -> int:
    """Send verified records after the saved position; returns how many were sent."""
    st = Path(state)
    pos_file = st / "siem.pos"
    seq, head = 0, "0" * 64
    if from_seq is None and pos_file.exists():
        p = json.loads(pos_file.read_text())
        seq, head = p["seq"], p["hash"]
    elif from_seq:
        from .audit import record_at
        r = record_at(st / "audit.jsonl", from_seq)
        seq, head = (r["seq"], r["hash"]) if r else (0, "0" * 64)
    sink = Sink(to, batch)
    sent = 0
    tail = _Tail(st / "audit.jsonl")
    while True:
        buf = []
        for rec in tail.read(seq):
            if rec["seq"] <= seq:
                continue
            check_record(rec, seq, head, public_key)  # never forward anything the engine did not sign
            buf.append(to_ocsf(rec))
            seq, head = rec["seq"], rec["hash"]
            if len(buf) >= batch:
                sink.send(buf)
                sent += len(buf)
                buf = []
                pos_file.write_text(json.dumps({"seq": seq, "hash": head}))
            if max_records is not None and sent + len(buf) >= max_records:
                break
        sink.send(buf)
        sent += len(buf)
        pos_file.write_text(json.dumps({"seq": seq, "hash": head}))
        if not follow or (max_records is not None and sent >= max_records):
            return sent
        time.sleep(idle)

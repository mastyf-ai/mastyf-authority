"""Audit evidence bundle: what a SOC 2 / ISO 27001 auditor asks for, taken from the verified audit log.

  authority evidence --state DIR --policy policy.json [--since 2026-10-01] [--until 2026-11-01] --out evidence.zip

The bundle holds:
  manifest.json      period, sha256 of every file, the audit chain head; signed by the engine key (manifest.sig)
  integrity.json     audit-log verification result (sequence, hash chain, every signature)
  activity.json      decisions by verdict and stage, approvals, denials, freezes/unfreezes, promotions (failovers)
  approvals.csv      who approved what for whom, and when (CC6.2/CC6.3: access is authorised by someone else)
  freezes.csv        every freeze and unfreeze with its reason and operator (CC7.4: incident response)
  failovers.csv      every promotion (A1.2: availability events)
  access_review.csv  every identity in the policy: kind, allowed actions, approver flag, frozen (CC6.2 review)
  config.json        sha256 of the policy, model and callers files and the policy version (CC8.1: change control)

Nothing in it is new evidence: every line comes from signed records, and an auditor can re-check the bundle
with `authority evidence-verify bundle.zip --public-key authority.pub.pem`.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .audit import iter_records, verify_log
from .crypto import b64d, b64e


def _ts(s: str | None, default: float) -> float:
    if not s:
        return default
    return datetime.fromisoformat(s).replace(tzinfo=datetime.fromisoformat(s).tzinfo or timezone.utc).timestamp()


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")


def _csv(rows: list[dict], cols: list[str]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode()


def _sha(p: str | Path | None) -> str | None:
    if not p or not Path(p).exists():
        return None
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def build(state: str, policy_path: str, signer, since: str | None = None, until: str | None = None,
          model: str | None = None, callers: str | None = None) -> bytes:
    log = Path(state) / "audit.jsonl"
    t0, t1 = _ts(since, 0.0), _ts(until, time.time())
    ok, msg = verify_log(log, signer.public_key)
    counts: Counter = Counter()
    approvals, freezes, failovers = [], [], []
    frozen: set[str] = set()
    head = (0, "")
    for rec in iter_records(log):
        head = (rec["seq"], rec["hash"])
        ev = rec["event"]
        kind = ev.get("type")
        if kind == "freeze":
            frozen.add(ev.get("identity"))
        elif kind == "unfreeze":
            frozen.discard(ev.get("identity"))
        if not t0 <= rec["ts"] < t1:
            continue
        when = _iso(rec["ts"])
        if kind == "decision":
            counts[f"decision|{ev.get('verdict')}|{ev.get('stage')}"] += 1
        else:
            counts[kind] += 1
        if kind == "approval":
            approvals.append({"time": when, "seq": rec["seq"], "approver": ev.get("approver"),
                              "requester": ev.get("requester"), "approval_id": ev.get("approval_id"),
                              "fingerprint": ev.get("fingerprint"), "reason": ev.get("reason")})
        elif kind in ("freeze", "unfreeze"):
            freezes.append({"time": when, "seq": rec["seq"], "event": kind, "identity": ev.get("identity"),
                            "reason": ev.get("reason", ""), "operator": ev.get("operator", "")})
        elif kind == "promotion":
            failovers.append({"time": when, "seq": rec["seq"], "epoch": ev.get("epoch"), "reason": ev.get("reason"),
                              "floor_seq": ev.get("floor_seq", "")})
    pol = json.loads(Path(policy_path).read_text())
    review = [{"identity": who, "kind": r.get("kind", ""), "allowed_actions": " ".join(r.get("allowed_actions", [])),
               "approver": bool(r.get("approver")), "frozen": who in frozen}
              for who, r in sorted(pol.get("identities", {}).items())]
    decisions = {k.split("|", 1)[1]: v for k, v in counts.items() if k.startswith("decision|")}
    files = {
        "integrity.json": json.dumps({"ok": ok, "detail": msg, "head_seq": head[0], "head_hash": head[1]}, indent=1).encode(),
        "activity.json": json.dumps({"decisions_by_verdict_and_stage": decisions,
                                     "other_records": {k: v for k, v in counts.items() if not k.startswith("decision|")}},
                                    indent=1, sort_keys=True).encode(),
        "approvals.csv": _csv(approvals, ["time", "seq", "approver", "requester", "approval_id", "fingerprint", "reason"]),
        "freezes.csv": _csv(freezes, ["time", "seq", "event", "identity", "reason", "operator"]),
        "failovers.csv": _csv(failovers, ["time", "seq", "epoch", "reason", "floor_seq"]),
        "access_review.csv": _csv(review, ["identity", "kind", "allowed_actions", "approver", "frozen"]),
        "config.json": json.dumps({"policy_version": pol.get("version"), "policy_sha256": _sha(policy_path),
                                   "model_sha256": _sha(model), "callers_sha256": _sha(callers)}, indent=1).encode(),
    }
    manifest = {"format": "mastyf-evidence/1", "generated": _iso(time.time()), "period": [_iso(t0), _iso(t1)],
                "audit_head": {"seq": head[0], "hash": head[1]}, "audit_verified": ok,
                "files": {n: hashlib.sha256(b).hexdigest() for n, b in sorted(files.items())}}
    mbytes = json.dumps(manifest, indent=1, sort_keys=True).encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in files.items():
            z.writestr(n, b)
        z.writestr("manifest.json", mbytes)
        z.writestr("manifest.sig", b64e(signer.sign(b"mastyf-evidence|" + mbytes)))
    return out.getvalue()


def verify(bundle: bytes, public_key) -> tuple[bool, str]:
    with zipfile.ZipFile(io.BytesIO(bundle)) as z:
        mbytes = z.read("manifest.json")
        try:
            public_key.verify(b64d(z.read("manifest.sig").decode()), b"mastyf-evidence|" + mbytes)
        except Exception:  # noqa: BLE001
            return False, "manifest signature does not verify"
        m = json.loads(mbytes)
        names = set(z.namelist()) - {"manifest.json", "manifest.sig"}
        if names != set(m["files"]):
            return False, "files differ from the manifest"
        for n, h in m["files"].items():
            if hashlib.sha256(z.read(n)).hexdigest() != h:
                return False, f"{n} was changed after signing"
    return True, f"signed manifest and {len(names)} files verify; audit head {m['audit_head']['seq']}"

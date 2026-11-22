"""Signed state snapshots, so a restart loads one file plus the audit records written after it instead
of replaying the whole history.

A snapshot holds everything `Authority.restore` rebuilds from the audit log (behaviour baselines, novelty
counts, rolling 24 h volumes, recent denials, frozen identities, approvals, pending requests, learned
destinations, integrity reports, the reviewer queue) plus the audit position it covers: the sequence
number and hash of the last record already reflected in it.

Trust: the file is JSON only (nothing in it can run code) and is signed with the authority's own key
over SHA-256 of its canonical form. A snapshot whose signature fails, whose audit position does not
exist in the log, or whose hash does not match that record is refused, and the engine falls back to a
full replay. Writes are atomic (temp file, fsync, rename, fsync directory), so a crash mid-write
leaves the previous snapshot in place.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from collections import defaultdict, deque
from pathlib import Path

from .crypto import b64d, b64e, verify
from .features import Profile

FORMAT = 3  # 2: the 24 h feature window as per-minute buckets; 3: known networks per identity
SEP = "\x1f"  # joins tuple keys; cannot appear in identities, action types or destinations from JSON callers


class FormatChanged(Exception):
    """An older snapshot format after an upgrade: ignore it and replay the audit log (not tampering)."""


def _k(t: tuple) -> str:
    return SEP.join(str(x) for x in t)


def _t(s: str, n: int = 2) -> tuple:
    return tuple(s.split(SEP, n - 1))


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ------------------------------------------------------------------ state <-> JSON
def dump(auth, now: float) -> dict:
    st, nv = auth.state, auth.novelty
    profiles = {}
    for ident, p in st.profiles.items():
        profiles[ident] = {"n": p.n, "first_ts": p.first_ts, "logc": {t: list(d) for t, d in p.logc.items()},
                           "prefix_seen": p.prefix_seen, "dest_seen": p.dest_seen, "type_seen": p.type_seen,
                           "hours": p.hours}
    rng_state = nv.rng.getstate()
    novelty = {
        "seen": {k: sorted(v) for k, v in nv.seen.items()}, "org": {k: sorted(v) for k, v in nv.org.items()},
        "first": nv.first, "n_actions": dict(nv.n_actions),
        "day_vol": {_k(k): list(v) for k, v in nv.day_vol.items()},
        "max_vol": {_k(k): v for k, v in nv.max_vol.items()},
        "slow": {k: list(v) for k, v in nv.slow.items()}, "decay": nv.decay, "sample": nv.sample,
        "n_sampled": nv.n_sampled, "scale": nv.scale, "rng": [rng_state[0], list(rng_state[1]), rng_state[2]],
    }
    daily = {}
    for k, dq in auth.daily.items():
        keep = [[ts, c] for ts, c in dq if ts >= now - 86400]
        if keep:
            daily[_k(k)] = keep
    return {
        "profiles": profiles, "windows": st.windows_json(), "novelty": novelty, "daily": daily,
        "denials": {k: [t for t in dq if t >= now - 3600] for k, dq in auth.denials.items() if dq},
        "frozen": auth.frozen, "integrity": auth.integrity, "approvals": auth.approvals, "pending": auth.pending,
        "learned_destinations": {_k(k): v for k, v in auth.learned_destinations.items()},
        "review": {str(day): {i: [sc, why] for i, (sc, why) in d.items()} for day, d in auth.review.days.items()},
        "counts": dict(auth.counts),
        "epoch": auth.issuer.epoch,
        "risk_hist": {k: list(v) for k, v in auth.risk_hist.items() if v},
        "origins": auth.origins.to_json(),
    }


def load(auth, d: dict) -> None:
    st, nv = auth.state, auth.novelty
    st.profiles.clear()
    for ident, p in d["profiles"].items():
        pr = Profile(p["first_ts"])
        pr.n = p["n"]
        for t, vals in p["logc"].items():
            pr.logc[t].extend(vals)
        pr.prefix_seen, pr.dest_seen, pr.type_seen = p["prefix_seen"], p["dest_seen"], p["type_seen"]
        pr.hours = list(p["hours"])
        st.profiles[ident] = pr
    st.load_windows(d["windows"])
    n = d["novelty"]
    nv.seen = defaultdict(set, {k: set(v) for k, v in n["seen"].items()})
    nv.org = defaultdict(set, {k: set(v) for k, v in n["org"].items()})
    nv.first = dict(n["first"])
    nv.n_actions = defaultdict(int, n["n_actions"])
    nv.day_vol = {_t(k): tuple(v) for k, v in n["day_vol"].items()}
    nv.max_vol = defaultdict(int, {_t(k): v for k, v in n["max_vol"].items()})
    nv.slow = {k: tuple(v) for k, v in n["slow"].items()}
    nv.decay, nv.sample, nv.n_sampled, nv.scale = n["decay"], list(n["sample"]), n["n_sampled"], n["scale"]
    nv.rng = random.Random()
    nv.rng.setstate((n["rng"][0], tuple(n["rng"][1]), n["rng"][2]))
    auth.daily.clear()
    for k, v in d["daily"].items():
        auth.daily[_t(k)] = deque((ts, c) for ts, c in v)
    auth.denials.clear()
    for k, v in d["denials"].items():
        auth.denials[k] = deque(v)
    auth.frozen.clear()
    auth.frozen.update(d["frozen"])
    auth.integrity.clear()
    auth.integrity.update(d["integrity"])
    auth.approvals.clear()
    auth.approvals.update(d["approvals"])
    auth.pending.clear()
    auth.pending.update(d["pending"])
    auth.origins.load(d.get("origins", {}))
    auth.learned_destinations.clear()
    auth.learned_destinations.update({_t(k): v for k, v in d["learned_destinations"].items()})
    auth.review.days.clear()
    for day, entries in d["review"].items():
        auth.review.days[int(day)] = {i: (sc, why) for i, (sc, why) in entries.items()}
    auth.counts.clear()
    auth.counts.update(d["counts"])
    auth.issuer.epoch = max(auth.issuer.epoch, int(d.get("epoch", 0)))
    auth.risk_hist.clear()
    for k, v in d.get("risk_hist", {}).items():
        auth.risk_hist[k].extend(v)


# ------------------------------------------------------------------ signed file
def write(path: Path, auth, signer, seq: int, head: str, now: float) -> dict:
    """Atomically writes the signed snapshot; returns {seq, sha256, bytes}. Call with the engine lock held,
    so the state and the audit position agree."""
    path = Path(path)
    body = {"format": FORMAT, "seq": seq, "head": head, "ts": now, "state": dump(auth, now)}
    raw = _canon(body)
    digest = hashlib.sha256(raw).hexdigest()
    doc = {"sha256": digest, "sig": b64e(signer.sign(digest.encode())), "body": body}
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(json.dumps(doc, separators=(",", ":")).encode())
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return {"seq": seq, "sha256": digest, "bytes": len(raw)}


def read(path: Path, public_key) -> dict | None:
    """The verified snapshot body, or None if there is none. Raises ValueError if it was altered."""
    path = Path(path)
    if not path.exists():
        return None
    doc = json.loads(path.read_bytes())
    body = doc.get("body")
    if not isinstance(body, dict):
        raise ValueError("snapshot not recognised")
    if body.get("format") != FORMAT:
        raise FormatChanged(f"snapshot format {body.get('format')} (this version writes {FORMAT})")
    digest = hashlib.sha256(_canon(body)).hexdigest()
    if digest != doc.get("sha256") or not verify(public_key, b64d(doc.get("sig", "")), digest.encode()):
        raise ValueError("snapshot signature does not verify")
    return body

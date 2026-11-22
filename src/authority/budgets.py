"""Bounded-loss data budgets, enforced at key release.

Every sensitive record is encrypted with its own data key (DEK). DEKs are stored only
wrapped by the key service's key-encryption key (KEK). A stolen database or disk is
ciphertext. To read records, a caller must get their DEKs released, and every release
is debited from a rolling 24-hour budget for (identity, data class).

The key service is a separate trust domain from the authority:
  - it verifies the authority's grant with the authority's PUBLIC key only;
  - it keeps its own ledger;
  - going over budget needs signatures from `overrun_signatures` distinct human approvers,
    verified here with the approvers' own public keys, never by the authority.

Guarantee: with full control of one identity AND of the authority, an attacker can read
at most that identity's budget per 24 h per data class (0 where the budget is 0), unless
`overrun_signatures` approvers sign. The behavioural model can only shrink budgets
(through a signed `budget_factor` in the grant), never raise them.

Scope: this bounds *reading* (confidentiality). It does not bound deletion, encryption
by ransomware, or code changes; those rely on the other layers and on immutable backups.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .actions import Action
from .crypto import b64d, b64e, verify
from .binding import approver_signed, wrap_to_device
from .features import DAY, dest_key
from .grants import GrantError, GrantVerifier
from fnmatch import fnmatchcase

from .policy import matches

NOVELTY_WINDOW = 30 * DAY
READ_ACTIONS = frozenset({"data.read", "data.export", "secret.read"})


@dataclass
class BudgetPolicy:
    classes: dict[str, list[str]]  # data class -> resource patterns (first match wins, in order)
    budgets: dict[str, dict[str, int]]  # identity -> class -> records per 24 h
    overrun_signatures: int = 2
    # identity -> class -> {"new_per_day": int, "distinct_30d": int}
    # "new" = a record this identity has not been given in the last 30 days
    novelty: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)
    # record ids that are bait: fake records no legitimate screen ever shows (patterns, fnmatch)
    canary_records: list[str] = field(default_factory=list)
    # identities (patterns) whose key releases need a registered-device signature
    device_bound: list[str] = field(default_factory=list)
    # identity -> classes whose records must be on the requester's active cases
    purpose_bound: dict[str, list[str]] = field(default_factory=dict)
    # identity -> class -> most records approvers may add on top of the budget per 24 h. When the
    # policy has this section, a missing entry means 0 (no overruns); without it overruns are
    # unlimited and the damage ceiling (ceiling.py) reports "unbounded if approvers are compromised".
    overrun_max: dict[str, dict[str, int]] | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "BudgetPolicy":
        return cls(d["classes"], d["budgets"], int(d.get("overrun_signatures", 2)), d.get("novelty", {}),
                   list(d.get("canary_records", [])), list(d.get("device_bound", [])), d.get("purpose_bound", {}),
                   d.get("overrun_max"))

    def overrun_cap(self, identity: str, data_class: str) -> int | None:
        if self.overrun_max is None:
            return None
        return int(self.overrun_max.get(identity, {}).get(data_class, 0))

    def novelty_for(self, identity: str, data_class: str) -> dict | None:
        return self.novelty.get(identity, {}).get(data_class)

    def classify(self, resource: str) -> str | None:
        for name, pats in self.classes.items():
            if matches(resource, pats):
                return name
        return None

    def budget(self, identity: str, data_class: str, destination: str | None = None) -> tuple[str, int]:
        """Returns (ledger key, records per 24 h). Reads with no destination use the plain class
        budget. Exports use a budget bound to the destination ("class@dest-pattern"); a destination
        with no entry gets 0. Unlisted = 0."""
        entries = self.budgets.get(identity, {})
        if destination:
            dk = dest_key(destination)
            for k, v in entries.items():
                c, sep, pat = k.partition("@")
                if sep and c == data_class and fnmatchcase(dk, pat):
                    return k, int(v)
            return f"{data_class}@{dk}", 0
        return data_class, int(entries.get(data_class, 0))


@dataclass
class Release:
    ok: bool
    reason: str
    data_class: str | None = None
    released: int = 0
    remaining: int | None = None
    shortfall: int = 0
    keys: dict[str, bytes] | None = None


def overrun_message(grant_id: str, amount: int) -> bytes:
    return f"mastyf-overrun|{grant_id}|{amount}".encode()


class KeyService:
    def __init__(self, policy: BudgetPolicy, authority_public_key, approver_keys: dict, now=time.time,
                 kek: bytes | None = None, verifier=None, custody: bool = True, canary_ids: set | None = None,
                 devices=None, cases=None, approver_devices=None):
        self.policy = policy
        self.approver_devices = approver_devices  # binding.DeviceRegistry of approvers' passkeys
        self.devices = devices  # binding.DeviceRegistry
        self.cases = cases  # binding.CaseRegistry
        self.canary_ids = canary_ids or set()  # explicit bait ids, in addition to policy patterns
        self.frozen: dict[str, str] = {}  # identity -> reason; frozen identities get nothing
        # custody=False: budget accounting only, no per-record keys held (simulations)
        self.custody = custody
        # verifier: a QuorumVerifier to require grants from t of n authority nodes
        self.verifier = verifier or GrantVerifier(authority_public_key, now=now)
        self.approver_keys = approver_keys  # name -> Ed25519 public key
        self.now = now
        self._kek = AESGCM(kek or AESGCM.generate_key(bit_length=256))
        self._wrapped: dict[str, tuple[str, bytes]] = {}  # record id -> (data class, wrapped DEK)
        self.ledger: dict[tuple[str, str], deque] = defaultdict(deque)
        self.seen: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)  # record id -> last released
        self.new_ledger: dict[tuple[str, str], deque] = defaultdict(deque)  # (t, new records)
        self._lock = threading.Lock()

    # ---- key custody ------------------------------------------------------
    def new_record_key(self, record_id: str, data_class: str) -> bytes:
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        self._wrapped[record_id] = (data_class, nonce + self._kek.encrypt(nonce, dek, record_id.encode()))
        return dek

    def _unwrap(self, record_id: str) -> bytes:
        _, blob = self._wrapped[record_id]
        return self._kek.decrypt(blob[:12], blob[12:], record_id.encode())

    def unfreeze(self, identity: str, until: int, sigs: list[dict]) -> tuple[bool, str]:
        """Same rule as the Rust service: `overrun_signatures` distinct approvers (not the identity)
        sign "mastyf-unfreeze|<identity>|<until>", until at most one hour ahead."""
        t = self.now()
        if until < t or until > t + 3600:
            return False, "unfreeze approval expired or too far in the future"
        msg = f"mastyf-unfreeze|{identity}|{until}".encode()
        ok = set()
        for s_ in sigs or []:
            name = approver_signed(self.approver_keys, self.approver_devices, s_, msg)
            if name is not None and name != identity:
                ok.add(name)
        if len(ok) < self.policy.overrun_signatures:
            return False, f"unfreeze needs {self.policy.overrun_signatures} approver signatures"
        with self._lock:
            self.frozen.pop(identity, None)
        return True, "ok"

    # ---- budget -----------------------------------------------------------
    def used(self, identity: str, key: str, ts: float) -> int:
        dq = self.ledger[(identity, key)]
        while dq and dq[0][0] <= ts - DAY:
            dq.popleft()
        return sum(n for _, n in dq)

    def _overrun_amount(self, gid: str, requester: str, sigs: list[dict] | None) -> int:
        """Record count approved for this grant by enough distinct approvers (never the requester).
        All signatures must name the same amount."""
        if not sigs:
            return 0
        signers, amounts = set(), set()
        for s in sigs:
            name, amount = s.get("approver"), s.get("amount")
            if name == requester or not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
                continue
            if approver_signed(self.approver_keys, self.approver_devices, s, overrun_message(gid, amount)) == name:
                signers.add(name)
                amounts.add(amount)
        if len(signers) >= self.policy.overrun_signatures and len(amounts) == 1:
            return amounts.pop()
        return 0

    def release(self, grant: str, action: Action, overrun: list[dict] | None = None) -> Release:
        if action.action_type not in READ_ACTIONS:
            return Release(False, f"{action.action_type} does not release data keys")
        cls = self.policy.classify(action.resource)
        if cls is None:
            return Release(False, "resource has no data class: refusing (fail closed)")
        with self._lock:
            if action.identity in self.frozen:
                return Release(False, f"identity frozen: {self.frozen[action.identity]}", cls)
            try:
                payload = self.verifier.verify(grant, action)
            except GrantError as e:
                return Release(False, f"grant rejected: {e}", cls)
            ids0 = action.metadata.get("record_ids")
            if isinstance(ids0, list):
                bait = next((r for r in ids0 if isinstance(r, str) and (r in self.canary_ids or
                             matches(r, self.policy.canary_records))), None)
                if bait is not None:
                    self.frozen[action.identity] = f"requested bait record {bait}"
                    return Release(False, "canary: bait record requested; identity frozen", cls)
            device_kex = None
            if matches(action.identity, self.policy.device_bound):
                device_kex, why = self.devices.check(action.identity, action.metadata.get("device_id"),
                                                     action.metadata.get("device_proof"), payload["gid"],
                                                     action.fingerprint()) if self.devices else (None, "no registry")
                if device_kex is None:
                    if "cloned" in why:
                        self.frozen[action.identity] = why
                    return Release(False, f"device: {why}", cls)
            outside_n = 0
            if cls in self.policy.purpose_bound.get(action.identity, []):
                ids_p = [] if ids0 is None else ids0
                if self.cases is None or not isinstance(ids_p, list) or len(ids_p) != action.count:
                    return Release(False, "need-to-know: record ids on assigned cases required", cls)
                ok, why, outside_n = self.cases.check(action.identity, ids_p)
                if not ok:
                    return Release(False, why, cls)
            factor = payload.get("con", {}).get("budget_factor", 1.0)
            factor = min(1.0, max(0.0, float(factor)))  # can only shrink
            key, base = self.policy.budget(action.identity, cls, action.destination)
            allowance = int(base * factor)
            approved = self._overrun_amount(payload["gid"], action.identity, overrun)
            t = self.now()  # never the caller-supplied timestamp
            used = self.used(action.identity, key, t)
            # an overrun signed by enough approvers for at least this action's count releases it
            # regardless of the remaining budget; it is still debited to the ledger
            over_budget = used + action.count > allowance
            if approved < action.count and over_budget:
                return Release(False, f"budget: {key} {used}+{action.count} > {allowance} per 24h for {action.identity}",
                               cls, 0, max(0, allowance - used), shortfall=used + action.count - allowance)
            ids = action.metadata.get("record_ids")
            nov = self.policy.novelty_for(action.identity, cls)
            new_ids: list[str] = []
            if nov:
                ids = [] if ids is None else ids
                if not isinstance(ids, list) or len(ids) != action.count or not all(isinstance(r, str) for r in ids):
                    return Release(False, "novelty budget: record ids required for every record", cls)
                k = (action.identity, cls)
                seen = self.seen[k]
                cutoff = t - NOVELTY_WINDOW
                for rid in [r for r, ts in seen.items() if ts <= cutoff]:
                    del seen[rid]
                new_ids = [r for r in dict.fromkeys(ids) if r not in seen]
                nq = self.new_ledger[k]
                while nq and nq[0][0] <= t - DAY:
                    nq.popleft()
                new_today = sum(n for _, n in nq)
                over_day = new_today + len(new_ids) > nov.get("new_per_day", 0)
                over_window = len(seen) + len(new_ids) > nov.get("distinct_30d", 0)
                over_budget = over_budget or over_day or over_window
                if approved < action.count and (over_day or over_window):
                    what = (f"{new_today}+{len(new_ids)} new records > {nov.get('new_per_day', 0)} per 24h" if over_day
                            else f"{len(seen)}+{len(new_ids)} distinct records > {nov.get('distinct_30d', 0)} per 30 days")
                    return Release(False, f"novelty: {what} for {action.identity}", cls, 0, max(0, allowance - used))
            con = payload.get("con", {})
            sess = con.get("sess")
            if sess is not None:  # AI agent session: total records the person approved, across classes
                cap = int(con.get("sess_max", 0))
                su = self.used(action.identity, f"sess:{sess}", t)
                if su + action.count > cap:
                    return Release(False, f"agent session cap: {su}+{action.count} > {cap} records", cls, 0,
                                   max(0, allowance - used))
            overrun_key = f"overrun:{cls}"
            if approved >= action.count and over_budget:
                cap = self.policy.overrun_cap(action.identity, cls)
                if cap is not None:
                    ou = self.used(action.identity, overrun_key, t)
                    if ou + action.count > cap:
                        return Release(False, f"overrun cap: {ou}+{action.count} > {cap} per 24h for {action.identity}",
                                       cls, 0, max(0, allowance - used))
            else:
                overrun_key = None
            keys = None
            if ids and self.custody:
                if len(ids) > action.count:
                    return Release(False, "more record ids than the granted count", cls)
                keys = {}
                for rid in ids:
                    if rid not in self._wrapped or self._wrapped[rid][0] != cls:
                        return Release(False, f"record {rid} not in class {cls}", cls)
                    dek = self._unwrap(rid)
                    # device-bound: the record key is sent encrypted to the device, never in the clear
                    keys[rid] = wrap_to_device(dek, device_kex, rid) if device_kex is not None else dek
            self.ledger[(action.identity, key)].append((t, action.count))
            if overrun_key:
                self.ledger[(action.identity, overrun_key)].append((t, action.count))
            if sess is not None:
                self.ledger[(action.identity, f"sess:{sess}")].append((t, action.count))
            if outside_n and self.cases is not None:
                self.cases.commit_outside(action.identity, outside_n)
            if nov:
                seen = self.seen[(action.identity, cls)]
                for rid in ids:
                    seen[rid] = t
                self.new_ledger[(action.identity, cls)].append((t, len(new_ids)))
            return Release(True, "released", cls, action.count, max(0, allowance - used - action.count), keys=keys)


class EncryptedStore:
    """A table whose rows are each encrypted under their own key held by the KeyService."""

    def __init__(self, keys: KeyService, data_class: str):
        self.keys = keys
        self.cls = data_class
        self.rows: dict[str, bytes] = {}

    def put(self, record_id: str, plaintext: bytes) -> None:
        dek = self.keys.new_record_key(record_id, self.cls)
        nonce = os.urandom(12)
        self.rows[record_id] = nonce + AESGCM(dek).encrypt(nonce, plaintext, record_id.encode())

    def dump(self) -> dict[str, str]:
        """What an attacker with full database access gets."""
        return {k: b64e(v) for k, v in self.rows.items()}

    @staticmethod
    def open(record_id: str, blob: bytes, dek: bytes) -> bytes:
        return AESGCM(dek).decrypt(blob[:12], blob[12:], record_id.encode())

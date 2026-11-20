"""Device enrolment: how a person adds a laptop or phone (passkey + device encryption key).

The weak point of device binding is enrolment: if a stolen password could register the attacker's
own laptop, binding would be worthless. So adding a device needs ONE of:
  * a user-verified signature from a device this person already has registered, or
  * signatures from two approvers (new starter, lost device), each over the exact request.
Every enrolment and removal is written to the audit log and raised as an alert to the person.

Flow (the web page at /enroll drives it):
  begin(identity)                  -> request id, message to authorise, expiry
  authorise(rid, ...)              -> existing-device proof, or approver signatures (passkey or Ed25519)
  finish(rid, attestation, cd, kex)-> passkey registration whose challenge binds the device's X25519 key
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from .binding import DeviceRegistry
from .crypto import b64d, b64e, verify
from .webauthn import verify_registration

TTL = 15 * 60
MAX_DEVICES = 5


def enroll_message(rid: str, identity: str, exp: int) -> bytes:
    return f"mastyf-enroll|{rid}|{identity}|{exp}".encode()


def registration_challenge(rid: str, identity: str, exp: int, kex_public: bytes) -> bytes:
    return hashlib.sha256(enroll_message(rid, identity, exp) + b"|" + kex_public).digest()


class Enrollment:
    def __init__(self, registry: DeviceRegistry, approver_keys: dict | None = None, approvers_needed: int = 2,
                 audit=None, alert=None, save_path=None, now=time.time, is_approver=None):
        self.reg = registry
        self.approver_keys = approver_keys or {}  # Ed25519 keys (CLI approvers)
        self.approvers_needed = approvers_needed
        self.audit = audit  # callable(dict)
        self.alert = alert  # callable(identity, text)
        self.save_path = save_path
        self.now = now
        self.is_approver = is_approver or (lambda name: name in self.approver_keys)
        self.requests: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _log(self, ev: dict) -> None:
        if self.audit:
            self.audit(ev)

    def _get(self, rid: str) -> dict:
        r = self.requests.get(rid)
        if r is None or r["exp"] < self.now():
            raise PermissionError("unknown or expired enrolment request")
        return r

    def begin(self, identity: str) -> dict:
        with self._lock:
            if len(self.reg.devices.get(identity, {})) >= MAX_DEVICES:
                raise PermissionError(f"{identity} already has {MAX_DEVICES} devices; remove one first")
            rid = secrets.token_urlsafe(12)
            exp = int(self.now() + TTL)
            self.requests[rid] = {"rid": rid, "identity": identity, "exp": exp, "authorised_by": None,
                                  "approvals": set()}
            self._log({"type": "enroll_begin", "identity": identity, "rid": rid})
            return {"rid": rid, "identity": identity, "exp": exp, "rp_id": self.reg.rp_id,
                    "challenge": b64e(hashlib.sha256(enroll_message(rid, identity, exp)).digest()),
                    "has_devices": bool(self.reg.devices.get(identity)),
                    "allow": [{"device": d, "cred_id": b64e(self.reg.cred_ids[(identity, d)])}
                              for d in self.reg.devices.get(identity, {}) if (identity, d) in self.reg.cred_ids]}

    def status(self, rid: str, identity: str) -> dict:
        r = self._get(rid)
        if r["identity"] != identity:
            raise PermissionError("not your enrolment request")
        return {"rid": rid, "authorised": bool(r["authorised_by"]), "approvals": sorted(r["approvals"]),
                "needed": self.approvers_needed}

    def owner(self, rid: str) -> str:
        return self._get(rid)["identity"]

    def pending(self) -> list[dict]:
        t = self.now()
        return [{"rid": r["rid"], "identity": r["identity"], "exp": r["exp"], "approvals": sorted(r["approvals"]),
                 "challenge": b64e(hashlib.sha256(enroll_message(r["rid"], r["identity"], r["exp"])).digest())}
                for r in self.requests.values() if r["exp"] >= t and not r["authorised_by"]]

    def authorise_with_device(self, rid: str, device_id: str, proof: str) -> str:
        with self._lock:
            r = self._get(rid)
            chal = hashlib.sha256(enroll_message(rid, r["identity"], r["exp"])).digest()
            ok, why = self.reg.verify_for(r["identity"], device_id, proof, chal)
            if not ok:
                raise PermissionError(f"existing device did not authorise: {why}")
            r["authorised_by"] = f"device:{device_id}"
            self._log({"type": "enroll_authorised", "identity": r["identity"], "rid": rid, "by": r["authorised_by"]})
            return "authorised"

    def approve(self, rid: str, approver: str, proof: str = "", device_id: str = "", signature: str = "") -> str:
        """One approver's signature: a passkey assertion from the approver's own registered device, or an
        Ed25519 signature from the approver CLI key."""
        with self._lock:
            r = self._get(rid)
            if approver == r["identity"]:
                raise PermissionError("you cannot approve your own device")
            if not self.is_approver(approver):
                raise PermissionError(f"{approver} is not an approver")
            msg = enroll_message(rid, r["identity"], r["exp"])
            if proof:
                ok, why = self.reg.verify_for(approver, device_id, proof, hashlib.sha256(msg).digest())
            else:
                pk = self.approver_keys.get(approver)
                try:
                    ok, why = (pk is not None and verify(pk, b64d(signature), msg)), "bad approver signature"
                except Exception:  # noqa: BLE001
                    ok, why = False, "bad approver signature"
            if not ok:
                raise PermissionError(why)
            r["approvals"].add(approver)
            self._log({"type": "enroll_approval", "identity": r["identity"], "rid": rid, "approver": approver})
            if len(r["approvals"]) >= self.approvers_needed:
                r["authorised_by"] = "approvers:" + ",".join(sorted(r["approvals"]))
                return "authorised"
            return f"{len(r['approvals'])} of {self.approvers_needed} approvals"

    def finish(self, rid: str, device_id: str, attestation_object: bytes, client_data_json: bytes,
               kex_public: bytes) -> dict:
        with self._lock:
            r = self._get(rid)
            if not r["authorised_by"]:
                raise PermissionError("not authorised yet: confirm on an existing device, or get two approvals")
            if len(kex_public) != 32:
                raise ValueError("device encryption key must be 32 bytes (X25519)")
            if not device_id or len(device_id) > 64 or not device_id.replace("-", "").replace("_", "").isalnum():
                raise ValueError("device name: letters, digits, - and _ only (max 64)")
            if device_id in self.reg.devices.get(r["identity"], {}):
                raise ValueError("a device with that name is already registered")
            chal = registration_challenge(rid, r["identity"], r["exp"], kex_public)
            cred = verify_registration(attestation_object, client_data_json, chal, self.reg.rp_id, self.reg.origin,
                                       require_uv=self.reg.require_user_verified)
            self.reg.register(r["identity"], device_id, cred["public_key"], X25519PublicKey.from_public_bytes(kex_public),
                              cred["alg"], cred["cred_id"])
            self.reg.counters[(r["identity"], device_id)] = cred["sign_count"]
            del self.requests[rid]
            if self.save_path:
                self.reg.save(self.save_path)
            self._log({"type": "device_enrolled", "identity": r["identity"], "device": device_id,
                       "authorised_by": r["authorised_by"]})
            if self.alert:
                self.alert(r["identity"], f"new device '{device_id}' added (authorised by {r['authorised_by']}). "
                                          f"If this was not you, report it now.")
            return {"identity": r["identity"], "device": device_id, "alg": cred["alg"]}

    def remove(self, identity: str, device_id: str, by: str) -> bool:
        with self._lock:
            ok = self.reg.revoke(identity, device_id)
            if ok and self.save_path:
                self.reg.save(self.save_path)
            self._log({"type": "device_removed", "identity": identity, "device": device_id, "by": by})
            if ok and self.alert:
                self.alert(identity, f"device '{device_id}' removed by {by}")
            return ok

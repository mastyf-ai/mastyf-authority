//! Device binding (WebAuthn-format assertions, user presence, clone detection), need-to-know case
//! binding, and key wrapping to a device. Port of `authority/binding.py`.

use std::collections::{HashMap, HashSet, VecDeque};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::Verifier as _;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{b64d_pub as b64d, py_json_str, DAY};

pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;

pub fn challenge(gid: &str, fingerprint: &str) -> [u8; 32] {
    Sha256::digest(format!("mastyf-device|{gid}|{fingerprint}").as_bytes()).into()
}

/// SubjectPublicKeyInfo PEM for a P-256 key -> the 65-byte uncompressed point. Only the exact
/// id-ecPublicKey + prime256v1 SPKI encoding is accepted.
fn p256_point_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("");
    let der = base64::engine::general_purpose::STANDARD.decode(body.trim()).map_err(|_| "bad P-256 PEM")?;
    const PREFIX: [u8; 26] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
                              0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
    if der.len() != 91 || der[..26] != PREFIX || der[26] != 0x04 {
        return Err("not an uncompressed P-256 SubjectPublicKeyInfo".into());
    }
    Ok(der[26..].to_vec())
}

enum SignKey {
    Ed(ed25519_dalek::VerifyingKey),
    /// uncompressed SEC1 point (65 bytes); verified with `ring` (constant-time, audited)
    P256(Vec<u8>),
}

struct Device {
    key: SignKey,
    kex: [u8; 32],
}

pub struct DeviceRegistry {
    rp_hash: [u8; 32],
    require_uv: bool,
    devices: HashMap<String, HashMap<String, Device>>,
    pub counters: HashMap<(String, String), u64>,
    pub cloned: HashSet<(String, String)>,
}

pub enum DeviceCheck {
    Ok { kex: [u8; 32], counter: u64 },
    Refused { why: String, counter: Option<u64> },
    Cloned { why: String },
}

impl DeviceRegistry {
    /// {"rp_id": str, "require_user_verified": bool,
    ///  "devices": {identity: {device_id: {"alg": -7|-8, "sign_pem": PEM, "kex": base64url(32 bytes)}}}}
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let rp = v.get("rp_id").and_then(Value::as_str).ok_or("rp_id required")?;
        let mut devices = HashMap::new();
        for (ident, devs) in v.get("devices").and_then(Value::as_object).ok_or("devices required")? {
            let mut m = HashMap::new();
            for (id, d) in devs.as_object().ok_or("device entries must be objects")? {
                let pem = d.get("sign_pem").and_then(Value::as_str).ok_or("sign_pem required")?;
                let key = match d.get("alg").and_then(Value::as_i64) {
                    Some(EDDSA) => SignKey::Ed(ed25519_dalek::VerifyingKey::from_public_key_pem(pem).map_err(|e| e.to_string())?),
                    Some(ES256) => SignKey::P256(p256_point_from_pem(pem)?),
                    _ => return Err("unsupported device algorithm".into()),
                };
                let kex: [u8; 32] = b64d(d.get("kex").and_then(Value::as_str).ok_or("kex required")?)?
                    .try_into().map_err(|_| "kex must be 32 bytes")?;
                m.insert(id.clone(), Device { key, kex });
            }
            devices.insert(ident.clone(), m);
        }
        Ok(DeviceRegistry {
            rp_hash: Sha256::digest(rp.as_bytes()).into(),
            require_uv: v.get("require_user_verified").and_then(Value::as_bool).unwrap_or(true),
            devices,
            counters: HashMap::new(),
            cloned: HashSet::new(),
        })
    }

    /// Verify a WebAuthn assertion bound to this grant. Mirrors `DeviceRegistry.check` in Python,
    /// including: any genuine signature advances the counter even if policy then refuses.
    pub fn check(&mut self, identity: &str, device_id: Option<&str>, proof: Option<&str>, gid: &str, fp: &str) -> DeviceCheck {
        self.check_challenge(identity, device_id, proof, &challenge(gid, fp))
    }

    /// Same checks for any server challenge (passkey-signed approvals use sha256 of the message).
    pub fn check_challenge(&mut self, identity: &str, device_id: Option<&str>, proof: Option<&str>, chal: &[u8; 32])
                           -> DeviceCheck {
        let no = |w: &str| DeviceCheck::Refused { why: w.into(), counter: None };
        let (Some(device_id), Some(proof)) = (device_id, proof) else { return no("no device proof") };
        let Some(d) = self.devices.get(identity).and_then(|m| m.get(device_id)) else { return no("unknown device") };
        let k = (identity.to_string(), device_id.to_string());
        if self.cloned.contains(&k) {
            return no("device key flagged as cloned");
        }
        let parsed = serde_json::from_str::<Value>(proof).ok().and_then(|p| {
            Some((b64d(p.get("ad")?.as_str()?).ok()?, b64d(p.get("cd")?.as_str()?).ok()?, b64d(p.get("sig")?.as_str()?).ok()?))
        });
        let Some((ad, cd, sig)) = parsed else { return no("malformed device proof") };
        let Ok(client) = serde_json::from_slice::<Value>(&cd) else { return no("client data not JSON") };
        if client.get("type").and_then(Value::as_str) != Some("webauthn.get") {
            return no("not an assertion");
        }
        if client.get("challenge").and_then(Value::as_str) != Some(URL_SAFE_NO_PAD.encode(chal).as_str()) {
            return no("challenge mismatch (assertion is for a different request)");
        }
        if ad.len() < 37 {
            return no("authenticator data too short");
        }
        if ad[..32] != self.rp_hash {
            return no("relying party mismatch");
        }
        let flags = ad[32];
        if flags & 0x01 == 0 {
            return no("user not present");
        }
        let uv = flags & 0x04 != 0;
        let count = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]) as u64;
        let mut msg = ad.clone();
        msg.extend_from_slice(&Sha256::digest(&cd));
        let ok = match &d.key {
            SignKey::Ed(pk) => ed25519_dalek::Signature::from_slice(&sig).map(|s| pk.verify(&msg, &s).is_ok()).unwrap_or(false),
            SignKey::P256(pt) => ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, pt)
                .verify(&msg, &sig).is_ok(),
        };
        if !ok {
            return no("bad signature");
        }
        let last = *self.counters.get(&k).unwrap_or(&0);
        if (count != 0 || last != 0) && count <= last {
            self.cloned.insert(k);
            return DeviceCheck::Cloned { why: "signature counter went backwards: possible cloned device key".into() };
        }
        let kex = d.kex;
        self.counters.insert(k, count);
        if self.require_uv && !uv {
            return DeviceCheck::Refused { why: "user verification (fingerprint/PIN) required".into(), counter: Some(count) };
        }
        DeviceCheck::Ok { kex, counter: count }
    }
}

/// Encrypt a record key so only the device holding the X25519 private key can open it.
/// Format: ephemeral public (32) || nonce (12) || AES-GCM ciphertext; HKDF-SHA256, info
/// "mastyf-dek-wrap|<record id>", AAD = record id. Same as Python `wrap_to_device`.
pub fn wrap_to_device(dek: &[u8], kex: [u8; 32], rid: &str) -> String {
    let eph = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(kex));
    let mut k = [0u8; 32];
    let info = [b"mastyf-dek-wrap|".as_slice(), rid.as_bytes()].concat();
    Hkdf::<Sha256>::new(None, shared.as_bytes()).expand(&info, &mut k).expect("hkdf length");
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = Aes256Gcm::new_from_slice(&k).expect("key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: dek, aad: rid.as_bytes() })
        .expect("encrypt");
    let mut out = eph_pub.as_bytes().to_vec();
    out.extend_from_slice(&nonce);
    out.extend(ct);
    URL_SAFE_NO_PAD.encode(out)
}

// ---------------------------------------------------------------- need-to-know cases

pub struct CaseRegistry {
    pk: ed25519_dalek::VerifyingKey,
    pub allowance: u64,
    assigned: HashMap<String, HashMap<String, (f64, HashSet<String>)>>,
    outside: HashMap<String, VecDeque<(f64, u64)>>,
}

pub fn case_message(case_id: &str, identity: &str, records: &[String], exp: u64) -> Vec<u8> {
    let mut recs: Vec<&String> = records.iter().collect();
    recs.sort();
    let list = recs.iter().map(|r| py_json_str(r)).collect::<Vec<_>>().join(",");
    format!("{{\"case\":{},\"exp\":{exp},\"records\":[{list}],\"to\":{}}}", py_json_str(case_id), py_json_str(identity))
        .into_bytes()
}

impl CaseRegistry {
    pub fn new(pk: ed25519_dalek::VerifyingKey, allowance: u64) -> Self {
        CaseRegistry { pk, allowance, assigned: HashMap::new(), outside: HashMap::new() }
    }

    pub fn assign(&mut self, case_id: &str, identity: &str, records: Vec<String>, exp: u64, sig_b64: &str) -> bool {
        let ok = b64d(sig_b64).ok()
            .and_then(|s| ed25519_dalek::Signature::from_slice(&s).ok())
            .map(|s| self.pk.verify(&case_message(case_id, identity, &records, exp), &s).is_ok())
            .unwrap_or(false);
        if ok {
            self.restore(case_id, identity, records, exp as f64);
        }
        ok
    }

    pub fn restore(&mut self, case_id: &str, identity: &str, records: Vec<String>, exp: f64) {
        self.assigned.entry(identity.into()).or_default().insert(case_id.into(), (exp, records.into_iter().collect()));
    }

    pub fn restore_outside(&mut self, identity: &str, ts: f64, n: u64) {
        self.outside.entry(identity.into()).or_default().push_back((ts, n));
    }

    /// Ok(number of outside-case records) or Err(reason).
    pub fn check(&mut self, identity: &str, ids: &[String], now: f64) -> Result<u64, String> {
        let mut ok_set: HashSet<&String> = HashSet::new();
        if let Some(cases) = self.assigned.get_mut(identity) {
            cases.retain(|_, (exp, _)| *exp > now);
            for (_, recs) in cases.values() {
                ok_set.extend(recs.iter());
            }
        }
        let mut seen = HashSet::new();
        let outside = ids.iter().filter(|r| seen.insert(r.as_str()) && !ok_set.contains(r)).count() as u64;
        let dq = self.outside.entry(identity.into()).or_default();
        while dq.front().is_some_and(|(t, _)| *t <= now - DAY) {
            dq.pop_front();
        }
        let used: u64 = dq.iter().map(|(_, n)| *n).sum();
        if used + outside > self.allowance {
            return Err(format!("need-to-know: {outside} records not on your active cases \
                                ({used} of {} outside-case lookups used today)", self.allowance));
        }
        Ok(outside)
    }

    pub fn commit_outside(&mut self, identity: &str, n: u64, now: f64) {
        if n > 0 {
            self.outside.entry(identity.into()).or_default().push_back((now, n));
        }
    }
}

//! Fuzz entry points with the invariants each one must keep. Shared by the coverage-guided libFuzzer
//! targets (fuzz/, run in CI with nightly) and the stable randomized tests (tests/fuzz_props.rs).
//! Every function must return normally for ANY input; a panic or a failed assertion is a finding.
#![doc(hidden)]

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};

use crate::binding::{DeviceCheck, DeviceRegistry};
use crate::http::{read_request, ReadErr, MAX_BODY};
use crate::{Action, BudgetPolicy, KeyService};

// the data_budgets section of policies/default.json (kept inline so the crate builds on its own)
const BUDGETS: &str = r#"{"classes": {"ssh.key": ["fs://home/*", "vault://prod/ssh/*"], "secret": ["vault://prod/*"], "crm.customer": ["db://crm/customers*"], "prod.files": ["fs://prod/*"], "system.config": ["fs://login-node/*"]}, "budgets": {"human:alice": {"crm.customer": 5000, "crm.customer@s3://corp-reports": 2500}, "human:bob": {"secret": 20, "ssh.key": 100}, "svc:export-job": {"crm.customer@s3://corp-warehouse": 20000}, "svc:backup": {"prod.files": 12000}, "agent:support-bot": {"crm.customer": 1000}}, "overrun_signatures": 2, "overrun_max": {"human:alice": {"crm.customer": 2500}, "human:bob": {"secret": 10, "ssh.key": 50}, "svc:export-job": {"crm.customer": 10000}, "svc:backup": {"prod.files": 6000}}}"#;

fn head_of(data: &[u8]) -> Option<&[u8]> {
    data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| &data[..p + 4])
}

/// The gateway's request reader: never panics; never accepts chunked bodies, duplicate lengths or
/// oversized bodies (the request-smuggling and memory-exhaustion classes).
pub fn http(data: &[u8]) {
    let mut buf = Vec::new();
    let mut cur = Cursor::new(data);
    let mut n = 0;
    while n < 8 {
        n += 1;
        match read_request(&mut cur, &mut buf) {
            Ok(req) => {
                assert!(req.body.len() <= MAX_BODY);
                assert!(!req.method.is_empty());
                let head = head_of(data).expect("a parsed request has a header block");
                let lower = head.to_ascii_lowercase();
                if n == 1 {
                    assert!(!lower.windows(19).any(|w| w == b"\ntransfer-encoding:"),
                            "accepted a request with Transfer-Encoding");
                    let cl = lower.windows(16).filter(|w| *w == b"\ncontent-length:").count();
                    assert!(cl <= 1, "accepted duplicate Content-Length");
                }
            }
            Err(ReadErr::Closed) | Err(ReadErr::Bad(..)) => return,
        }
    }
}

struct Ks {
    ks: KeyService,
}

fn keyservice_fixture() -> &'static Ks {
    static K: OnceLock<Ks> = OnceLock::new();
    K.get_or_init(|| {
        let bp = BudgetPolicy::from_json(&serde_json::from_str::<Value>(BUDGETS).unwrap()).unwrap();
        // the authority's key is one nobody in the fuzzer knows: no grant it produces can be valid
        let authority = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let approver = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        Ks { ks: KeyService::new(bp, authority, HashMap::from([("human:dana".to_string(), approver)])) }
    })
}

/// The key service's release path: never panics, and a grant not signed by the authority never
/// releases a single record, whatever the action, overrun signatures or grant bytes.
pub fn keyservice(data: &[u8]) {
    let ks = &keyservice_fixture().ks;
    let (grant, action, overrun) = match serde_json::from_slice::<Value>(data) {
        Ok(Value::Object(m)) => (
            m.get("grant").and_then(Value::as_str).unwrap_or("").to_string(),
            m.get("action").cloned().unwrap_or(Value::Null),
            m.get("overrun").and_then(Value::as_array).cloned().unwrap_or_default(),
        ),
        _ => {
            let s = String::from_utf8_lossy(data).to_string();
            (s.clone(), json!({"identity": "human:alice", "action_type": "data.read",
                              "resource": "db://crm/customers/1", "count": 5, "ts": 1.0}), vec![])
        }
    };
    let Ok(a) = Action::from_json(&action) else { return };
    let r = ks.release(&grant, &a, &overrun, 1_000_000.0);
    assert!(!r.ok, "released keys for a forged grant");
    assert_eq!(r.released, 0);
    assert!(r.keys.is_none());
}

/// Script-integrity check: never panics and always answers with a verdict, for any previous/candidate
/// pair (split at the first NUL byte) and allowed-host list.
pub fn script_check(data: &[u8]) {
    let (a, b) = match data.iter().position(|&c| c == 0) {
        Some(i) => (Some(String::from_utf8_lossy(&data[..i]).to_string()), String::from_utf8_lossy(&data[i + 1..]).to_string()),
        None => (None, String::from_utf8_lossy(data).to_string()),
    };
    let hosts = vec!["cdn.corp.example".to_string()];
    let v = crate::gates::check(a.as_deref(), &b, &hosts);
    assert!(v.get("verdict").and_then(Value::as_str).is_some(), "no verdict: {v}");
}

fn registry() -> DeviceRegistry {
    let pk: VerifyingKey = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
    let pem = pk.to_public_key_pem(Default::default()).unwrap();
    DeviceRegistry::from_json(&json!({"rp_id": "authority.corp.example", "require_user_verified": true,
        "devices": {"human:dana": {"mbp": {"alg": -8, "sign_pem": pem, "kex": URL_SAFE_NO_PAD.encode([5u8; 32])}}}}))
        .unwrap()
}

/// Passkey (WebAuthn) assertion parsing and checking: never panics and never accepts a proof that was
/// not signed by the registered device key.
pub fn webauthn(data: &[u8]) {
    let mut reg = registry();
    let proof = String::from_utf8_lossy(data);
    let chal = [1u8; 32];
    for dev in [Some("mbp"), Some("other"), None] {
        let r = reg.check_challenge("human:dana", dev, Some(&proof), &chal);
        assert!(!matches!(r, DeviceCheck::Ok { .. }), "accepted a forged passkey assertion");
    }
}

/// Action parsing from arbitrary JSON: never panics.
pub fn action(data: &[u8]) {
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        let _ = Action::from_json(&v);
        let _ = Action::from_json(&json!({"identity": v, "action_type": "data.read", "resource": "x"}));
    }
}

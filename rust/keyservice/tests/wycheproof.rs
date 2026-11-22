//! Project Wycheproof Ed25519 vectors (tests/vectors/, Apache-2.0) against the key service's signature
//! check: "valid" accepted; "invalid" and "acceptable" (weak or mixed-order keys) refused.
use ed25519_dalek::VerifyingKey;
use mastyf_keyservice::verify_sig;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn wycheproof_ed25519() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/wycheproof_ed25519_test.json");
    let d: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let (mut n, mut bad) = (0, vec![]);
    for g in d["testGroups"].as_array().unwrap() {
        let pk: [u8; 32] = hex(g["publicKey"]["pk"].as_str().unwrap()).try_into().unwrap();
        let key = VerifyingKey::from_bytes(&pk);
        for t in g["tests"].as_array().unwrap() {
            n += 1;
            let ok = key.as_ref().map(|k| verify_sig(k, &hex(t["sig"].as_str().unwrap()), &hex(t["msg"].as_str().unwrap())))
                .unwrap_or(false);
            if ok != (t["result"] == "valid") {
                bad.push(t["tcId"].as_u64().unwrap());
            }
        }
    }
    assert_eq!(n, d["numberOfTests"].as_u64().unwrap());
    assert!(bad.is_empty(), "{bad:?}");
}

//! Single sign-on for API callers: OIDC access or ID tokens (JWT) from the company's identity provider
//! (Okta, Microsoft Entra ID, Google, Keycloak, Ping, Auth0) instead of long-lived bearer keys.
//!
//! The gateway checks the token and maps one of its claims to an Authority identity:
//!   - signature: RS256 or ES256 only, with a key from the provider's JWKS (a file the operator refreshes,
//!     re-read when it changes); "none" and shared-secret algorithms are refused;
//!   - issuer must match exactly; audience (aud, or azp) must include a configured one;
//!   - exp / nbf with 60 s leeway;
//!   - identity: the configured claim (default preferred_username) looked up in a map file, or put into a
//!     format such as "human:{}"; a format can never produce admin, replica or gateway (only the map can).
use crate::b64d;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

const LEEWAY: f64 = 60.0;
const MAX_TOKEN: usize = 16 * 1024;

#[derive(Clone)]
enum Key {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ec { point: Vec<u8> },
}

pub struct Oidc {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub claim: String,
    pub map: HashMap<String, String>,
    pub format: Option<String>,
    jwks_path: String,
    keys: Mutex<(HashMap<String, Key>, Option<SystemTime>, Instant)>,
}

fn parse_jwks(v: &Value) -> Result<HashMap<String, Key>, String> {
    let mut out = HashMap::new();
    for k in v["keys"].as_array().ok_or("JWKS: no keys")? {
        if k.get("use").and_then(Value::as_str).is_some_and(|u| u != "sig") {
            continue;
        }
        let kid = k["kid"].as_str().unwrap_or("").to_string();
        let f = |n: &str| k[n].as_str().ok_or(format!("JWKS key {kid}: {n} missing")).and_then(b64d);
        match k["kty"].as_str() {
            Some("RSA") => {
                let n = f("n")?;
                if n.len() < 256 {
                    continue; // RSA below 2048 bits is refused
                }
                let e = f("e")?;
                out.insert(kid.clone(), Key::Rsa { n, e });
            }
            Some("EC") if k["crv"] == "P-256" => {
                let (x, y) = (f("x")?, f("y")?);
                if x.len() != 32 || y.len() != 32 {
                    continue;
                }
                let mut point = vec![4u8];
                point.extend(x);
                point.extend(y);
                out.insert(kid.clone(), Key::Ec { point });
            }
            _ => {}
        }
    }
    if out.is_empty() {
        return Err("JWKS has no usable RS256/ES256 signing keys".into());
    }
    Ok(out)
}

fn safe_identity(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && s.chars().all(|c| c.is_ascii_alphanumeric() || "._@:/+-".contains(c))
}

impl Oidc {
    pub fn new(issuer: String, audiences: Vec<String>, jwks_path: String, claim: Option<String>,
               map: HashMap<String, String>, format: Option<String>) -> Result<Self, String> {
        if audiences.is_empty() {
            return Err("--oidc-audience required".into());
        }
        if let Some(f) = &format {
            if f.matches("{}").count() != 1 {
                return Err("--oidc-identity-format must contain {} once".into());
            }
        }
        let o = Oidc { issuer, audiences, claim: claim.unwrap_or_else(|| "preferred_username".into()), map, format,
                       jwks_path, keys: Mutex::new((HashMap::new(), None, Instant::now() - Duration::from_secs(3600))) };
        o.reload(true)?;
        Ok(o)
    }

    fn reload(&self, force: bool) -> Result<(), String> {
        let mut g = self.keys.lock().unwrap();
        if !force && g.2.elapsed() < Duration::from_secs(10) {
            return Ok(());
        }
        g.2 = Instant::now();
        let mt = std::fs::metadata(&self.jwks_path).and_then(|m| m.modified()).ok();
        if !force && mt == g.1 {
            return Ok(());
        }
        let txt = std::fs::read_to_string(&self.jwks_path).map_err(|e| format!("JWKS {}: {e}", self.jwks_path))?;
        let v: Value = serde_json::from_str(&txt).map_err(|e| format!("JWKS: {e}"))?;
        g.0 = parse_jwks(&v)?;
        g.1 = mt;
        Ok(())
    }

    pub fn looks_like_jwt(token: &str) -> bool {
        token.len() <= MAX_TOKEN && token.matches('.').count() == 2 && token.starts_with("eyJ")
    }

    /// The Authority identity for a valid token, or why it was refused.
    pub fn verify(&self, token: &str, now: f64) -> Result<String, String> {
        if !Self::looks_like_jwt(token) {
            return Err("not a JWT".into());
        }
        let mut parts = token.split('.');
        let (h, p, s) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
        let header: Value = serde_json::from_slice(&b64d(h)?).map_err(|_| "bad JWT header")?;
        let alg = header["alg"].as_str().unwrap_or("");
        let kid = header["kid"].as_str().unwrap_or("");
        let _ = self.reload(false);
        let key = {
            let g = self.keys.lock().unwrap();
            match g.0.get(kid) {
                Some(k) => k.clone(),
                None if kid.is_empty() && g.0.len() == 1 => g.0.values().next().unwrap().clone(),
                None => {
                    drop(g);
                    let _ = self.reload(true); // the provider may have rotated its keys
                    self.keys.lock().unwrap().0.get(kid).cloned().ok_or("unknown signing key")?
                }
            }
        };
        let msg = format!("{h}.{p}");
        let sig = b64d(s)?;
        let ok = match (alg, &key) {
            ("RS256", Key::Rsa { n, e }) => RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg.as_bytes(), &sig).is_ok(),
            ("ES256", Key::Ec { point }) => UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(msg.as_bytes(), &sig).is_ok(),
            _ => return Err(format!("algorithm {alg} not accepted for this key")),
        };
        if !ok {
            return Err("bad token signature".into());
        }
        let c: Value = serde_json::from_slice(&b64d(p)?).map_err(|_| "bad JWT claims")?;
        if c["iss"].as_str() != Some(self.issuer.as_str()) {
            return Err("wrong issuer".into());
        }
        let auds: Vec<&str> = match &c["aud"] {
            Value::String(a) => vec![a.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        let azp = c["azp"].as_str();
        if !self.audiences.iter().any(|a| auds.contains(&a.as_str()) || azp == Some(a.as_str())) {
            return Err("wrong audience".into());
        }
        let exp = c["exp"].as_f64().ok_or("token has no expiry")?;
        if exp + LEEWAY < now {
            return Err("token expired".into());
        }
        if c["nbf"].as_f64().is_some_and(|n| n - LEEWAY > now) {
            return Err("token not yet valid".into());
        }
        let v = c[self.claim.as_str()].as_str().ok_or(format!("token has no {} claim", self.claim))?;
        if let Some(id) = self.map.get(v) {
            return Ok(id.clone());
        }
        let f = self.format.as_ref().ok_or("user not mapped to an identity")?;
        if !v.chars().all(|ch| ch.is_ascii_alphanumeric() || "._@-".contains(ch)) || v.len() > 128 {
            return Err("user name has characters an identity may not".into());
        }
        let id = f.replace("{}", v);
        if ["admin", "replica", "gateway"].contains(&id.as_str()) || !safe_identity(&id) {
            return Err("this user can only be mapped explicitly".into());
        }
        Ok(id)
    }
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

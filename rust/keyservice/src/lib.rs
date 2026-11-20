//! Bounded-loss key service.
//!
//! Port of `authority/budgets.py`. Verifies grants issued by the (Python) authority with the
//! authority's public key only, enforces rolling 24 h data budgets per identity and data class
//! (export budgets bound to destinations), accepts over-budget releases only with signatures
//! from enough distinct approvers, and holds per-record data keys wrapped under its own KEK.
//!
//! Security properties:
//! - no `unsafe` code;
//! - the service's own clock is used for budgets and expiry, never the caller's timestamp;
//! - anything it does not understand is refused (unknown action type, unclassified resource,
//!   unsupported pattern syntax, non-string artifact hash, non-finite budget factor).

#![forbid(unsafe_code)]

pub mod binding;
pub mod gates;
pub mod ha;
pub mod undo;

use binding::{CaseRegistry, DeviceCheck, DeviceRegistry};

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const DAY: f64 = 86400.0;
pub const READ_ACTIONS: [&str; 3] = ["data.read", "data.export", "secret.read"];
pub const ACTION_TYPES: [&str; 20] = [
    "auth.login", "data.read", "data.export", "secret.read", "artifact.publish", "repo.push",
    "repo.history_rewrite", "process.exec", "network.egress", "file.write_bulk", "backup.delete",
    "payment.send", "email.bulk_send", "dns.change", "key.delete", "storage.delete", "account.delete",
    "permission.grant", "agent.session", "security.control_change",
];
const MAX_STR: usize = 1024;
const MAX_COUNT: u64 = 1_000_000_000_000;

// ---------------------------------------------------------------- python-compatible JSON

/// Encode a string exactly as Python's `json.dumps` does with default `ensure_ascii=True`.
pub fn py_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn opt_str(v: &Option<String>) -> String {
    v.as_deref().map(py_json_str).unwrap_or_else(|| "null".into())
}

// ---------------------------------------------------------------- action

#[derive(Debug, Clone)]
pub struct Action {
    pub identity: String,
    pub action_type: String,
    pub resource: String,
    pub count: u64,
    pub destination: Option<String>,
    pub artifact: Option<String>,
    pub record_ids: Vec<String>,
    pub device_id: Option<String>,
    pub device_proof: Option<String>,
}

fn req_str(o: &Map<String, Value>, k: &str, required: bool) -> Result<Option<String>, String> {
    match o.get(k) {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::String(s)) if !s.is_empty() && s.chars().count() <= MAX_STR => Ok(Some(s.clone())),
        _ => Err(format!("field {k} must be a non-empty string of at most {MAX_STR} chars")),
    }
}

impl Action {
    pub fn from_json(v: &Value) -> Result<Action, String> {
        let o = v.as_object().ok_or("action must be an object")?;
        let action_type = req_str(o, "action_type", true)?.unwrap();
        if !ACTION_TYPES.contains(&action_type.as_str()) {
            return Err(format!("unknown action_type: {action_type}"));
        }
        let count = match o.get("count") {
            None => 1,
            Some(Value::Number(n)) => n.as_u64().filter(|c| *c <= MAX_COUNT).ok_or("count out of range")?,
            _ => return Err("count must be an integer".into()),
        };
        let meta = match o.get("metadata") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            _ => return Err("metadata must be an object".into()),
        };
        let artifact = match meta.get("candidate_sha256") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            _ => return Err("candidate_sha256 must be a string".into()),
        };
        let record_ids = match meta.get("record_ids") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| x.as_str().map(String::from).ok_or("record_ids must be strings"))
                .collect::<Result<_, _>>()?,
            _ => return Err("record_ids must be a list".into()),
        };
        let meta_str = |k: &str| meta.get(k).and_then(Value::as_str).map(String::from);
        Ok(Action {
            device_id: meta_str("device_id"),
            device_proof: meta_str("device_proof"),
            identity: req_str(o, "identity", true)?.unwrap(),
            action_type,
            resource: req_str(o, "resource", true)?.unwrap(),
            count,
            destination: req_str(o, "destination", false)?,
            artifact,
            record_ids,
        })
    }

    /// The fields an executor needs to perform the action (no device proofs).
    pub fn to_json(&self) -> Value {
        json!({"identity": self.identity, "action_type": self.action_type, "resource": self.resource,
               "count": self.count, "destination": self.destination})
    }

    /// Must equal Python `Action.fingerprint()` byte for byte.
    pub fn fingerprint(&self) -> String {
        let canon = format!(
            "{{\"action_type\":{},\"artifact\":{},\"count\":{},\"destination\":{},\"identity\":{},\"resource\":{}}}",
            py_json_str(&self.action_type),
            opt_str(&self.artifact),
            self.count,
            opt_str(&self.destination),
            py_json_str(&self.identity),
            py_json_str(&self.resource),
        );
        hex::encode(Sha256::digest(canon.as_bytes()))
    }
}

// ---------------------------------------------------------------- patterns and destinations

/// Case-sensitive glob with `*` and `?` (Python fnmatchcase subset). Patterns containing
/// `[` are rejected when the policy loads, so semantics cannot silently differ.
pub fn fnmatch(text: &str, pat: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    let (mut ti, mut pi, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn dest_key(dest: &str) -> String {
    match dest.split_once("://") {
        None => dest.to_lowercase(),
        Some((scheme, rest)) => {
            let host = rest.split('/').next().unwrap_or("").to_lowercase();
            if scheme == "http" || scheme == "https" {
                host
            } else {
                format!("{scheme}://{host}")
            }
        }
    }
}

// ---------------------------------------------------------------- budget policy

#[derive(Debug, Clone)]
pub struct BudgetPolicy {
    pub classes: Vec<(String, Vec<String>)>,
    pub budgets: HashMap<String, Vec<(String, u64)>>,
    pub overrun_signatures: usize,
    /// identity -> class -> (new records per 24 h, distinct records per 30 days)
    pub novelty: HashMap<String, HashMap<String, (u64, u64)>>,
    /// bait record ids (patterns): fake records no legitimate screen ever shows
    pub canary_records: Vec<String>,
    /// identities (patterns) whose releases need a registered-device WebAuthn assertion
    pub device_bound: Vec<String>,
    /// identity -> classes whose records must be on the requester's active cases
    pub purpose_bound: HashMap<String, Vec<String>>,
    /// identity -> class -> max overrun records per 24 h. None: section absent (unlimited);
    /// present: a missing entry means 0.
    pub overrun_max: Option<HashMap<String, HashMap<String, u64>>>,
}

pub const NOVELTY_WINDOW: f64 = 30.0 * DAY;

impl BudgetPolicy {
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let check = |p: &str| if p.contains('[') { Err(format!("unsupported pattern syntax: {p}")) } else { Ok(()) };
        let mut classes = vec![];
        for (name, pats) in v["classes"].as_object().ok_or("classes must be an object")? {
            let pats: Vec<String> = pats
                .as_array()
                .ok_or("class patterns must be a list")?
                .iter()
                .map(|x| x.as_str().map(String::from).ok_or("pattern must be a string"))
                .collect::<Result<_, _>>()?;
            for p in &pats {
                check(p)?;
            }
            classes.push((name.clone(), pats));
        }
        let mut budgets = HashMap::new();
        for (ident, m) in v["budgets"].as_object().ok_or("budgets must be an object")? {
            let mut entries = vec![];
            for (k, n) in m.as_object().ok_or("budget entries must be an object")? {
                check(k)?;
                entries.push((k.clone(), n.as_u64().ok_or("budget must be a non-negative integer")?));
            }
            budgets.insert(ident.clone(), entries);
        }
        let overrun_signatures = v.get("overrun_signatures").and_then(Value::as_u64).unwrap_or(2) as usize;
        if overrun_signatures == 0 {
            return Err("overrun_signatures must be at least 1".into());
        }
        let mut novelty = HashMap::new();
        if let Some(n) = v.get("novelty").and_then(Value::as_object) {
            for (ident, m) in n {
                let mut per = HashMap::new();
                for (cls, lim) in m.as_object().ok_or("novelty entries must be objects")? {
                    let npd = lim.get("new_per_day").and_then(Value::as_u64).unwrap_or(0);
                    let d30 = lim.get("distinct_30d").and_then(Value::as_u64).unwrap_or(0);
                    per.insert(cls.clone(), (npd, d30));
                }
                novelty.insert(ident.clone(), per);
            }
        }
        let mut canary_records = vec![];
        for p in v.get("canary_records").and_then(Value::as_array).cloned().unwrap_or_default() {
            let p = p.as_str().ok_or("canary_records must be strings")?.to_string();
            check(&p)?;
            canary_records.push(p);
        }
        let strs = |x: Option<&Value>| -> Vec<String> {
            x.and_then(Value::as_array).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };
        let device_bound = strs(v.get("device_bound"));
        let mut purpose_bound = HashMap::new();
        if let Some(m) = v.get("purpose_bound").and_then(Value::as_object) {
            for (k, cls) in m {
                purpose_bound.insert(k.clone(), strs(Some(cls)));
            }
        }
        let overrun_max = match v.get("overrun_max") {
            None | Some(Value::Null) => None,
            Some(m) => {
                let mut out = HashMap::new();
                for (ident, per) in m.as_object().ok_or("overrun_max must be an object")? {
                    if ident.starts_with('_') {
                        continue; // comments
                    }
                    let mut pc = HashMap::new();
                    for (cls, n) in per.as_object().ok_or("overrun_max entries must be objects")? {
                        pc.insert(cls.clone(), n.as_u64().ok_or("overrun_max must be a non-negative integer")?);
                    }
                    out.insert(ident.clone(), pc);
                }
                Some(out)
            }
        };
        Ok(BudgetPolicy { classes, budgets, overrun_signatures, novelty, canary_records, device_bound, purpose_bound,
                          overrun_max })
    }

    pub fn classify(&self, resource: &str) -> Option<&str> {
        self.classes
            .iter()
            .find(|(_, pats)| pats.iter().any(|p| fnmatch(resource, p)))
            .map(|(n, _)| n.as_str())
    }

    pub fn budget(&self, identity: &str, class: &str, destination: Option<&str>) -> (String, u64) {
        let entries = self.budgets.get(identity);
        if let Some(dest) = destination {
            let dk = dest_key(dest);
            if let Some(es) = entries {
                for (k, v) in es {
                    if let Some((c, pat)) = k.split_once('@') {
                        if c == class && fnmatch(&dk, pat) {
                            return (k.clone(), *v);
                        }
                    }
                }
            }
            return (format!("{class}@{dk}"), 0);
        }
        let v = entries.and_then(|es| es.iter().find(|(k, _)| k == class)).map(|(_, v)| *v).unwrap_or(0);
        (class.to_string(), v)
    }
}

// ---------------------------------------------------------------- grants

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .or_else(|_| URL_SAFE.decode(s))
        .map_err(|_| "bad base64".to_string())
}

fn verify_sig(pk: &VerifyingKey, sig: &[u8], msg: &[u8]) -> bool {
    Signature::from_slice(sig).map(|s| pk.verify(msg, &s).is_ok()).unwrap_or(false)
}

pub struct GrantVerifier {
    pk: VerifyingKey,
    used: HashMap<String, f64>,
}

impl GrantVerifier {
    pub fn new(pk: VerifyingKey) -> Self {
        GrantVerifier { pk, used: HashMap::new() }
    }

    pub fn verify(&mut self, token: &str, action: &Action, now: f64) -> Result<Map<String, Value>, String> {
        let (body_s, sig_s) = token.split_once('.').ok_or("malformed grant")?;
        if sig_s.contains('.') {
            return Err("malformed grant".into());
        }
        let body = b64d(body_s).map_err(|_| "malformed grant")?;
        let sig = b64d(sig_s).map_err(|_| "malformed grant")?;
        if !verify_sig(&self.pk, &sig, &body) {
            return Err("bad signature".into());
        }
        let payload: Map<String, Value> = serde_json::from_slice(&body).map_err(|_| "malformed grant")?;
        let exp = payload.get("exp").and_then(Value::as_f64).ok_or("malformed grant")?;
        if now > exp {
            return Err("grant expired".into());
        }
        if payload.get("fp").and_then(Value::as_str) != Some(action.fingerprint().as_str()) {
            return Err("grant does not match this action".into());
        }
        let gid = payload.get("gid").and_then(Value::as_str).ok_or("malformed grant")?.to_string();
        self.used.retain(|_, e| *e >= now);
        if self.used.contains_key(&gid) {
            return Err("grant already used".into());
        }
        self.used.insert(gid, exp);
        Ok(payload)
    }

    pub fn mark_used(&mut self, gid: &str, exp: f64) {
        self.used.insert(gid.to_string(), exp);
    }
}

/// t-of-n authority quorum: a bundle of grants ("~"-separated) from distinct authority nodes,
/// all for the same action. The strictest budget_factor applies. Mirrors `authority/quorum.py`.
pub struct QuorumVerifier {
    nodes: Vec<(String, GrantVerifier)>,
    threshold: usize,
}

impl QuorumVerifier {
    pub fn new(keys: Vec<(String, VerifyingKey)>, threshold: usize) -> Result<Self, String> {
        if threshold == 0 || threshold > keys.len() {
            return Err("need 1 <= threshold <= number of nodes".into());
        }
        Ok(QuorumVerifier { nodes: keys.into_iter().map(|(n, k)| (n, GrantVerifier::new(k))).collect(), threshold })
    }

    pub fn verify(&mut self, bundle: &str, action: &Action, now: f64) -> Result<Map<String, Value>, String> {
        let tokens: Vec<&str> = if bundle.is_empty() { vec![] } else { bundle.split('~').collect() };
        if tokens.len() > self.nodes.len() {
            return Err("too many grants in bundle".into());
        }
        let mut accepted: Vec<(String, Map<String, Value>)> = vec![];
        for tok in tokens {
            for (name, v) in self.nodes.iter_mut() {
                if accepted.iter().any(|(n, _)| n == name) {
                    continue;
                }
                match v.verify(tok, action, now) {
                    Ok(p) => {
                        accepted.push((name.clone(), p));
                        break;
                    }
                    Err(e) if e == "bad signature" => continue,
                    Err(e) => return Err(format!("{name}: {e}")),
                }
            }
        }
        if accepted.len() < self.threshold {
            return Err(format!("quorum not met: {} of {} nodes", accepted.len(), self.threshold));
        }
        let factor = accepted
            .iter()
            .map(|(_, p)| p.get("con").and_then(|c| c.get("budget_factor")).and_then(Value::as_f64).unwrap_or(1.0))
            .fold(f64::INFINITY, f64::min);
        let mut gids: Vec<String> =
            accepted.iter().map(|(_, p)| p.get("gid").and_then(Value::as_str).unwrap_or("").to_string()).collect();
        gids.sort();
        let used: Vec<Value> = accepted
            .iter()
            .map(|(n, p)| json!([n, p.get("gid").cloned().unwrap_or(Value::Null), p.get("exp").cloned().unwrap_or(Value::Null)]))
            .collect();
        let mut merged = accepted[0].1.clone();
        merged.insert("_used".into(), Value::Array(used));
        merged.insert("gid".into(), Value::String(gids.join("+")));
        let mut con = merged.get("con").and_then(Value::as_object).cloned().unwrap_or_default();
        con.insert("budget_factor".into(), serde_json::json!(factor));
        merged.insert("con".into(), Value::Object(con));
        Ok(merged)
    }
}

pub enum GrantCheck {
    Single(Box<GrantVerifier>),
    Quorum(QuorumVerifier),
}

pub(crate) fn b64d_pub(s: &str) -> Result<Vec<u8>, String> {
    b64d(s)
}

pub(crate) fn b64_verify(pk: &VerifyingKey, sig_b64: &str, msg: &[u8]) -> bool {
    b64d(sig_b64).map(|b| verify_sig(pk, &b, msg)).unwrap_or(false)
}

impl GrantCheck {
    /// (node, gid, exp) for every grant consumed by a successful verify, for the journal
    pub fn consumed(payload: &Map<String, Value>) -> Vec<(String, String, f64)> {
        if let Some(Value::Array(u)) = payload.get("_used") {
            return u
                .iter()
                .filter_map(|x| Some((x[0].as_str()?.to_string(), x[1].as_str()?.to_string(), x[2].as_f64()?)))
                .collect();
        }
        match (payload.get("gid").and_then(Value::as_str), payload.get("exp").and_then(Value::as_f64)) {
            (Some(g), Some(e)) => vec![(String::new(), g.to_string(), e)],
            _ => vec![],
        }
    }

    pub fn mark_used(&mut self, node: &str, gid: &str, exp: f64) {
        match self {
            GrantCheck::Single(v) => v.mark_used(gid, exp),
            GrantCheck::Quorum(q) => {
                if let Some((_, v)) = q.nodes.iter_mut().find(|(n, _)| n == node) {
                    v.mark_used(gid, exp);
                }
            }
        }
    }

    pub fn verify_pub(&mut self, token: &str, action: &Action, now: f64) -> Result<Map<String, Value>, String> {
        self.verify(token, action, now)
    }

    fn verify(&mut self, token: &str, action: &Action, now: f64) -> Result<Map<String, Value>, String> {
        match self {
            GrantCheck::Single(v) => v.verify(token, action, now),
            GrantCheck::Quorum(q) => q.verify(token, action, now),
        }
    }
}

/// Append-only journal of state changes, with group commit.
///
/// `write` only appends to an in-memory buffer (no syscall, so it never blocks behind a disk flush).
/// `Durability::sync(seq)` writes everything buffered so far and fsyncs once; concurrent callers whose
/// entries were included return immediately. A request that hands anything out syncs before replying;
/// a background flusher persists refusals/freezes within ~200 ms. Replayed and compacted at startup.
pub struct Journal {
    path: std::path::PathBuf,
    pub seq: u64,
    shared: std::sync::Arc<Mutex<(Vec<u8>, u64)>>,
    file: std::fs::File,
}

pub struct Durability {
    name: String,
    state: Mutex<(std::fs::File, u64)>,
    shared: std::sync::Arc<Mutex<(Vec<u8>, u64)>>,
}

/// Synchronous replication hook (high availability). `commit` must send `bytes` to the standby and
/// run `local` (the local write + fsync); it returns an error unless the bytes are safe to rely on.
pub trait Replicator: Send + Sync {
    fn commit(&self, journal: &str, bytes: &[u8], local: &mut dyn FnMut() -> Result<(), String>) -> Result<(), String>;
}

pub static REPLICATOR: std::sync::OnceLock<Box<dyn Replicator>> = std::sync::OnceLock::new();

impl Durability {
    pub fn sync(&self, upto: u64) -> Result<(), String> {
        use std::io::Write;
        let mut g = self.state.lock().unwrap();
        if g.1 >= upto {
            return Ok(());
        }
        let (bytes, last) = {
            let mut b = self.shared.lock().unwrap();
            (std::mem::take(&mut b.0), b.1)
        };
        if !bytes.is_empty() {
            let file = &mut g.0;
            let mut local = || -> Result<(), String> {
                file.write_all(&bytes).map_err(|e| e.to_string())?;
                file.sync_data().map_err(|e| e.to_string())
            };
            match REPLICATOR.get() {
                Some(r) => r.commit(&self.name, &bytes, &mut local)?,
                None => local()?,
            }
        }
        g.1 = g.1.max(last);
        Ok(())
    }

    /// Persist whatever is buffered (used by the background flusher).
    pub fn flush(&self) -> Result<(), String> {
        let last = self.shared.lock().unwrap().1;
        self.sync(last)
    }
}

impl Journal {
    pub fn open(path: &std::path::Path) -> Result<(Journal, Vec<Value>), String> {
        use std::io::BufRead;
        let mut events = vec![];
        if path.exists() {
            let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
            for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
                let line = line.map_err(|e| e.to_string())?;
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(&line) {
                    Ok(v) => events.push(v),
                    // a torn last line after a crash is expected; anything else is corruption
                    Err(_) => eprintln!("journal: ignoring unreadable line {}", i + 1),
                }
            }
        }
        let file = Self::open_append(path)?;
        Ok((Journal { path: path.to_path_buf(), seq: 0, shared: Default::default(), file }, events))
    }

    fn open_append(path: &std::path::Path) -> Result<std::fs::File, String> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path).map_err(|e| e.to_string())
    }

    /// Append to the buffer (not yet on disk). Anything handed out must `Durability::sync(seq)` first.
    pub fn write(&mut self, v: &Value) -> Result<(), String> {
        let line = format!("{v}\n");
        self.seq += 1;
        let mut b = self.shared.lock().unwrap();
        b.0.extend_from_slice(line.as_bytes());
        b.1 = self.seq;
        Ok(())
    }

    pub fn durability(&self) -> Result<Durability, String> {
        let name = self.path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        Ok(Durability { name, state: Mutex::new((self.file.try_clone().map_err(|e| e.to_string())?, 0)),
                        shared: std::sync::Arc::clone(&self.shared) })
    }

    /// Replace the journal with `events` (atomic rename), used for compaction at startup.
    pub fn rewrite(&mut self, events: &[Value]) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = self.path.with_extension("compact");
        {
            let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600)
                .open(&tmp).map_err(|e| e.to_string())?;
            for v in events {
                writeln!(f, "{v}").map_err(|e| e.to_string())?;
            }
            f.sync_all().map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())?;
        self.file = Self::open_append(&self.path)?;
        Ok(())
    }
}

/// KEK rotation (offline): re-wrap every record key in `journal` from `old` to `new`.
/// All-or-nothing: every key must open with `old` and re-open with `new` before the journal is
/// atomically replaced. The previous journal is kept as `<name>.pre-rotation` (0600) until the
/// operator has confirmed the service starts with the new KEK. Returns the number of keys re-wrapped.
pub fn rewrap_journal(journal: &std::path::Path, old: [u8; 32], new: [u8; 32]) -> Result<usize, String> {
    use std::io::{BufRead, Write};
    use std::os::unix::fs::OpenOptionsExt;
    if old == new {
        return Err("old and new KEK are the same".into());
    }
    let (ko, kn) = (Aes256Gcm::new_from_slice(&old).map_err(|e| e.to_string())?,
                    Aes256Gcm::new_from_slice(&new).map_err(|e| e.to_string())?);
    let f = std::fs::File::open(journal).map_err(|e| format!("{}: {e}", journal.display()))?;
    let mut out: Vec<String> = vec![];
    let mut n = 0usize;
    for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(mut ev) = serde_json::from_str::<Value>(&line) else {
            return Err(format!("line {}: unreadable journal entry; refusing to rotate", i + 1));
        };
        if ev.get("e").and_then(Value::as_str) == Some("wrap") {
            let rid = ev["rid"].as_str().unwrap_or("").to_string();
            let blob = ev["blob"].as_str().and_then(|b| b64d(b).ok()).ok_or(format!("line {}: bad key blob", i + 1))?;
            if blob.len() < 12 + 16 {
                return Err(format!("line {}: key blob too short", i + 1));
            }
            let dek = ko.decrypt(Nonce::from_slice(&blob[..12]), Payload { msg: &blob[12..], aad: rid.as_bytes() })
                .map_err(|_| format!("record {rid}: does not open with the old KEK; nothing changed"))?;
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let ct = kn.encrypt(Nonce::from_slice(&nonce), Payload { msg: &dek, aad: rid.as_bytes() })
                .map_err(|_| "encrypt failed".to_string())?;
            let check = kn.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: rid.as_bytes() })
                .map_err(|_| "re-wrapped key does not open; nothing changed".to_string())?;
            if check != dek {
                return Err("re-wrap verification failed; nothing changed".into());
            }
            let mut b = nonce.to_vec();
            b.extend(ct);
            ev["blob"] = Value::String(URL_SAFE_NO_PAD.encode(&b));
            n += 1;
        }
        out.push(ev.to_string());
    }
    let tmp = journal.with_extension("rotating");
    {
        let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600)
            .open(&tmp).map_err(|e| e.to_string())?;
        for l in &out {
            writeln!(f, "{l}").map_err(|e| e.to_string())?;
        }
        f.sync_all().map_err(|e| e.to_string())?;
    }
    let backup = journal.with_extension("pre-rotation");
    std::fs::copy(journal, &backup).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&backup, std::os::unix::fs::PermissionsExt::from_mode(0o600)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, journal).map_err(|e| e.to_string())?;
    if let Some(d) = journal.parent() {
        if let Ok(df) = std::fs::File::open(d) {
            let _ = df.sync_all();
        }
    }
    Ok(n)
}

/// Approvers' registered passkeys (same registry format as --devices), shared by the key service
/// and the change gates.
pub type ApproverDevices = std::sync::Arc<Mutex<Option<DeviceRegistry>>>;

/// One approver signature entry over `msg`. Either {"approver", "sig"}: Ed25519 from the approver CLI,
/// or {"approver", "device", "proof"}: a user-verified passkey assertion whose challenge is
/// sha256(msg), from that approver's registered device (clone counter enforced). The approver must
/// be in the approvers file either way (that file is the list of who may approve).
pub fn approver_signed(keys: &HashMap<String, VerifyingKey>, devs: Option<&ApproverDevices>, s: &Value, msg: &[u8])
                       -> Option<String> {
    let name = s.get("approver").and_then(Value::as_str)?;
    let pk = keys.get(name)?;
    if let Some(sig) = s.get("sig").and_then(Value::as_str) {
        return b64_verify(pk, sig, msg).then(|| name.to_string());
    }
    let (device, proof) = (s.get("device").and_then(Value::as_str)?, s.get("proof").and_then(Value::as_str)?);
    let chal: [u8; 32] = Sha256::digest(msg).into();
    let mut g = devs?.lock().unwrap();
    match g.as_mut()?.check_challenge(name, Some(device), Some(proof), &chal) {
        DeviceCheck::Ok { .. } => Some(name.to_string()),
        _ => None,
    }
}

pub fn unfreeze_message(identity: &str, until: u64) -> Vec<u8> {
    format!("mastyf-unfreeze|{identity}|{until}").into_bytes()
}

pub fn overrun_message(gid: &str, amount: u64) -> Vec<u8> {
    format!("mastyf-overrun|{gid}|{amount}").into_bytes()
}

// ---------------------------------------------------------------- key service

#[derive(Debug, serde::Serialize, PartialEq)]
pub struct Release {
    pub ok: bool,
    pub reason: String,
    pub data_class: Option<String>,
    pub released: u64,
    pub remaining: Option<u64>,
    pub shortfall: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<HashMap<String, String>>,
}

impl Release {
    fn no(reason: impl Into<String>, class: Option<&str>) -> Self {
        Release { ok: false, reason: reason.into(), data_class: class.map(String::from), released: 0,
                  remaining: None, shortfall: 0, keys: None }
    }
}

struct Inner {
    journal: Option<Journal>,
    devices: Option<DeviceRegistry>,
    cases: Option<CaseRegistry>,
    verifier: GrantCheck,
    ledger: HashMap<(String, String), VecDeque<(f64, u64)>>,
    seen: HashMap<(String, String), HashMap<String, f64>>,
    frozen: HashMap<String, String>,
    new_ledger: HashMap<(String, String), VecDeque<(f64, u64)>>,
    wrapped: HashMap<String, (String, Vec<u8>)>,
}

pub struct KeyService {
    durable: std::sync::OnceLock<Durability>,
    pub approver_devices: std::sync::OnceLock<ApproverDevices>,
    pub policy: BudgetPolicy,
    approvers: HashMap<String, VerifyingKey>,
    kek: Aes256Gcm,
    inner: Mutex<Inner>,
}

impl KeyService {
    pub fn new(policy: BudgetPolicy, authority: VerifyingKey, approvers: HashMap<String, VerifyingKey>) -> Self {
        Self::with_verifier(policy, GrantCheck::Single(Box::new(GrantVerifier::new(authority))), approvers)
    }

    pub fn with_verifier(policy: BudgetPolicy, verifier: GrantCheck, approvers: HashMap<String, VerifyingKey>) -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Self::with_kek(policy, verifier, approvers, k)
    }

    /// Production constructor: the KEK comes from a protected file or a KMS, never generated per run.
    pub fn with_kek(policy: BudgetPolicy, verifier: GrantCheck, approvers: HashMap<String, VerifyingKey>,
                    k: [u8; 32]) -> Self {
        KeyService {
            durable: std::sync::OnceLock::new(),
            approver_devices: std::sync::OnceLock::new(),
            policy,
            approvers,
            kek: Aes256Gcm::new_from_slice(&k).expect("32-byte key"),
            inner: Mutex::new(Inner { journal: None, devices: None, cases: None, verifier, ledger: HashMap::new(),
                                      seen: HashMap::new(), frozen: HashMap::new(), new_ledger: HashMap::new(), wrapped: HashMap::new() }),
        }
    }

    /// Create and store (wrapped) a fresh data key for a record. Returns the DEK so the
    /// writer can encrypt the record once; the service never returns it again without a release.
    /// Attach a journal: replay its events (state survives restarts), then compact it.
    pub fn attach_journal(&self, mut j: Journal, events: Vec<Value>, now: f64) -> Result<usize, String> {
        let mut inner = self.inner.lock().unwrap();
        let mut keep = vec![];
        for ev in events {
            let live = match ev.get("e").and_then(Value::as_str) {
                Some("gid") => {
                    let exp = ev["exp"].as_f64().unwrap_or(0.0);
                    if exp >= now {
                        inner.verifier.mark_used(ev["node"].as_str().unwrap_or(""), ev["gid"].as_str().unwrap_or(""), exp);
                    }
                    exp >= now
                }
                Some("rel") => {
                    let ts = ev["ts"].as_f64().unwrap_or(0.0);
                    let id = ev["id"].as_str().unwrap_or("").to_string();
                    let n = ev["n"].as_u64().unwrap_or(0);
                    inner.ledger.entry((id.clone(), ev["key"].as_str().unwrap_or("").to_string())).or_default()
                        .push_back((ts, n));
                    if let Some(ids) = ev.get("ids").and_then(Value::as_array) {
                        let k = (id, ev["cls"].as_str().unwrap_or("").to_string());
                        let seen = inner.seen.entry(k.clone()).or_default();
                        for r in ids.iter().filter_map(Value::as_str) {
                            seen.insert(r.to_string(), ts);
                        }
                        inner.new_ledger.entry(k).or_default().push_back((ts, ev["new"].as_u64().unwrap_or(0)));
                    }
                    ts > now - NOVELTY_WINDOW
                }
                Some("unfreeze") => {
                    inner.frozen.remove(ev["id"].as_str().unwrap_or(""));
                    true
                }
                Some("freeze") => {
                    inner.frozen.insert(ev["id"].as_str().unwrap_or("").into(), ev["why"].as_str().unwrap_or("").into());
                    true
                }
                Some("devctr") => {
                    if let Some(reg) = inner.devices.as_mut() {
                        reg.counters.insert((ev["id"].as_str().unwrap_or("").into(), ev["dev"].as_str().unwrap_or("").into()),
                                            ev["n"].as_u64().unwrap_or(0));
                    }
                    true
                }
                Some("cloned") => {
                    if let Some(reg) = inner.devices.as_mut() {
                        reg.cloned.insert((ev["id"].as_str().unwrap_or("").into(), ev["dev"].as_str().unwrap_or("").into()));
                    }
                    true
                }
                Some("case") => {
                    let exp = ev["exp"].as_f64().unwrap_or(0.0);
                    if let (Some(c), true) = (inner.cases.as_mut(), exp > now) {
                        let recs = ev["recs"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        c.restore(ev["case"].as_str().unwrap_or(""), ev["to"].as_str().unwrap_or(""), recs, exp);
                    }
                    exp > now
                }
                Some("outside") => {
                    let ts = ev["ts"].as_f64().unwrap_or(0.0);
                    if let (Some(c), true) = (inner.cases.as_mut(), ts > now - DAY) {
                        c.restore_outside(ev["id"].as_str().unwrap_or(""), ts, ev["n"].as_u64().unwrap_or(0));
                    }
                    ts > now - DAY
                }
                Some("wrap") => {
                    let blob = ev["blob"].as_str().and_then(|b| b64d(b).ok()).unwrap_or_default();
                    inner.wrapped.insert(ev["rid"].as_str().unwrap_or("").into(), (ev["cls"].as_str().unwrap_or("").into(), blob));
                    true
                }
                _ => false,
            };
            if live {
                keep.push(ev);
            }
        }
        let n = keep.len();
        j.rewrite(&keep)?;
        let _ = self.durable.set(j.durability()?);
        inner.journal = Some(j);
        Ok(n)
    }

    /// Background flusher entry point: persist anything buffered (refusals, freezes, consumed grants).
    pub fn flush(&self) -> Result<(), String> {
        match self.durable.get() {
            Some(d) => d.flush(),
            None => Ok(()),
        }
    }

    /// Make everything journaled so far durable before replying (group commit).
    fn commit(&self) -> Result<(), String> {
        let Some(d) = self.durable.get() else { return Ok(()) };
        let seq = self.inner.lock().unwrap().journal.as_ref().map(|j| j.seq).unwrap_or(0);
        d.sync(seq)
    }

    pub fn set_devices(&self, reg: DeviceRegistry) {
        self.inner.lock().unwrap().devices = Some(reg);
    }

    /// False if record keys exist and the configured KEK cannot open one (wrong KEK after rotation,
    /// or the wrong KMS key): the service must not start.
    pub fn kek_matches(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        match inner.wrapped.iter().next() {
            None => true,
            Some((rid, (_, blob))) => blob.len() >= 28 && self.kek
                .decrypt(Nonce::from_slice(&blob[..12]), Payload { msg: &blob[12..], aad: rid.as_bytes() }).is_ok(),
        }
    }

    /// Swap in a re-read registry file (device added or removed) keeping clone counters and flags.
    pub fn update_devices(&self, mut reg: DeviceRegistry) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(old) = inner.devices.take() {
            reg.counters = old.counters;
            reg.cloned = old.cloned;
        }
        inner.devices = Some(reg);
    }

    pub fn set_cases(&self, reg: CaseRegistry) {
        self.inner.lock().unwrap().cases = Some(reg);
    }

    /// A case assignment signed by the case system (never by the requester).
    pub fn assign_case(&self, case_id: &str, identity: &str, records: Vec<String>, exp: u64, sig: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(cases) = inner.cases.as_mut() else { return false };
        if !cases.assign(case_id, identity, records.clone(), exp, sig) {
            return false;
        }
        let _ = Self::journal(&mut inner, json!({"e": "case", "case": case_id, "to": identity, "recs": records, "exp": exp}));
        drop(inner);
        self.commit().is_ok()
    }

    /// Lift a freeze: needs `overrun_signatures` distinct approvers (never the frozen identity), each
    /// signing "mastyf-unfreeze|<identity>|<until>", with `until` at most one hour ahead.
    pub fn unfreeze(&self, identity: &str, until: u64, sigs: &[Value], now: f64) -> Result<(), String> {
        if (until as f64) < now || (until as f64) > now + 3600.0 {
            return Err("unfreeze approval expired or too far in the future".into());
        }
        let msg = unfreeze_message(identity, until);
        let mut ok = HashSet::new();
        for s in sigs {
            if let Some(name) = approver_signed(&self.approvers, self.approver_devices.get(), s, &msg) {
                if name != identity {
                    ok.insert(name);
                }
            }
        }
        if ok.len() < self.policy.overrun_signatures {
            return Err(format!("unfreeze needs {} approver signatures", self.policy.overrun_signatures));
        }
        let mut inner = self.inner.lock().unwrap();
        Self::journal(&mut inner, json!({"e": "unfreeze", "id": identity}))?;
        inner.frozen.remove(identity);
        drop(inner);
        self.commit()
    }

    fn journal(inner: &mut Inner, v: Value) -> Result<(), String> {
        match inner.journal.as_mut() {
            Some(j) => j.write(&v),
            None => Ok(()),
        }
    }

    pub fn new_record_key(&self, record_id: &str, class: &str) -> Vec<u8> {
        let mut dek = vec![0u8; 32];
        OsRng.fill_bytes(&mut dek);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = self
            .kek
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &dek, aad: record_id.as_bytes() })
            .expect("encrypt");
        let mut blob = nonce.to_vec();
        blob.extend(ct);
        let mut inner = self.inner.lock().unwrap();
        if Self::journal(&mut inner, json!({"e": "wrap", "rid": record_id, "cls": class,
                                            "blob": URL_SAFE_NO_PAD.encode(&blob)})).is_err() {
            return vec![];  // not persisted: do not hand out a key that would be lost on restart
        }
        inner.wrapped.insert(record_id.to_string(), (class.to_string(), blob));
        drop(inner);
        if self.commit().is_err() {
            return vec![];
        }
        dek
    }

    fn overrun_amount(&self, gid: &str, requester: &str, sigs: &[Value]) -> u64 {
        let mut signers = HashSet::new();
        let mut amounts = HashSet::new();
        for s in sigs {
            let Some(amount) = s.get("amount").and_then(Value::as_u64) else { continue };
            if amount == 0 {
                continue;
            }
            if let Some(name) = approver_signed(&self.approvers, self.approver_devices.get(), s, &overrun_message(gid, amount)) {
                if name != requester {
                    signers.insert(name);
                    amounts.insert(amount);
                }
            }
        }
        if signers.len() >= self.policy.overrun_signatures && amounts.len() == 1 {
            amounts.into_iter().next().unwrap()
        } else {
            0
        }
    }

    /// Decide and, if allowed, debit. `now` is the service's own clock. Keys are returned only after
    /// the journal entries for this release are on disk.
    pub fn release(&self, grant: &str, action: &Action, overrun: &[Value], now: f64) -> Release {
        let r = self.release_inner(grant, action, overrun, now);
        // keys handed out, or an identity frozen: must be on disk before we answer
        if r.ok || r.reason.starts_with("canary") || r.reason.contains("cloned") {
            if let Err(e) = self.commit() {
                return Release::no(format!("journal sync failed: refusing (fail closed): {e}"), r.data_class.as_deref());
            }
        }
        r
    }

    fn release_inner(&self, grant: &str, action: &Action, overrun: &[Value], now: f64) -> Release {
        if !READ_ACTIONS.contains(&action.action_type.as_str()) {
            return Release::no(format!("{} does not release data keys", action.action_type), None);
        }
        let Some(class) = self.policy.classify(&action.resource).map(String::from) else {
            return Release::no("resource has no data class: refusing (fail closed)", None);
        };
        let mut inner = self.inner.lock().unwrap();
        if let Some(why) = inner.frozen.get(&action.identity) {
            return Release::no(format!("identity frozen: {why}"), Some(&class));
        }
        let payload = match inner.verifier.verify(grant, action, now) {
            Ok(p) => p,
            Err(e) => return Release::no(format!("grant rejected: {e}"), Some(&class)),
        };
        for (node, gid, exp) in GrantCheck::consumed(&payload) {
            if Self::journal(&mut inner, json!({"e": "gid", "node": node, "gid": gid, "exp": exp})).is_err() {
                return Release::no("journal write failed: refusing (fail closed)", Some(&class));
            }
        }
        if let Some(bait) = action.record_ids.iter().find(|r| self.policy.canary_records.iter().any(|p| fnmatch(r, p))) {
            let why = format!("requested bait record {bait}");
            let _ = Self::journal(&mut inner, json!({"e": "freeze", "id": action.identity, "why": why}));
            inner.frozen.insert(action.identity.clone(), why);
            return Release::no("canary: bait record requested; identity frozen", Some(&class));
        }
        let mut device_kex: Option<[u8; 32]> = None;
        if self.policy.device_bound.iter().any(|p| fnmatch(&action.identity, p)) {
            let gid = payload.get("gid").and_then(Value::as_str).unwrap_or("").to_string();
            let fp = action.fingerprint();
            let dev = action.device_id.clone().unwrap_or_default();
            let res = match inner.devices.as_mut() {
                None => DeviceCheck::Refused { why: "no registry".into(), counter: None },
                Some(reg) => reg.check(&action.identity, action.device_id.as_deref(), action.device_proof.as_deref(), &gid, &fp),
            };
            match res {
                DeviceCheck::Ok { kex, counter } => {
                    if Self::journal(&mut inner, json!({"e": "devctr", "id": action.identity, "dev": dev, "n": counter})).is_err() {
                        return Release::no("journal write failed: refusing (fail closed)", Some(&class));
                    }
                    device_kex = Some(kex);
                }
                DeviceCheck::Refused { why, counter } => {
                    if let Some(n) = counter {
                        let _ = Self::journal(&mut inner, json!({"e": "devctr", "id": action.identity, "dev": dev, "n": n}));
                    }
                    return Release::no(format!("device: {why}"), Some(&class));
                }
                DeviceCheck::Cloned { why } => {
                    let _ = Self::journal(&mut inner, json!({"e": "cloned", "id": action.identity, "dev": dev}));
                    let _ = Self::journal(&mut inner, json!({"e": "freeze", "id": action.identity, "why": why}));
                    inner.frozen.insert(action.identity.clone(), why.clone());
                    return Release::no(format!("device: {why}"), Some(&class));
                }
            }
        }
        let mut outside_n = 0u64;
        if self.policy.purpose_bound.get(&action.identity).is_some_and(|c| c.contains(&class)) {
            if action.record_ids.len() as u64 != action.count {
                return Release::no("need-to-know: record ids on assigned cases required", Some(&class));
            }
            match inner.cases.as_mut() {
                None => return Release::no("need-to-know: record ids on assigned cases required", Some(&class)),
                Some(c) => match c.check(&action.identity, &action.record_ids, now) {
                    Ok(n) => outside_n = n,
                    Err(why) => return Release::no(why, Some(&class)),
                },
            }
        }
        let factor = payload
            .get("con")
            .and_then(|c| c.get("budget_factor"))
            .and_then(Value::as_f64)
            .unwrap_or(1.0);
        let factor = if factor.is_finite() { factor.clamp(0.0, 1.0) } else { 0.0 };
        let (key, base) = self.policy.budget(&action.identity, &class, action.destination.as_deref());
        let allowance = (base as f64 * factor).floor() as u64;
        let gid = payload.get("gid").and_then(Value::as_str).unwrap_or("");
        let approved = self.overrun_amount(gid, &action.identity, overrun);
        let dq = inner.ledger.entry((action.identity.clone(), key.clone())).or_default();
        while dq.front().is_some_and(|(t, _)| *t <= now - DAY) {
            dq.pop_front();
        }
        let used: u64 = dq.iter().map(|(_, n)| *n).sum();
        let over = used.checked_add(action.count).is_none_or(|s| s > allowance);
        let mut over_budget = over;
        if approved < action.count && over {
            let mut r = Release::no(
                format!("budget: {key} {used}+{} > {allowance} per 24h for {}", action.count, action.identity),
                Some(&class),
            );
            r.remaining = Some(allowance.saturating_sub(used));
            r.shortfall = (used + action.count).saturating_sub(allowance);
            return r;
        }
        // novelty: limit records this identity has not been given in the last 30 days
        let nov = self.policy.novelty.get(&action.identity).and_then(|m| m.get(&class)).copied();
        let mut new_count: u64 = 0;
        if let Some((new_per_day, distinct_30d)) = nov {
            if action.record_ids.len() as u64 != action.count {
                return Release::no("novelty budget: record ids required for every record", Some(&class));
            }
            let k = (action.identity.clone(), class.clone());
            let seen = inner.seen.entry(k.clone()).or_default();
            seen.retain(|_, ts| *ts > now - NOVELTY_WINDOW);
            let mut uniq = HashSet::new();
            for r in &action.record_ids {
                if uniq.insert(r.as_str()) && !seen.contains_key(r) {
                    new_count += 1;
                }
            }
            let distinct = seen.len() as u64;
            let nq = inner.new_ledger.entry(k).or_default();
            while nq.front().is_some_and(|(t, _)| *t <= now - DAY) {
                nq.pop_front();
            }
            let new_today: u64 = nq.iter().map(|(_, n)| *n).sum();
            let over_day = new_today + new_count > new_per_day;
            let over_window = distinct + new_count > distinct_30d;
            over_budget = over_budget || over_day || over_window;
            if approved < action.count && (over_day || over_window) {
                let what = if over_day {
                    format!("{new_today}+{new_count} new records > {new_per_day} per 24h")
                } else {
                    format!("{distinct}+{new_count} distinct records > {distinct_30d} per 30 days")
                };
                let mut r = Release::no(format!("novelty: {what} for {}", action.identity), Some(&class));
                r.remaining = Some(allowance.saturating_sub(used));
                return r;
            }
        }
        // AI agent session: total records the person approved (grant constraint "sess"/"sess_max")
        let sess = payload.get("con").and_then(|c| c.get("sess")).and_then(Value::as_str).map(String::from);
        let sess_key = sess.as_ref().map(|s| format!("sess:{s}"));
        if let Some(sk) = &sess_key {
            let cap = payload.get("con").and_then(|c| c.get("sess_max")).and_then(Value::as_u64).unwrap_or(0);
            let sq = inner.ledger.entry((action.identity.clone(), sk.clone())).or_default();
            while sq.front().is_some_and(|(t, _)| *t <= now - DAY) {
                sq.pop_front();
            }
            let su: u64 = sq.iter().map(|(_, n)| *n).sum();
            if su.saturating_add(action.count) > cap {
                let mut r = Release::no(format!("agent session cap: {su}+{} > {cap} records", action.count), Some(&class));
                r.remaining = Some(allowance.saturating_sub(used));
                return r;
            }
        }
        let overrun_key = format!("overrun:{class}");
        let overrun_used = approved >= action.count && over_budget;
        if overrun_used {
            if let Some(caps) = &self.policy.overrun_max {
                let cap = caps.get(&action.identity).and_then(|m| m.get(&class)).copied().unwrap_or(0);
                let oq = inner.ledger.entry((action.identity.clone(), overrun_key.clone())).or_default();
                while oq.front().is_some_and(|(t, _)| *t <= now - DAY) {
                    oq.pop_front();
                }
                let ou: u64 = oq.iter().map(|(_, n)| *n).sum();
                if ou.saturating_add(action.count) > cap {
                    let mut r = Release::no(format!("overrun cap: {ou}+{} > {cap} per 24h for {}", action.count,
                                                    action.identity), Some(&class));
                    r.remaining = Some(allowance.saturating_sub(used));
                    return r;
                }
            }
        }
        let mut keys = None;
        if !action.record_ids.is_empty() {
            if action.record_ids.len() as u64 > action.count {
                return Release::no("more record ids than the granted count", Some(&class));
            }
            let mut out = HashMap::new();
            for rid in &action.record_ids {
                let Some((c, blob)) = inner.wrapped.get(rid) else {
                    return Release::no(format!("record {rid} not in class {class}"), Some(&class));
                };
                if *c != class || blob.len() < 12 {
                    return Release::no(format!("record {rid} not in class {class}"), Some(&class));
                }
                let dek = match self.kek.decrypt(Nonce::from_slice(&blob[..12]),
                                                 Payload { msg: &blob[12..], aad: rid.as_bytes() }) {
                    Ok(d) => d,
                    Err(_) => return Release::no("key unwrap failed", Some(&class)),
                };
                let v = match device_kex {
                    Some(k) => binding::wrap_to_device(&dek, k, rid),
                    None => URL_SAFE_NO_PAD.encode(dek),
                };
                out.insert(rid.clone(), v);
            }
            keys = Some(out);
        }
        let mut ev = json!({"e": "rel", "id": action.identity, "key": key, "cls": class, "ts": now, "n": action.count});
        if nov.is_some() {
            ev["ids"] = json!(action.record_ids);
            ev["new"] = json!(new_count);
        }
        if Self::journal(&mut inner, ev).is_err() {
            return Release::no("journal write failed: refusing (fail closed)", Some(&class));
        }
        inner.ledger.entry((action.identity.clone(), key)).or_default().push_back((now, action.count));
        if overrun_used {
            if Self::journal(&mut inner, json!({"e": "rel", "id": action.identity, "key": overrun_key, "cls": class,
                                                "ts": now, "n": action.count})).is_err() {
                return Release::no("journal write failed: refusing (fail closed)", Some(&class));
            }
            inner.ledger.entry((action.identity.clone(), overrun_key)).or_default().push_back((now, action.count));
        }
        if let Some(sk) = sess_key {
            if Self::journal(&mut inner, json!({"e": "rel", "id": action.identity, "key": sk, "cls": class,
                                                "ts": now, "n": action.count})).is_err() {
                return Release::no("journal write failed: refusing (fail closed)", Some(&class));
            }
            inner.ledger.entry((action.identity.clone(), sk)).or_default().push_back((now, action.count));
        }
        if outside_n > 0 {
            let _ = Self::journal(&mut inner, json!({"e": "outside", "id": action.identity, "ts": now, "n": outside_n}));
            if let Some(c) = inner.cases.as_mut() {
                c.commit_outside(&action.identity, outside_n, now);
            }
        }
        if nov.is_some() {
            let k = (action.identity.clone(), class.clone());
            let seen = inner.seen.entry(k.clone()).or_default();
            for r in &action.record_ids {
                seen.insert(r.clone(), now);
            }
            inner.new_ledger.entry(k).or_default().push_back((now, new_count));
        }
        Release { ok: true, reason: "released".into(), data_class: Some(class), released: action.count,
                  remaining: Some(allowance.saturating_sub(used + action.count)), shortfall: 0, keys }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_matches_python_escaping() {
        assert_eq!(py_json_str("a\"b\\c\n"), r#""a\"b\\c\n""#);
        assert_eq!(py_json_str("\u{e9}"), "\"\\u00e9\"");
        assert_eq!(py_json_str("\u{1f600}"), "\"\\ud83d\\ude00\"");
        assert_eq!(py_json_str("\u{7f}"), r#""\u007f""#);
    }

    #[test]
    fn glob() {
        assert!(fnmatch("db://crm/customers/query", "db://crm/customers*"));
        assert!(fnmatch("s3://corp-partner-7", "s3://corp-partner-*"));
        assert!(!fnmatch("s3://corp-warehousex", "s3://corp-warehouse"));
        assert!(fnmatch("abc", "a?c") && !fnmatch("ac", "a?c"));
    }

    #[test]
    fn dest_keys() {
        assert_eq!(dest_key("https://Files.Evil.net/u"), "files.evil.net");
        assert_eq!(dest_key("s3://corp-warehouse/nightly"), "s3://corp-warehouse");
        assert_eq!(dest_key("Host.Example"), "host.example");
    }
}

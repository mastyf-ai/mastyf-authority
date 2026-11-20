//! Change gates and the script-integrity check. Port of `authority/gates.py` and
//! `authority/script_integrity.py`; the differential test keeps them in agreement.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha384};

use crate::{fnmatch, Action, Durability, GrantCheck, Journal, DAY};

pub const GATED: [&str; 4] = ["artifact.publish", "repo.history_rewrite", "backup.delete", "file.write_bulk"];

// ---------------------------------------------------------------- script integrity

struct Rx {
    url: Regex,
    host_lit: Regex,
    sensitive: Regex,
    sinks: Vec<(&'static str, Regex)>,
    obf: Vec<(&'static str, Regex)>,
    listener: Regex,
    clipboard: Regex,
    wallet: Regex,
    wallet_pattern: Regex,
    caps: Vec<(&'static str, Regex)>,
    cookie: Regex,
    b64: Regex,
    hex: Regex,
    charcode: Regex,
}

fn rx() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx {
        url: Regex::new(r"(?i)(?:https?:|wss?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,})").unwrap(),
        host_lit: Regex::new(
            r#"(?i)["'`]([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|ru|xyz|top|cc|info|biz|invalid|co|app|dev|site|online|cn|su))["'`]"#,
        )
        .unwrap(),
        sensitive: Regex::new(
            r#"(?i)cc-?(?:number|num|exp|csc)|card.?(?:number|num|holder)|\bcvv\b|\bcvc\b|security.?code|autocomplete\s*=\s*['"]?cc-|type\s*=\s*['"]?password|\bpassword\b|\biban\b|seed.?phrase|mnemonic|private.?key"#,
        )
        .unwrap(),
        sinks: vec![
            ("fetch", Regex::new(r"\bfetch\s*\(").unwrap()),
            ("xhr", Regex::new(r"XMLHttpRequest").unwrap()),
            ("beacon", Regex::new(r"sendBeacon").unwrap()),
            ("image_beacon", Regex::new(r"new\s+Image\s*\(").unwrap()),
            ("websocket", Regex::new(r"new\s+WebSocket").unwrap()),
            ("form_action", Regex::new(r"\.action\s*=").unwrap()),
            ("script_inject", Regex::new(r#"createElement\s*\(\s*['"]script"#).unwrap()),
        ],
        obf: vec![
            ("eval", Regex::new(r"\beval\s*\(").unwrap()),
            ("function_ctor", Regex::new(r"new\s+Function\s*\(").unwrap()),
            ("atob", Regex::new(r"\batob\s*\(").unwrap()),
            ("fromcharcode", Regex::new(r"fromCharCode").unwrap()),
            ("hex_escapes", Regex::new(r"(?i)(?:\\x[0-9a-f]{2}){8,}").unwrap()),
            ("long_blob", Regex::new(r#"['"][A-Za-z0-9+/=]{200,}['"]"#).unwrap()),
        ],
        listener: Regex::new(
            r#"(?i)addEventListener\s*\(\s*['"](input|change|keydown|keyup|keypress|submit|blur|copy|paste)['"]"#,
        )
        .unwrap(),
        clipboard: Regex::new(r"(?i)clipboardData|navigator\.clipboard").unwrap(),
        wallet: Regex::new(r"\b(0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{25,62}|T[1-9A-HJ-NP-Za-km-z]{33})\b").unwrap(),
        wallet_pattern: Regex::new(r"(?i)0x\[a-f0-9|0x\[0-9a-f|bc1\[|\[13\]\[a-km").unwrap(),
        caps: vec![
            ("remote_code", Regex::new(r#"(?i)createElement\s*\(\s*['"]script|\bimport\s*\(|document\.write\s*\(\s*['"]<script|new\s+Worker\s*\(|importScripts\s*\("#).unwrap()),
            ("dynamic_code", Regex::new(r#"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*['"]|set(?:Timeout|Interval)\s*\(\s*['"]"#).unwrap()),
            ("native_hooks", Regex::new(r"(?i)Function\.prototype\.(?:call|apply|bind)\s*=|window\.fetch\s*=|(?:^|[^\w.])fetch\s*=\s*function|XMLHttpRequest\.prototype\.(?:open|send|setRequestHeader)\s*=|navigator\.clipboard\.(?:writeText|readText|write)\s*=|navigator\.share\s*=|HTMLFormElement\.prototype\.submit\s*=|window\.open\s*=|navigator\.sendBeacon\s*=|Object\.defineProperty\s*\(\s*(?:navigator|window|document)\b").unwrap()),
            ("card_logic", Regex::new(r"(?i)\bluhn\b|\(\?:\\d\[ -\]\?\)\{13,19\}|\\d\{13,19\}|x\s*\*=\s*2[^;]{0,40}>\s*9").unwrap()),
            ("screenshot", Regex::new(r"(?i)html2canvas|toDataURL\s*\(|getDisplayMedia|captureStream").unwrap()),
            ("ios_targeting", Regex::new(r"(?i)iPhone\s*\|\s*iPad|iPad\s*\|\s*iPhone|iPhone[^\n]{0,40}userAgent|userAgent[^\n]{0,60}iPhone").unwrap()),
            ("hidden_iframe", Regex::new(r#"(?i)createElement\s*\(\s*['"]iframe['"]\s*\)[\s\S]{0,300}?(?:display\s*=\s*['"]none|width\s*=\s*['"]?0\b|visibility\s*=\s*['"]hidden)"#).unwrap()),
            ("reload_loop", Regex::new(r"(?i)set(?:Interval|Timeout)\s*\([^)]{0,80}location\.reload").unwrap()),
            ("dom_rewrite", Regex::new(r"(?i)MutationObserver[\s\S]{0,400}?\.(?:value|textContent|href|src)\s*=").unwrap()),
        ],
        cookie: Regex::new(r"document\.cookie\s*(={0,2})").unwrap(),
        b64: Regex::new(r#"['"`]([A-Za-z0-9+/]{24,}={0,2})['"`]"#).unwrap(),
        hex: Regex::new(r"((?:\\x[0-9a-fA-F]{2}){8,})").unwrap(),
        charcode: Regex::new(r"fromCharCode\s*\(\s*((?:\d{2,3}\s*,\s*){5,}\d{2,3})\s*\)").unwrap(),
    })
}

pub struct Caps {
    pub hosts: BTreeSet<String>,
    pub sensitive: BTreeSet<String>,
    pub sinks: BTreeSet<String>,
    pub obfuscation: BTreeSet<String>,
    pub listeners: BTreeSet<String>,
    pub clipboard: bool,
    pub wallets: BTreeSet<String>,
    pub wallet_patterns: bool,
    pub size: usize,
    pub entropy: f64,
    pub caps: BTreeSet<String>,
    pub hidden_code: bool,
}

fn entropy(s: &str) -> f64 {
    // same summation order as Python's Counter (first-occurrence order)
    let mut order: Vec<char> = vec![];
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        let e = counts.entry(c).or_insert(0);
        if *e == 0 {
            order.push(c);
        }
        *e += 1;
    }
    let n = s.chars().count() as f64;
    if n == 0.0 {
        return 0.0;
    }
    -order.iter().map(|c| { let p = counts[c] as f64 / n; p * p.log2() }).sum::<f64>()
}

/// Approximates Python's str.isprintable() (plus \n \r \t): control, non-ASCII spacing, format and
/// private-use characters are not printable.
fn printable(c: char) -> bool {
    if c == '\n' || c == '\r' || c == '\t' || c == ' ' {
        return true;
    }
    let u = c as u32;
    !(c.is_control()
        || c.is_whitespace()
        || (0x200B..=0x200F).contains(&u)
        || (0x202A..=0x202E).contains(&u)
        || (0x2060..=0x2064).contains(&u)
        || u == 0xFEFF
        || u == 0xAD
        || (0xE000..=0xF8FF).contains(&u))
}

fn b64_lenient(s: &str) -> Option<Vec<u8>> {
    use base64::alphabet::STANDARD as ALPHA;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    let core = s.trim_end_matches('=');
    if core.len() % 4 == 1 {
        return None;
    }
    let cfg = GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    GeneralPurpose::new(&ALPHA, cfg).decode(core).ok()
}

/// Decode text hidden in base64, \x escapes and String.fromCharCode lists (recursively), like Python `reveal`.
pub fn reveal(src: &str) -> String {
    let r = rx();
    let mut out: Vec<String> = vec![];
    let mut frontier = vec![src.to_string()];
    let mut total = 0usize;
    for _ in 0..3 {
        let mut nxt = vec![];
        for text in &frontier {
            for c in r.b64.captures_iter(text) {
                if let Some(raw) = b64_lenient(&c[1]) {
                    if let Ok(dec) = String::from_utf8(raw) {
                        let n = dec.chars().count();
                        if n > 0 && dec.chars().filter(|ch| printable(*ch)).count() as f64 / n as f64 > 0.95 {
                            nxt.push(dec);
                        }
                    }
                }
            }
            for c in r.hex.captures_iter(text) {
                if let Ok(bytes) = hex::decode(c[1].replace("\\x", "")) {
                    if let Ok(dec) = String::from_utf8(bytes) {
                        nxt.push(dec);
                    }
                }
            }
            for c in r.charcode.captures_iter(text) {
                let s: Option<String> = c[1].split(',').map(|x| x.trim().parse::<u32>().ok().and_then(char::from_u32)).collect();
                if let Some(s) = s {
                    nxt.push(s);
                }
            }
        }
        if nxt.is_empty() {
            break;
        }
        total += nxt.iter().map(|x| x.chars().count()).sum::<usize>();
        out.extend(nxt.iter().cloned());
        frontier = nxt;
        if total > 2_000_000 {
            break;
        }
    }
    out.join("\n")
}

pub fn capabilities(src0: &str) -> Caps {
    let r = rx();
    let hidden = reveal(src0);
    let combined;
    let src: &str = if hidden.is_empty() { src0 } else { combined = format!("{src0}\n{hidden}"); &combined };
    let mut hosts: BTreeSet<String> = r.url.captures_iter(src).map(|c| c[1].to_lowercase()).collect();
    hosts.extend(r.host_lit.captures_iter(src).map(|c| c[1].to_lowercase()));
    let mut caps: BTreeSet<String> = r.caps.iter().filter(|(_, x)| x.is_match(src)).map(|(k, _)| k.to_string()).collect();
    if r.cookie.captures_iter(src).any(|c| &c[1] != "=") {
        caps.insert("cookie_read".into());
    }
    Caps {
        hosts,
        sensitive: r.sensitive.find_iter(src).map(|m| m.as_str().to_lowercase()).collect(),
        sinks: r.sinks.iter().filter(|(_, x)| x.is_match(src)).map(|(k, _)| k.to_string()).collect(),
        obfuscation: r.obf.iter().filter(|(_, x)| x.is_match(src)).map(|(k, _)| k.to_string()).collect(),
        listeners: r.listener.captures_iter(src).map(|c| c[1].to_lowercase()).collect(),
        clipboard: r.clipboard.is_match(src),
        wallets: r.wallet.captures_iter(src).map(|c| c[1].to_string()).collect(),
        wallet_patterns: r.wallet_pattern.is_match(src),
        size: src.chars().count(),
        entropy: entropy(src),
        caps,
        hidden_code: !hidden.is_empty(),
    }
}

pub fn sri(src: &str) -> String {
    format!("sha384-{}", STANDARD.encode(Sha384::digest(src.as_bytes())))
}

/// Returns {"candidate_sha256", "sri", "verdict", "findings": [{"severity","code"}]}. Mirrors Python `check`.
pub fn check(previous: Option<&str>, candidate: &str, allowed_hosts: &[String]) -> Value {
    let digest = hex::encode(Sha256::digest(candidate.as_bytes()));
    if previous == Some(candidate) {
        return json!({"candidate_sha256": digest, "sri": sri(candidate), "verdict": "pass", "findings": []});
    }
    let allowed: HashSet<String> = allowed_hosts.iter().map(|h| h.to_lowercase()).collect();
    let new = capabilities(candidate);
    let old = previous.map(capabilities);
    let added = |n: &BTreeSet<String>, o: Option<&BTreeSet<String>>| -> BTreeSet<String> {
        match o {
            Some(o) => n.difference(o).cloned().collect(),
            None => n.clone(),
        }
    };
    let new_hosts: BTreeSet<String> =
        added(&new.hosts, old.as_ref().map(|o| &o.hosts)).into_iter().filter(|h| !allowed.contains(h)).collect();
    let new_sens = added(&new.sensitive, old.as_ref().map(|o| &o.sensitive));
    let new_sinks = added(&new.sinks, old.as_ref().map(|o| &o.sinks));
    let new_listen = added(&new.listeners, old.as_ref().map(|o| &o.listeners));
    let new_obf = added(&new.obfuscation, old.as_ref().map(|o| &o.obfuscation));
    let new_wallets = added(&new.wallets, old.as_ref().map(|o| &o.wallets));
    let new_caps = added(&new.caps, old.as_ref().map(|o| &o.caps));

    let mut findings: Vec<(&str, String)> = vec![];
    let mut f = |sev: &'static str, code: &str| findings.push((sev, code.to_string()));
    if !new_hosts.is_empty() { f("high", "new_host"); }
    if !new_sens.is_empty() { f("high", "new_sensitive_field_access"); }
    if !new_sinks.is_empty() { f("medium", "new_network_sink"); }
    if !new_listen.is_empty() { f("medium", "new_input_listener"); }
    if !new_obf.is_empty() { f("medium", "new_obfuscation"); }
    let old_wp = old.as_ref().is_some_and(|o| o.wallet_patterns);
    if !new_wallets.is_empty() || (new.wallet_patterns && !old_wp) {
        f("high", "wallet_address_material");
    }
    if new.clipboard && !old.as_ref().is_some_and(|o| o.clipboard) {
        f("medium", "new_clipboard_access");
    }
    if let Some(o) = &old {
        if o.size > 0 && (new.size as f64) > 1.5 * o.size as f64 + 2000.0 {
            f("low", "size_jump");
        }
    }
    if new.entropy > 5.5 && old.as_ref().is_none_or(|o| new.entropy - o.entropy > 0.5) {
        f("medium", "entropy_jump");
    }
    for c in &new_caps {
        f("high", &format!("new_{c}"));
    }
    let new_hidden = new.hidden_code && !old.as_ref().is_some_and(|o| o.hidden_code);
    if new_hidden {
        f("high", "new_hidden_code");
    }
    let has = |c: &str| new_caps.contains(c);
    let reads_secrets = !new_sens.is_empty() || !new_listen.is_empty()
        || (!new.sensitive.is_empty() && !new_sinks.is_empty() && !new_hosts.is_empty());
    let sends_out = !new_hosts.is_empty() || !new_sinks.is_empty();
    let new_wallet_material = !new_wallets.is_empty() || (new.wallet_patterns && !old_wp);
    let wallet_swap = new_wallet_material && (new.clipboard || candidate.contains("replace"));
    let any_sink = !new.sinks.is_empty();
    let hard = has("native_hooks")
        || (has("remote_code") && (!new_hosts.is_empty() || new_hidden))
        || (has("dynamic_code") && (new_hidden || !new_obf.is_empty()))
        || (has("card_logic") && (sends_out || any_sink))
        || (has("cookie_read") && sends_out)
        || (has("screenshot") && (sends_out || any_sink))
        || (has("ios_targeting") && has("hidden_iframe"))
        || (has("reload_loop") && has("hidden_iframe"));
    // first version: everything looks "new"; a human reviews it once (mirrors Python)
    let verdict = if previous.is_none() {
        findings.push(("low", "no_baseline".into()));
        "review"
    } else if (reads_secrets && sends_out) || wallet_swap || hard {
        "block"
    } else if findings.iter().any(|(s, _)| *s == "high" || *s == "medium") {
        "review"
    } else {
        "pass"
    };
    json!({
        "candidate_sha256": digest,
        "sri": sri(candidate),
        "verdict": verdict,
        "findings": findings.iter().map(|(s, c)| json!({"severity": s, "code": c})).collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------- gates

pub struct GatePolicy {
    pub signatures: usize,
    pub protected_branches: Vec<String>,
    pub rewrite_budget: HashMap<String, u64>,
    pub write_budget: HashMap<String, Vec<(String, u64)>>,
    pub delete_lock_seconds: f64,
    pub publish_allowed_hosts: Vec<String>,
}

impl GatePolicy {
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let strs = |x: Option<&Value>| -> Vec<String> {
            x.and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };
        let mut write_budget = HashMap::new();
        if let Some(m) = v.get("write_budget").and_then(Value::as_object) {
            for (ident, caps) in m {
                let mut e = vec![];
                for (pat, n) in caps.as_object().ok_or("write_budget entries must be objects")? {
                    if pat.contains('[') {
                        return Err(format!("unsupported pattern syntax: {pat}"));
                    }
                    e.push((pat.clone(), n.as_u64().ok_or("write budget must be an integer")?));
                }
                write_budget.insert(ident.clone(), e);
            }
        }
        let protected = if v.get("protected_branches").is_some() {
            strs(v.get("protected_branches"))
        } else {
            vec!["main".into(), "master".into(), "release/*".into()]
        };
        Ok(GatePolicy {
            signatures: v.get("signatures").and_then(Value::as_u64).unwrap_or(2) as usize,
            protected_branches: protected,
            rewrite_budget: v
                .get("rewrite_budget")
                .and_then(Value::as_object)
                .map(|m| m.iter().filter_map(|(k, n)| n.as_u64().map(|n| (k.clone(), n))).collect())
                .unwrap_or_default(),
            write_budget,
            delete_lock_seconds: v.get("delete_lock_seconds").and_then(Value::as_f64).unwrap_or(72.0 * 3600.0),
            publish_allowed_hosts: strs(v.get("publish_allowed_hosts")),
        })
    }
}

pub fn gate_message(gid: &str, fingerprint: &str) -> Vec<u8> {
    format!("mastyf-gate|{gid}|{fingerprint}").into_bytes()
}

struct GateInner {
    journal: Option<Journal>,
    verifier: GrantCheck,
    live: HashMap<String, String>,
    pending: HashMap<String, (f64, bool)>,
    ledger: HashMap<String, VecDeque<(f64, u64)>>,
}

pub struct ChangeGate {
    durable: OnceLock<Durability>,
    pub approver_devices: OnceLock<crate::ApproverDevices>,
    p: GatePolicy,
    approvers: HashMap<String, VerifyingKey>,
    inner: Mutex<GateInner>,
}

fn res(ok: bool, reason: impl Into<String>) -> Value {
    json!({"ok": ok, "reason": reason.into()})
}

impl ChangeGate {
    pub fn new(p: GatePolicy, verifier: GrantCheck, approvers: HashMap<String, VerifyingKey>) -> Self {
        ChangeGate { durable: OnceLock::new(), approver_devices: OnceLock::new(), p, approvers, inner: Mutex::new(GateInner { journal: None, verifier, live: HashMap::new(),
                                                                   pending: HashMap::new(), ledger: HashMap::new() }) }
    }

    /// Attach a journal: replay (counters, live versions, pending deletions survive restarts), compact.
    pub fn attach_journal(&self, mut j: Journal, events: Vec<Value>, now: f64) -> Result<usize, String> {
        let mut inner = self.inner.lock().unwrap();
        let mut live_last: HashMap<String, Value> = HashMap::new();
        let mut keep = vec![];
        for ev in events {
            match ev.get("e").and_then(Value::as_str) {
                Some("gid") => {
                    let exp = ev["exp"].as_f64().unwrap_or(0.0);
                    if exp >= now {
                        inner.verifier.mark_used(ev["node"].as_str().unwrap_or(""), ev["gid"].as_str().unwrap_or(""), exp);
                        keep.push(ev);
                    }
                }
                Some("ledger") => {
                    let ts = ev["ts"].as_f64().unwrap_or(0.0);
                    if ts > now - DAY {
                        inner.ledger.entry(ev["k"].as_str().unwrap_or("").into()).or_default()
                            .push_back((ts, ev["n"].as_u64().unwrap_or(0)));
                        keep.push(ev);
                    }
                }
                Some("live") => {
                    let r = ev["res"].as_str().unwrap_or("").to_string();
                    inner.live.insert(r.clone(), ev["content"].as_str().unwrap_or("").into());
                    live_last.insert(r, ev);
                }
                Some("pending") => {
                    inner.pending.insert(ev["gid"].as_str().unwrap_or("").into(),
                                         (ev["exec"].as_f64().unwrap_or(0.0), ev["cancelled"].as_bool().unwrap_or(false)));
                    keep.push(ev);
                }
                _ => {}
            }
        }
        keep.extend(live_last.into_values());
        let n = keep.len();
        j.rewrite(&keep)?;
        let _ = self.durable.set(j.durability()?);
        inner.journal = Some(j);
        Ok(n)
    }

    pub fn flush(&self) -> Result<(), String> {
        match self.durable.get() {
            Some(d) => d.flush(),
            None => Ok(()),
        }
    }

    fn journal(inner: &mut GateInner, v: Value) -> Result<(), String> {
        match inner.journal.as_mut() {
            Some(j) => j.write(&v),
            None => Ok(()),
        }
    }

    pub fn set_live(&self, resource: &str, content: &str) {
        self.inner.lock().unwrap().live.insert(resource.into(), content.into());
    }

    fn signers(&self, gid: &str, a: &Action, sigs: &[Value]) -> usize {
        let msg = gate_message(gid, &a.fingerprint());
        let mut ok = HashSet::new();
        for s in sigs {
            if let Some(name) = crate::approver_signed(&self.approvers, self.approver_devices.get(), s, &msg) {
                if name != a.identity {
                    ok.insert(name);
                }
            }
        }
        ok.len()
    }

    fn used(dq: &mut VecDeque<(f64, u64)>, now: f64) -> u64 {
        while dq.front().is_some_and(|(t, _)| *t <= now - DAY) {
            dq.pop_front();
        }
        dq.iter().map(|(_, n)| *n).sum()
    }

    /// Apply a change; an approved change is reported only after its journal entries are on disk.
    pub fn apply(&self, grant: &str, a: &Action, sigs: &[Value], content: Option<&str>, now: f64) -> Value {
        let r = self.apply_inner(grant, a, sigs, content, now);
        if r["ok"] == json!(true) || r.get("pending_id").is_some() {
            if let Some(d) = self.durable.get() {
                let seq = self.inner.lock().unwrap().journal.as_ref().map(|j| j.seq).unwrap_or(0);
                if let Err(e) = d.sync(seq) {
                    return res(false, format!("journal sync failed: refusing (fail closed): {e}"));
                }
            }
        }
        r
    }

    fn apply_inner(&self, grant: &str, a: &Action, sigs: &[Value], content: Option<&str>, now: f64) -> Value {
        if !GATED.contains(&a.action_type.as_str()) {
            return res(false, format!("{} is not handled by this gate", a.action_type));
        }
        let mut inner = self.inner.lock().unwrap();
        let payload: Map<String, Value> = match inner.verifier.verify_pub(grant, a, now) {
            Ok(p) => p,
            Err(e) => return res(false, format!("grant rejected: {e}")),
        };
        for (node, g, exp) in GrantCheck::consumed(&payload) {
            if Self::journal(&mut inner, json!({"e": "gid", "node": node, "gid": g, "exp": exp})).is_err() {
                return res(false, "journal write failed: refusing (fail closed)");
            }
        }
        let gid = payload.get("gid").and_then(Value::as_str).unwrap_or("").to_string();
        let quorum = self.signers(&gid, a, sigs) >= self.p.signatures;
        match a.action_type.as_str() {
            "artifact.publish" => {
                let Some(content) = content else {
                    return res(false, "no artifact content: the gate checks content itself");
                };
                let rep = check(inner.live.get(&a.resource).map(String::as_str), content, &self.p.publish_allowed_hosts);
                if rep["candidate_sha256"].as_str() != a.artifact.as_deref() {
                    return res(false, "content does not match the granted artifact hash");
                }
                let verdict = rep["verdict"].as_str().unwrap_or("block");
                if verdict == "block" {
                    return res(false, "integrity block at the gate");
                }
                if verdict == "review" && !quorum {
                    return res(false, format!("integrity review needs {} approver signatures", self.p.signatures));
                }
                if Self::journal(&mut inner, json!({"e": "live", "res": a.resource, "content": content})).is_err() {
                    return res(false, "journal write failed: refusing (fail closed)");
                }
                inner.live.insert(a.resource.clone(), content.to_string());
                res(true, format!("published ({verdict})"))
            }
            "repo.history_rewrite" => {
                let rest = a.resource.split_once("://").map(|x| x.1).unwrap_or("");
                let parts: Vec<&str> = rest.split('/').collect();
                let branch = if parts.len() > 2 { parts[2..].join("/") } else { String::new() };
                if self.p.protected_branches.iter().any(|p| fnmatch(&branch, p)) {
                    return if quorum { res(true, "protected rewrite approved by quorum") }
                           else { res(false, format!("protected branch: needs {} approver signatures", self.p.signatures)) };
                }
                let cap = *self.p.rewrite_budget.get(&a.identity).unwrap_or(&0);
                let k = format!("rewrite|{}", a.identity);
                let dq = inner.ledger.entry(k.clone()).or_default();
                if !quorum && Self::used(dq, now) + a.count > cap {
                    return res(false, format!("rewrite budget: {} commits over {cap}/24h for {}", a.count, a.identity));
                }
                if Self::journal(&mut inner, json!({"e": "ledger", "k": k, "ts": now, "n": a.count})).is_err() {
                    return res(false, "journal write failed: refusing (fail closed)");
                }
                inner.ledger.entry(k).or_default().push_back((now, a.count));
                res(true, if quorum { "rewrite approved by quorum" } else { "rewrite within budget" })
            }
            "file.write_bulk" => {
                let target = a.destination.clone().unwrap_or_else(|| a.resource.clone());
                let (cap_key, cap) = self
                    .p
                    .write_budget
                    .get(&a.identity)
                    .and_then(|caps| caps.iter().find(|(k, _)| fnmatch(&target, k)).cloned())
                    .unwrap_or((target.clone(), 0));
                let k = format!("write|{}|{cap_key}", a.identity);
                let dq = inner.ledger.entry(k.clone()).or_default();
                if !quorum && Self::used(dq, now) + a.count > cap {
                    return res(false, format!("write budget: {} files to {target} over {cap}/24h", a.count));
                }
                if Self::journal(&mut inner, json!({"e": "ledger", "k": k, "ts": now, "n": a.count})).is_err() {
                    return res(false, "journal write failed: refusing (fail closed)");
                }
                inner.ledger.entry(k).or_default().push_back((now, a.count));
                res(true, if quorum { "write approved by quorum" } else { "write within budget" })
            }
            _ => {
                if !quorum {
                    return res(false, format!("backup deletion needs {} approver signatures", self.p.signatures));
                }
                let exec = now + self.p.delete_lock_seconds;
                if Self::journal(&mut inner, json!({"e": "pending", "gid": gid, "exec": exec, "cancelled": false})).is_err() {
                    return res(false, "journal write failed: refusing (fail closed)");
                }
                inner.pending.insert(gid.clone(), (exec, false));
                let mut r = res(false, format!("queued: executes after {} h unless cancelled",
                                               (self.p.delete_lock_seconds / 3600.0) as u64));
                r["pending_id"] = json!(gid);
                r
            }
        }
    }
}

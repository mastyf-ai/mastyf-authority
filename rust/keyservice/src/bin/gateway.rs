//! mastyf-gateway: the internet-facing front door of the authority, in Rust.
//!
//! Everything from outside lands here first. The Python decision engine listens on localhost only
//! and receives nothing but requests this gateway has already checked and re-encoded:
//!   - TLS 1.3 only (rustls); optional client certificates (--tls-client-ca)
//!   - HTTP/1.1 parsed with `httparse`; GET/POST only; known paths only; headers <= 16 KB;
//!     Content-Length bodies <= 2 MB; chunked/Transfer-Encoding refused (no request smuggling)
//!   - per-caller API keys (sha256 callers file, same as the authority); unknown key -> 401, and
//!     repeated failures from one address are slowed down
//!   - per-caller rate limit (token bucket) and a cap on open connections
//!   - JSON bodies parsed and re-serialized (the engine never sees the raw bytes); for /v1/decide the
//!     action's identity must be the caller's own, checked here as well as in the engine
//!   - engine down or slow: /v1/decide answers DENY (fails closed)
//!
//!   mastyf-gateway --listen 0.0.0.0:443 --tls-cert cert.pem --tls-key key.pem --callers callers.json \
//!                  --upstream 127.0.0.1:8740 [--tls-client-ca ca.pem] [--rate 50] [--burst 200] [--max-clients 1024]

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mastyf_keyservice::http::{read_request, ReadErr, Req, MAX_BODY, MAX_HEAD};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

const PUBLIC: [&str; 5] = ["/healthz", "/approve", "/enroll", "/web/app.js", "/web/app.css"];
const GET_API: [&str; 7] = ["/v1/alerts", "/v1/pending", "/v1/public-key", "/v1/devices", "/v1/enroll/pending",
                            "/v1/enroll/status", "/metrics"];
const POST_API: [&str; 18] = ["/v1/agents/session", "/v1/agents/revoke", "/v1/decide", "/v1/approve", "/v1/deny", "/v1/script/check", "/v1/grant/verify",
                              "/v1/freeze", "/v1/unfreeze", "/v1/enroll/begin", "/v1/enroll/authorise",
                              "/v1/enroll/approve", "/v1/enroll/finish", "/v1/devices/remove", "/v1/decide/batch", "/v1/noop",
                              "/v1/replication", "/v1/promote"];
const PASS_HEADERS: [&str; 5] = ["content-type", "content-security-policy", "x-content-type-options",
                                 "referrer-policy", "cache-control"];

/// every `--name value` / `--name=value`
fn args_all(args: &[String], name: &str) -> Vec<String> {
    let eq = format!("{name}=");
    args.iter().enumerate().filter_map(|(i, a)| {
        if a == name { args.get(i + 1).cloned() } else { a.strip_prefix(&eq).map(String::from) }
    }).collect()
}

/// `--name value` or `--name=value`
fn arg(args: &[String], name: &str) -> Option<String> {
    let eq = format!("{name}=");
    args.iter().enumerate().find_map(|(i, a)| {
        if a == name { args.get(i + 1).cloned() } else { a.strip_prefix(&eq).map(String::from) }
    })
}

fn die(msg: &str) -> ! {
    eprintln!("mastyf-gateway: {msg}");
    std::process::exit(2)
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

/// One engine pair (a shard): its engines and which of them is deciding.
struct Group {
    name: String,
    upstreams: Vec<String>,
    active: AtomicUsize, // index into upstreams of the engine currently deciding
}

struct Gate {
    callers: HashMap<String, String>, // sha256 hex of key -> identity
    groups: Vec<Group>,               // one per shard (a single unnamed one unless --shard is used)
    promote_key: Option<String>,    // bearer key the standby engine accepts for /v1/promote
    failover_after: Duration,
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
    failures: Mutex<HashMap<IpAddr, Bucket>>,
    open: AtomicUsize,
    max_clients: usize,
    oidc: Option<mastyf_keyservice::oidc::Oidc>, // single sign-on tokens (oidc.rs)
    gateway_key: Option<String>,                 // what the gateway presents to engines for SSO callers
}

impl Gate {
    fn take<K: std::hash::Hash + Eq + Clone>(map: &Mutex<HashMap<K, Bucket>>, k: &K, rate: f64, burst: f64) -> bool {
        let mut m = map.lock().unwrap();
        let now = Instant::now();
        let b = m.entry(k.clone()).or_insert(Bucket { tokens: burst, at: now });
        b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * rate).min(burst);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn json_resp(status: u16, v: Value) -> Resp {
    Resp { status, headers: vec![("Content-Type".into(), "application/json".into())], body: v.to_string().into_bytes() }
}

fn write_resp<S: Write>(s: &mut S, r: &Resp, close: bool) -> std::io::Result<()> {
    let reason = match r.status {
        200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found",
        405 => "Method Not Allowed", 411 => "Length Required", 413 => "Payload Too Large", 429 => "Too Many Requests",
        431 => "Request Header Fields Too Large", 500 => "Internal Server Error", 502 => "Bad Gateway",
        503 => "Service Unavailable", 505 => "HTTP Version Not Supported", _ => "",
    };
    let mut out = format!("HTTP/1.1 {} {reason}\r\n", r.status);
    for (k, v) in &r.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Strict-Transport-Security: max-age=63072000; includeSubDomains\r\nX-Frame-Options: DENY\r\n");
    let has = |n: &str| r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    if !has("x-content-type-options") {
        out.push_str("X-Content-Type-Options: nosniff\r\n");
    }
    if !has("cross-origin-resource-policy") {
        out.push_str("Cross-Origin-Resource-Policy: same-origin\r\n");
    }
    if !has("cache-control") {
        out.push_str("Cache-Control: no-store\r\n"); // decisions and grants must never be cached
    }
    out.push_str(&format!("Content-Length: {}\r\n", r.body.len()));
    if close {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    s.write_all(out.as_bytes())?;
    s.write_all(&r.body)?;
    s.flush()
}

/// `ident`: an SSO caller's identity, checked by the gateway, sent with the gateway's own key.
#[allow(clippy::too_many_arguments)]
fn upstream_call_as(g: &Gate, gi: usize, conn: &mut Option<TcpStream>, method: &str, target: &str, auth: Option<&str>,
                    ident: Option<&str>, body: &[u8]) -> Result<Resp, String> {
    let grp = &g.groups[gi];
    let target_up = &grp.upstreams[grp.active.load(Ordering::SeqCst)];
    if g.groups.len() > 1 || grp.upstreams.len() > 1 {
        use std::net::ToSocketAddrs;
        let want: Vec<std::net::SocketAddr> = target_up.to_socket_addrs().map(|i| i.collect()).unwrap_or_default();
        if conn.as_ref().is_some_and(|c| !c.peer_addr().is_ok_and(|a| want.contains(&a))) {
            *conn = None; // another engine (failover, or another shard): never send to the wrong one
        }
    }
    for attempt in 0..2 {
        if conn.is_none() {
            let c = TcpStream::connect(target_up).map_err(|e| e.to_string())?;
            let _ = c.set_read_timeout(Some(UPSTREAM_TIMEOUT));
            let _ = c.set_write_timeout(Some(UPSTREAM_TIMEOUT));
            let _ = c.set_nodelay(true);
            *conn = Some(c);
        }
        let c = conn.as_mut().unwrap();
        let mut head = format!("{method} {target} HTTP/1.1\r\nHost: authority\r\nContent-Length: {}\r\n", body.len());
        if let Some(a) = auth {
            head.push_str(&format!("Authorization: {a}\r\n"));
        }
        if let Some(i) = ident {
            head.push_str(&format!("X-Authority-Identity: {i}\r\n"));
        }
        if !body.is_empty() {
            head.push_str("Content-Type: application/json\r\n");
        }
        head.push_str("\r\n");
        let sent = c.write_all(head.as_bytes()).and_then(|_| c.write_all(body));
        match sent.map_err(|e| e.to_string()).and_then(|_| read_response(c)) {
            Ok((r, keep)) => {
                if !keep {
                    *conn = None;
                }
                return Ok(r);
            }
            Err(e) => {
                *conn = None;
                if attempt == 1 {
                    return Err(e);
                }
            }
        }
    }
    Err("upstream failed".into())
}

fn read_response(c: &mut TcpStream) -> Result<(Resp, bool), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 16384];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err("upstream headers too large".into());
        }
        match c.read(&mut tmp) {
            Ok(0) => return Err("upstream closed".into()),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(e.to_string()),
        }
    };
    let mut hs = [httparse::EMPTY_HEADER; 32];
    let mut r = httparse::Response::new(&mut hs);
    if !matches!(r.parse(&buf[..head_end]), Ok(httparse::Status::Complete(_))) {
        return Err("bad upstream response".into());
    }
    let status = r.code.unwrap_or(502);
    let (mut len, mut keep, mut headers) = (None, true, vec![]);
    for h in r.headers.iter() {
        let n = h.name.to_ascii_lowercase();
        let v = String::from_utf8_lossy(h.value).to_string();
        if n == "content-length" {
            len = v.trim().parse::<usize>().ok();
        } else if n == "connection" && v.eq_ignore_ascii_case("close") {
            keep = false;
        } else if PASS_HEADERS.contains(&n.as_str()) {
            headers.push((h.name.to_string(), v));
        }
    }
    let len = len.ok_or("upstream response without length")?;
    if len > 8 * MAX_BODY {
        return Err("upstream response too large".into());
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        match c.read(&mut tmp) {
            Ok(0) => return Err("upstream closed".into()),
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(e.to_string()),
        }
    }
    body.truncate(len);
    Ok((Resp { status, headers, body }, keep))
}

/// One plain HTTP call to an engine (they listen on a private network / localhost).
fn engine_call(addr: &str, method: &str, path: &str, auth: Option<&str>, body: &[u8]) -> Option<Value> {
    use std::net::ToSocketAddrs;
    let sa = addr.to_socket_addrs().ok()?.next()?;
    let mut c = TcpStream::connect_timeout(&sa, Duration::from_secs(1)).ok()?;
    let _ = c.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = c.set_write_timeout(Some(Duration::from_secs(2)));
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: authority\r\nConnection: close\r\nContent-Length: {}\r\n",
                           body.len());
    if let Some(a) = auth {
        head.push_str(&format!("Authorization: Bearer {a}\r\nContent-Type: application/json\r\n"));
    }
    head.push_str("\r\n");
    c.write_all(head.as_bytes()).ok()?;
    c.write_all(body).ok()?;
    let (r, _) = read_response(&mut c).ok()?;
    let mut v: Value = serde_json::from_slice(&r.body).ok()?;
    v["_status"] = json!(r.status);
    Some(v)
}

/// Every second: route to the engine that reports `active` with the highest epoch. If none is active
/// for `failover_after`, promote a healthy standby (it fences the key service before it decides).
/// One health round: route to the active engine with the highest epoch. True if one was found.
fn pick_active(g: &Gate, gi: usize) -> bool {
    let grp = &g.groups[gi];
    let best = grp.upstreams.iter().enumerate()
        .filter_map(|(i, u)| engine_call(u, "GET", "/healthz", None, b"").filter(|h| h["role"] == "active")
            .map(|h| (h["epoch"].as_u64().unwrap_or(0), i)))
        .max();
    if let Some((_, i)) = best {
        grp.active.store(i, Ordering::SeqCst);
    }
    best.is_some()
}

fn failover_loop(g: &Gate, gi: usize) {
    let grp = &g.groups[gi];
    let mut no_active_since: Option<Instant> = None;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let health: Vec<Option<Value>> = grp.upstreams.iter().map(|u| engine_call(u, "GET", "/healthz", None, b"")).collect();
        let best = health.iter().enumerate()
            .filter_map(|(i, h)| h.as_ref().filter(|h| h["role"] == "active").map(|h| (h["epoch"].as_u64().unwrap_or(0), i)))
            .max();
        if let Some((epoch, i)) = best {
            if grp.active.swap(i, Ordering::SeqCst) != i {
                eprintln!("mastyf-gateway: shard {:?}: routing to {} (active, epoch {epoch})", grp.name, grp.upstreams[i]);
            }
            no_active_since = None;
            continue;
        }
        let since = *no_active_since.get_or_insert_with(Instant::now);
        if since.elapsed() < g.failover_after {
            continue;
        }
        let Some(key) = g.promote_key.as_deref() else { continue };
        if let Some(i) = health.iter().position(|h| h.as_ref().is_some_and(|h| h["role"] == "standby")) {
            eprintln!("mastyf-gateway: shard {:?}: no active engine for {:?}; promoting {}", grp.name, since.elapsed(),
                      grp.upstreams[i]);
            let r = engine_call(&grp.upstreams[i], "POST", "/v1/promote", Some(key),
                                br#"{"reason": "gateway: active engine unreachable"}"#);
            let promoted = r.as_ref().is_some_and(|v| v["ok"] == true && v["role"] == "active");
            eprintln!("mastyf-gateway: promote answered {}", r.map(|v| v.to_string()).unwrap_or_else(|| "nothing".into()));
            if promoted {
                grp.active.store(i, Ordering::SeqCst); // route to it at once, not at the next health check
                no_active_since = None;
            }
        }
    }
}

fn handle(g: &Gate, ip: IpAddr, req: &Req, ups: &mut [Option<TcpStream>]) -> Resp {
    let fail_closed = |why: &str| json_resp(503, json!({"verdict": "DENY", "reasons": [format!("{why}; failing closed")]}));
    let is_get = req.method == "GET";
    if req.method != "GET" && req.method != "POST" {
        return json_resp(405, json!({"error": "method not allowed"}));
    }
    if !(req.query.is_empty() || is_get && req.path == "/v1/enroll/status") {
        return json_resp(400, json!({"error": "query strings not accepted here"}));
    }
    // engines of a shard name it on health and replication calls; everything else is routed by identity
    let named = match req.shard.as_deref() {
        Some(n) => match g.groups.iter().position(|x| x.name == n) {
            Some(i) => Some(i),
            None => return json_resp(404, json!({"error": "unknown shard"})),
        },
        None => None,
    };
    if is_get && PUBLIC.contains(&req.path.as_str()) {
        return upstream_call_as(g, named.unwrap_or(0), &mut ups[named.unwrap_or(0)], "GET", &req.path, None, None, b"")
            .unwrap_or_else(|_| json_resp(502, json!({"error": "authority unavailable"})));
    }
    let known = if is_get { GET_API.contains(&req.path.as_str()) } else { POST_API.contains(&req.path.as_str()) };
    if !known {
        return json_resp(404, json!({"error": "not found"}));
    }
    // authentication: the caller's own key, or a single sign-on token from the identity provider
    let bearer = req.auth.as_deref().and_then(|a| a.strip_prefix("Bearer "));
    let mut sso: Option<String> = None;
    let mut who = bearer.filter(|k| k.len() <= 256)
        .and_then(|k| g.callers.get(&hex::encode(Sha256::digest(k.as_bytes())))).cloned();
    if who.is_none() {
        if let (Some(o), Some(t)) = (g.oidc.as_ref(), bearer) {
            if mastyf_keyservice::oidc::Oidc::looks_like_jwt(t) {
                match o.verify(t, mastyf_keyservice::oidc::now()) {
                    Ok(id) => {
                        sso = Some(id.clone());
                        who = Some(id);
                    }
                    Err(e) => eprintln!("mastyf-gateway: sign-on token refused: {e}"),
                }
            }
        }
    }
    let Some(who) = who else {
        if !Gate::take(&g.failures, &ip, 0.2, 10.0) {
            std::thread::sleep(Duration::from_millis(500)); // slow down key guessing from one address
        }
        return json_resp(401, json!({"error": "unauthorized"}));
    };
    let who = &who;
    if !Gate::take(&g.buckets, &who.to_string(), g.rate, g.burst) {
        return if req.path == "/v1/decide" {
            json_resp(429, json!({"verdict": "DENY", "reasons": ["rate limit"]}))
        } else {
            json_resp(429, json!({"error": "rate limit"}))
        };
    }
    let gw_auth = g.gateway_key.as_ref().map(|k| format!("Bearer {k}"));
    let (auth, ident) = match &sso {
        Some(id) => (gw_auth.as_deref(), Some(id.as_str())),
        None => (req.auth.as_deref(), None),
    };
    let target = if req.query.is_empty() { req.path.clone() } else { format!("{}?{}", req.path, req.query) };
    let sharded = g.groups.len() > 1;
    if sharded && FANOUT.contains(&(req.method.as_str(), req.path.as_str())) {
        return fanout(g, &req.method, &target, auth, ident, &req.body);
    }
    if is_get {
        let gi = named.unwrap_or_else(|| shard_for(g, who));
        return upstream_call_as(g, gi, &mut ups[gi], "GET", &target, auth, ident, b"")
            .unwrap_or_else(|_| json_resp(502, json!({"error": "authority unavailable"})));
    }
    // POST: strict JSON object, re-encoded
    let v: Value = match serde_json::from_slice(&req.body) {
        Ok(v @ Value::Object(_)) => v,
        _ => {
            return if req.path == "/v1/decide" {
                json_resp(400, json!({"verdict": "DENY", "reasons": ["bad request: body must be a JSON object"]}))
            } else {
                json_resp(400, json!({"error": "body must be a JSON object"}))
            }
        }
    };
    if req.path == "/v1/decide" && v.pointer("/action/identity").and_then(Value::as_str) != Some(who.as_str()) {
        return json_resp(403, json!({"verdict": "DENY", "reasons": ["action identity must be the caller's own"]}));
    }
    let body = v.to_string().into_bytes();
    let gi = if req.path == "/v1/replication" || req.path == "/v1/promote" {
        match named {
            Some(i) => i,
            None if sharded => return json_resp(400, json!({"error": "name the shard (X-Authority-Shard)"})),
            None => 0,
        }
    } else {
        shard_for(g, routing_identity(&req.path, &v, who))
    };
    match upstream_call_as(g, gi, &mut ups[gi], "POST", &target, auth, ident, &body) {
        Ok(r) => r,
        Err(_) if req.path == "/v1/decide" => fail_closed("authority unavailable"),
        Err(_) => json_resp(502, json!({"error": "authority unavailable"})),
    }
}

/// Calls every shard and merges the answers (lists of alerts, pending requests, devices; metrics).
const FANOUT: [(&str, &str); 7] = [("GET", "/v1/alerts"), ("GET", "/v1/pending"), ("GET", "/v1/devices"),
                                   ("GET", "/v1/enroll/pending"), ("GET", "/metrics"), ("POST", "/v1/script/check"),
                                   ("POST", "/v1/agents/revoke")];

/// Rendezvous hashing: an identity always lands on the same shard, and adding a shard moves only the
/// identities that now score highest on it (about 1 in N), which start a new baseline there.
fn shard_for(g: &Gate, identity: &str) -> usize {
    if g.groups.len() == 1 {
        return 0;
    }
    g.groups.iter().enumerate()
        .max_by_key(|(_, grp)| {
            let h = Sha256::digest(format!("{}|{identity}", grp.name).as_bytes());
            u64::from_be_bytes(h[..8].try_into().unwrap())
        })
        .map(|(i, _)| i).unwrap_or(0)
}

/// Whose state a request touches: the requester of an approval, the identity being frozen, the action's
/// identity for grant checks, the agent of an agent session; otherwise the caller.
fn routing_identity<'a>(path: &str, v: &'a Value, who: &'a str) -> &'a str {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    match path {
        "/v1/approve" | "/v1/deny" => s("/requester"),
        "/v1/freeze" | "/v1/unfreeze" | "/v1/devices/remove" => s("/identity"),
        "/v1/grant/verify" => s("/action/identity"),
        "/v1/agents/session" => s("/manifest/agent").or(s("/agent")),
        _ => None,
    }.unwrap_or(who)
}

fn merge(into: &mut Value, add: Value) {
    match (into, add) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                match a.get_mut(&k) {
                    Some(Value::Array(x)) => {
                        if let Value::Array(y) = v {
                            x.extend(y);
                        }
                    }
                    Some(o @ Value::Object(_)) => merge(o, v),
                    Some(_) => {}
                    None => {
                        a.insert(k, v);
                    }
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => a.extend(b),
        _ => {}
    }
}

fn fanout(g: &Gate, method: &str, target: &str, auth: Option<&str>, ident: Option<&str>, body: &[u8]) -> Resp {
    let mut parts = vec![];
    for gi in 0..g.groups.len() {
        let mut c = None;
        if let Ok(r) = upstream_call_as(g, gi, &mut c, method, target, auth, ident, body) {
            parts.push((gi, r));
        }
    }
    if parts.is_empty() {
        return json_resp(502, json!({"error": "authority unavailable"}));
    }
    if target == "/metrics" {
        let mut out = String::new();
        for (gi, r) in &parts {
            out.push_str(&format!("# shard {}\n{}", g.groups[*gi].name, String::from_utf8_lossy(&r.body)));
        }
        return Resp { status: 200, headers: vec![("Content-Type".into(), "text/plain; version=0.0.4".into())],
                      body: out.into_bytes() };
    }
    if method == "POST" {  // one shard did it (revoke) or all did (script check): the best answer
        let pick = parts.iter().position(|(_, r)| r.status == 200).unwrap_or(0);
        return parts.swap_remove(pick).1;
    }
    let mut acc = Value::Null;
    let mut status = 200;
    for (_, r) in parts {
        if r.status != 200 {
            status = r.status;
            continue;
        }
        let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        if acc.is_null() { acc = v } else { merge(&mut acc, v) }
    }
    json_resp(if acc.is_null() { status } else { 200 }, acc)
}

fn serve_conn<S: Read + Write>(g: &Gate, ip: IpAddr, mut s: S) {
    let mut buf = Vec::new();
    // one kept-alive engine connection per shard (alternating shards must not reconnect every request)
    let mut ups: Vec<Option<TcpStream>> = (0..g.groups.len()).map(|_| None).collect();
    loop {
        match read_request(&mut s, &mut buf) {
            Ok(req) => {
                let resp = handle(g, ip, &req, &mut ups);
                if write_resp(&mut s, &resp, req.close).is_err() || req.close {
                    return;
                }
            }
            Err(ReadErr::Bad(code, why)) => {
                let _ = write_resp(&mut s, &json_resp(code, json!({"error": why})), true);
                return;
            }
            Err(ReadErr::Closed) => return,
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let need = |n: &str| arg(&args, n).unwrap_or_else(|| die(&format!("{n} required")));
    let callers: HashMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(need("--callers")).unwrap_or_else(|e| die(&e.to_string())))
        .unwrap_or_else(|e| die(&e.to_string()));
    if callers.keys().any(|k| k.len() != 64 || !k.chars().all(|c| c.is_ascii_hexdigit())) {
        die("callers file must map sha256 hex digests to identities");
    }
    let num = |n: &str, d: f64| arg(&args, n).map(|v| v.parse().unwrap_or_else(|_| die(&format!("bad {n}")))).unwrap_or(d);
    let g = Arc::new(Gate {
        callers,
        groups: {
            let sh = args_all(&args, "--shard");
            if sh.is_empty() {
                let u = args_all(&args, "--upstream");
                vec![Group { name: String::new(), upstreams: if u.is_empty() { vec!["127.0.0.1:8740".into()] } else { u },
                             active: AtomicUsize::new(0) }]
            } else {
                // --shard NAME=host:port,host:port (one per engine pair)
                let mut gs: Vec<Group> = sh.iter().map(|s| {
                    let (n, ups) = s.split_once('=').unwrap_or_else(|| die("--shard NAME=host:port[,host:port]"));
                    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                        die("shard names: letters, digits, - and _");
                    }
                    Group { name: n.into(), upstreams: ups.split(',').map(String::from).collect(), active: AtomicUsize::new(0) }
                }).collect();
                gs.sort_by(|a, b| a.name.cmp(&b.name));
                gs.dedup_by(|a, b| a.name == b.name);
                gs
            }
        },
        promote_key: arg(&args, "--promote-key-file").map(|p| std::fs::read_to_string(p)
            .unwrap_or_else(|e| die(&e.to_string())).trim().to_string()),
        failover_after: Duration::from_secs_f64(num("--failover-after", 3.0)),
        rate: num("--rate", 50.0), burst: num("--burst", 200.0),
        buckets: Mutex::new(HashMap::new()), failures: Mutex::new(HashMap::new()),
        open: AtomicUsize::new(0), max_clients: num("--max-clients", 1024.0) as usize,
        oidc: arg(&args, "--oidc-issuer").map(|iss| {
            let map: HashMap<String, String> = arg(&args, "--oidc-map")
                .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| die(&e.to_string())))
                    .unwrap_or_else(|e| die(&format!("--oidc-map: {e}"))))
                .unwrap_or_default();
            mastyf_keyservice::oidc::Oidc::new(iss, args_all(&args, "--oidc-audience"), need("--oidc-jwks"),
                                                arg(&args, "--oidc-claim"), map, arg(&args, "--oidc-identity-format"))
                .unwrap_or_else(|e| die(&e))
        }),
        gateway_key: arg(&args, "--gateway-key-file").map(|p| std::fs::read_to_string(p)
            .unwrap_or_else(|e| die(&e.to_string())).trim().to_string()),
    });
    if g.oidc.is_some() && g.gateway_key.is_none() {
        die("--oidc-issuer needs --gateway-key-file (the key engines accept as \"gateway\")");
    }
    let load_certs = |p: &str| mastyf_keyservice::ha::load_certs(p).unwrap_or_else(|e| die(&e));
    let key = mastyf_keyservice::ha::load_key(&need("--tls-key")).unwrap_or_else(|e| die(&e));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap_or_else(|e| die(&e.to_string()));
    let builder = match arg(&args, "--tls-client-ca") {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for c in load_certs(&ca) {
                roots.add(c).unwrap_or_else(|e| die(&e.to_string()));
            }
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                    .build().unwrap_or_else(|e| die(&e.to_string())))
        }
        None => builder.with_no_client_auth(),
    };
    let mut cfg = builder.with_single_cert(load_certs(&need("--tls-cert")), key).unwrap_or_else(|e| die(&e.to_string()));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cfg = Arc::new(cfg);
    // SIGTERM/SIGINT: exit at once (stateless; PID 1 in a container would otherwise ignore SIGTERM)
    let mut sigs = signal_hook::iterator::Signals::new([signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT])
        .unwrap_or_else(|e| die(&e.to_string()));
    std::thread::spawn(move || {
        if sigs.forever().next().is_some() {
            eprintln!("mastyf-gateway: stopping");
            std::process::exit(0);
        }
    });
    let listen = need("--listen");
    let listener = std::net::TcpListener::bind(&listen).unwrap_or_else(|e| die(&e.to_string()));
    for (gi, grp) in g.groups.iter().enumerate() {
        eprintln!("mastyf-gateway: TLS 1.3 on {listen} -> shard {:?}: engines {:?}", grp.name, grp.upstreams);
        if grp.upstreams.len() > 1 {
            // know which engine is active before taking traffic (after a failover it is not the first one)
            if !pick_active(&g, gi) {
                eprintln!("mastyf-gateway: shard {:?}: no active engine yet; its decisions fail closed until one is", grp.name);
            }
            let g2 = g.clone();
            std::thread::spawn(move || failover_loop(&g2, gi));
        }
    }
    for tcp in listener.incoming().flatten() {
        let ip = tcp.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
        if g.open.fetch_add(1, Ordering::SeqCst) >= g.max_clients {
            g.open.fetch_sub(1, Ordering::SeqCst);
            drop(tcp); // over capacity: refuse quickly rather than queue without bound
            continue;
        }
        let _ = tcp.set_read_timeout(Some(CLIENT_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(CLIENT_TIMEOUT));
        let (g, cfg) = (Arc::clone(&g), Arc::clone(&cfg));
        std::thread::spawn(move || {
            if let Ok(conn) = rustls::ServerConnection::new(cfg) {
                serve_conn(&g, ip, rustls::StreamOwned::new(conn, tcp));
            }
            g.open.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

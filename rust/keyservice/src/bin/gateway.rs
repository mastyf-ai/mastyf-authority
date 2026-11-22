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

fn args_all(args: &[String], name: &str) -> Vec<String> {
    args.iter().enumerate().filter(|(_, a)| *a == name).filter_map(|(i, _)| args.get(i + 1).cloned()).collect()
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn die(msg: &str) -> ! {
    eprintln!("mastyf-gateway: {msg}");
    std::process::exit(2)
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

struct Gate {
    callers: HashMap<String, String>, // sha256 hex of key -> identity
    upstreams: Vec<String>,
    active: AtomicUsize,            // index into upstreams of the engine currently deciding
    promote_key: Option<String>,    // bearer key the standby engine accepts for /v1/promote
    failover_after: Duration,
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
    failures: Mutex<HashMap<IpAddr, Bucket>>,
    open: AtomicUsize,
    max_clients: usize,
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
    out.push_str(&format!("Content-Length: {}\r\n", r.body.len()));
    if close {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    s.write_all(out.as_bytes())?;
    s.write_all(&r.body)?;
    s.flush()
}

fn upstream_call(g: &Gate, conn: &mut Option<TcpStream>, method: &str, target: &str, auth: Option<&str>, body: &[u8])
                 -> Result<Resp, String> {
    if g.upstreams.len() > 1 {
        use std::net::ToSocketAddrs;
        let want: Vec<std::net::SocketAddr> = g.upstreams[g.active.load(Ordering::SeqCst)].to_socket_addrs()
            .map(|i| i.collect()).unwrap_or_default();
        if conn.as_ref().is_some_and(|c| !c.peer_addr().is_ok_and(|a| want.contains(&a))) {
            *conn = None; // the active engine changed (failover): never send to the old one
        }
    }
    for attempt in 0..2 {
        if conn.is_none() {
            let c = TcpStream::connect(&g.upstreams[g.active.load(Ordering::SeqCst)]).map_err(|e| e.to_string())?;
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
fn failover_loop(g: &Gate) {
    let mut no_active_since: Option<Instant> = None;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let health: Vec<Option<Value>> = g.upstreams.iter().map(|u| engine_call(u, "GET", "/healthz", None, b"")).collect();
        let best = health.iter().enumerate()
            .filter_map(|(i, h)| h.as_ref().filter(|h| h["role"] == "active").map(|h| (h["epoch"].as_u64().unwrap_or(0), i)))
            .max();
        if let Some((epoch, i)) = best {
            if g.active.swap(i, Ordering::SeqCst) != i {
                eprintln!("mastyf-gateway: routing to {} (active, epoch {epoch})", g.upstreams[i]);
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
            eprintln!("mastyf-gateway: no active engine for {:?}; promoting {}", since.elapsed(), g.upstreams[i]);
            let r = engine_call(&g.upstreams[i], "POST", "/v1/promote", Some(key),
                                br#"{"reason": "gateway: active engine unreachable"}"#);
            let promoted = r.as_ref().is_some_and(|v| v["ok"] == true && v["role"] == "active");
            eprintln!("mastyf-gateway: promote answered {}", r.map(|v| v.to_string()).unwrap_or_else(|| "nothing".into()));
            if promoted {
                g.active.store(i, Ordering::SeqCst); // route to it at once, not at the next health check
                no_active_since = None;
            }
        }
    }
}

fn handle(g: &Gate, ip: IpAddr, req: &Req, up: &mut Option<TcpStream>) -> Resp {
    let fail_closed = |why: &str| json_resp(503, json!({"verdict": "DENY", "reasons": [format!("{why}; failing closed")]}));
    let is_get = req.method == "GET";
    if req.method != "GET" && req.method != "POST" {
        return json_resp(405, json!({"error": "method not allowed"}));
    }
    if !(req.query.is_empty() || is_get && req.path == "/v1/enroll/status") {
        return json_resp(400, json!({"error": "query strings not accepted here"}));
    }
    if is_get && PUBLIC.contains(&req.path.as_str()) {
        return upstream_call(g, up, "GET", &req.path, None, b"")
            .unwrap_or_else(|_| json_resp(502, json!({"error": "authority unavailable"})));
    }
    let known = if is_get { GET_API.contains(&req.path.as_str()) } else { POST_API.contains(&req.path.as_str()) };
    if !known {
        return json_resp(404, json!({"error": "not found"}));
    }
    // authentication
    let who = req.auth.as_deref().and_then(|a| a.strip_prefix("Bearer ")).filter(|k| k.len() <= 256)
        .and_then(|k| g.callers.get(&hex::encode(Sha256::digest(k.as_bytes()))));
    let Some(who) = who else {
        if !Gate::take(&g.failures, &ip, 0.2, 10.0) {
            std::thread::sleep(Duration::from_millis(500)); // slow down key guessing from one address
        }
        return json_resp(401, json!({"error": "unauthorized"}));
    };
    if !Gate::take(&g.buckets, &who.to_string(), g.rate, g.burst) {
        return if req.path == "/v1/decide" {
            json_resp(429, json!({"verdict": "DENY", "reasons": ["rate limit"]}))
        } else {
            json_resp(429, json!({"error": "rate limit"}))
        };
    }
    let auth = req.auth.as_deref();
    let target = if req.query.is_empty() { req.path.clone() } else { format!("{}?{}", req.path, req.query) };
    if is_get {
        return upstream_call(g, up, "GET", &target, auth, b"")
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
    match upstream_call(g, up, "POST", &target, auth, &body) {
        Ok(r) => r,
        Err(_) if req.path == "/v1/decide" => fail_closed("authority unavailable"),
        Err(_) => json_resp(502, json!({"error": "authority unavailable"})),
    }
}

fn serve_conn<S: Read + Write>(g: &Gate, ip: IpAddr, mut s: S) {
    let mut buf = Vec::new();
    let mut up: Option<TcpStream> = None;
    loop {
        match read_request(&mut s, &mut buf) {
            Ok(req) => {
                let resp = handle(g, ip, &req, &mut up);
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
        upstreams: { let u = args_all(&args, "--upstream"); if u.is_empty() { vec!["127.0.0.1:8740".into()] } else { u } },
        active: AtomicUsize::new(0),
        promote_key: arg(&args, "--promote-key-file").map(|p| std::fs::read_to_string(p)
            .unwrap_or_else(|e| die(&e.to_string())).trim().to_string()),
        failover_after: Duration::from_secs_f64(num("--failover-after", 3.0)),
        rate: num("--rate", 50.0), burst: num("--burst", 200.0),
        buckets: Mutex::new(HashMap::new()), failures: Mutex::new(HashMap::new()),
        open: AtomicUsize::new(0), max_clients: num("--max-clients", 1024.0) as usize,
    });
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
    let listen = need("--listen");
    let listener = std::net::TcpListener::bind(&listen).unwrap_or_else(|e| die(&e.to_string()));
    eprintln!("mastyf-gateway: TLS 1.3 on {listen} -> authority engines {:?}", g.upstreams);
    if g.upstreams.len() > 1 {
        let g2 = g.clone();
        std::thread::spawn(move || failover_loop(&g2));
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

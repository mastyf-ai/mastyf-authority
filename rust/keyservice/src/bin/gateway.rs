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

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 2 * 1024 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

const PUBLIC: [&str; 5] = ["/healthz", "/approve", "/enroll", "/web/app.js", "/web/app.css"];
const GET_API: [&str; 7] = ["/v1/alerts", "/v1/pending", "/v1/public-key", "/v1/devices", "/v1/enroll/pending",
                            "/v1/enroll/status", "/metrics"];
const POST_API: [&str; 16] = ["/v1/agents/session", "/v1/agents/revoke", "/v1/decide", "/v1/approve", "/v1/deny", "/v1/script/check", "/v1/grant/verify",
                              "/v1/freeze", "/v1/unfreeze", "/v1/enroll/begin", "/v1/enroll/authorise",
                              "/v1/enroll/approve", "/v1/enroll/finish", "/v1/devices/remove", "/v1/decide/batch", "/v1/noop"];
const PASS_HEADERS: [&str; 5] = ["content-type", "content-security-policy", "x-content-type-options",
                                 "referrer-policy", "cache-control"];

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
    upstream: String,
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

struct Req {
    method: String,
    path: String,
    query: String,
    auth: Option<String>,
    body: Vec<u8>,
    close: bool,
}

enum ReadErr {
    Closed,
    Bad(u16, &'static str),
}

fn read_request<S: Read>(s: &mut S, buf: &mut Vec<u8>) -> Result<Req, ReadErr> {
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(ReadErr::Bad(431, "request headers too large"));
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return Err(ReadErr::Closed),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    if head_end > MAX_HEAD {
        return Err(ReadErr::Bad(431, "request headers too large"));
    }
    let mut hs = [httparse::EMPTY_HEADER; 32];
    let mut r = httparse::Request::new(&mut hs);
    match r.parse(&buf[..head_end]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(ReadErr::Bad(400, "malformed request")),
    }
    if r.version != Some(1) {
        return Err(ReadErr::Bad(505, "HTTP/1.1 only"));
    }
    let method = r.method.unwrap_or("").to_string();
    let target = r.path.unwrap_or("").to_string();
    let (mut len, mut auth, mut close, mut seen_len) = (0usize, None, false, false);
    for h in r.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        let v = std::str::from_utf8(h.value).map_err(|_| ReadErr::Bad(400, "bad header"))?;
        match name.as_str() {
            "transfer-encoding" => return Err(ReadErr::Bad(411, "chunked bodies not accepted")),
            "content-length" => {
                if seen_len {
                    return Err(ReadErr::Bad(400, "duplicate content-length"));
                }
                seen_len = true;
                len = v.trim().parse().map_err(|_| ReadErr::Bad(400, "bad content-length"))?;
            }
            "authorization" => auth = Some(v.to_string()),
            "connection" => close = v.eq_ignore_ascii_case("close"),
            _ => {}
        }
    }
    if len > MAX_BODY {
        return Err(ReadErr::Bad(413, "body too large"));
    }
    buf.drain(..head_end);
    while buf.len() < len {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return Err(ReadErr::Closed),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let body: Vec<u8> = buf.drain(..len).collect();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    Ok(Req { method, path, query, auth, body, close })
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
    for attempt in 0..2 {
        if conn.is_none() {
            let c = TcpStream::connect(&g.upstream).map_err(|e| e.to_string())?;
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
        callers, upstream: arg(&args, "--upstream").unwrap_or_else(|| "127.0.0.1:8740".into()),
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
    eprintln!("mastyf-gateway: TLS 1.3 on {listen} -> authority at {}", g.upstream);
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

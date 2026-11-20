//! JSON-lines front end: one request per line on stdin, one response per line on stdout.
//!
//!   mastyf-keyservice --policy policies/default.json --authority-key authority.pub.pem \
//!                     [--authority-key node2.pem ... --threshold 2] [--approvers approvers.json] \
//!                     [--socket /path/ks.sock] [--fake-clock]
//!
//! Without --socket it serves stdin/stdout. With --socket it listens on a Unix socket created
//! with mode 0600 (only the owning account can connect) and serves many clients concurrently.
//! Several --authority-key flags plus --threshold t require grants from t distinct authority nodes.
//!
//! Requests:
//!   {"op":"release","grant":"...","action":{...},"overrun":[...]}
//!   {"op":"new_record_key","record_id":"r1","class":"crm.customer"}
//!
//! `--fake-clock` (tests only) lets each request carry "now". Without it the service always
//! uses its own clock and ignores any "now" sent by callers.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::VerifyingKey;
use mastyf_keyservice::binding::{CaseRegistry, DeviceRegistry};
use mastyf_keyservice::gates::{check, ChangeGate, GatePolicy};
use mastyf_keyservice::{Action, BudgetPolicy, GrantCheck, GrantVerifier, Journal, KeyService, QuorumVerifier};
use serde_json::{json, Value};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn args_all(args: &[String], name: &str) -> Vec<String> {
    args.iter().enumerate().filter(|(_, a)| *a == name).filter_map(|(i, _)| args.get(i + 1).cloned()).collect()
}

static STATE_LOCK: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

struct Svc {
    ks: KeyService,
    gate: Option<ChangeGate>,
    undo: Option<mastyf_keyservice::undo::UndoGate>,
}

fn handle(svc: &Svc, line: &str, fake_clock: bool) -> Value {
    let ks = &svc.ks;
    match serde_json::from_str::<Value>(line) {
        Err(_) => json!({"ok": false, "reason": "bad request"}),
        Ok(req) => {
            let now = if fake_clock {
                req.get("now").and_then(Value::as_f64).unwrap_or(0.0)
            } else {
                SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
            };
            match req.get("op").and_then(Value::as_str) {
                Some("release") => match req.get("action").map(Action::from_json) {
                    Some(Ok(a)) => {
                        let grant = req.get("grant").and_then(Value::as_str).unwrap_or("");
                        let ov = req.get("overrun").and_then(Value::as_array).cloned().unwrap_or_default();
                        serde_json::to_value(ks.release(grant, &a, &ov, now)).unwrap()
                    }
                    Some(Err(e)) => json!({"ok": false, "reason": format!("bad action: {e}")}),
                    None => json!({"ok": false, "reason": "missing action"}),
                },
                Some("new_record_key") => {
                    match (req.get("record_id").and_then(Value::as_str), req.get("class").and_then(Value::as_str)) {
                        (Some(r), Some(c)) => json!({"ok": true, "dek": URL_SAFE_NO_PAD.encode(ks.new_record_key(r, c))}),
                        _ => json!({"ok": false, "reason": "record_id and class required"}),
                    }
                }
                Some("unfreeze") => {
                    let sigs = req.get("sigs").and_then(Value::as_array).cloned().unwrap_or_default();
                    match ks.unfreeze(req["identity"].as_str().unwrap_or(""), req["until"].as_u64().unwrap_or(0), &sigs, now) {
                        Ok(()) => json!({"ok": true}),
                        Err(e) => json!({"ok": false, "reason": e}),
                    }
                }
                Some("health") => json!({"ok": true, "service": "mastyf-keyservice", "version": env!("CARGO_PKG_VERSION"),
                                         "gates": svc.gate.is_some()}),
                Some("assign_case") => {
                    let recs: Vec<String> = req.get("records").and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                    let ok = ks.assign_case(req["case"].as_str().unwrap_or(""), req["to"].as_str().unwrap_or(""), recs,
                                            req["exp"].as_u64().unwrap_or(0), req["sig"].as_str().unwrap_or(""));
                    json!({"ok": ok})
                }
                Some("check_script") => {
                    let allowed: Vec<String> = req.get("allowed_hosts").and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                    match req.get("candidate").and_then(Value::as_str) {
                        Some(c) => check(req.get("previous").and_then(Value::as_str), c, &allowed),
                        None => json!({"ok": false, "reason": "candidate required"}),
                    }
                }
                Some("gate") | Some("gate_set_live") => match &svc.gate {
                    None => json!({"ok": false, "reason": "no change_gates in policy"}),
                    Some(g) if req["op"] == "gate_set_live" && fake_clock => {
                        g.set_live(req["resource"].as_str().unwrap_or(""), req["content"].as_str().unwrap_or(""));
                        json!({"ok": true})
                    }
                    Some(_) if req["op"] == "gate_set_live" => json!({"ok": false, "reason": "test only"}),
                    Some(g) => match req.get("action").map(Action::from_json) {
                        Some(Ok(a)) => {
                            let grant = req.get("grant").and_then(Value::as_str).unwrap_or("");
                            let sigs = req.get("sigs").and_then(Value::as_array).cloned().unwrap_or_default();
                            g.apply(grant, &a, &sigs, req.get("content").and_then(Value::as_str), now)
                        }
                        Some(Err(e)) => json!({"ok": false, "reason": format!("bad action: {e}")}),
                        None => json!({"ok": false, "reason": "missing action"}),
                    },
                },
                Some(op) if op.starts_with("undo_") => match &svc.undo {
                    None => json!({"ok": false, "reason": "no undo_windows in policy"}),
                    Some(u) => {
                        let s = |k: &str| req.get(k).and_then(Value::as_str).unwrap_or("");
                        match op {
                            "undo_submit" => match req.get("action").map(Action::from_json) {
                                Some(Ok(a)) => u.submit(s("grant"), &a, now),
                                Some(Err(e)) => json!({"ok": false, "reason": format!("bad action: {e}")}),
                                None => json!({"ok": false, "reason": "missing action"}),
                            },
                            "undo_cancel" => u.cancel(s("pid"), s("by")),
                            "undo_expedite" => u.expedite(s("pid"), req.get("sigs").and_then(Value::as_array)
                                .map(Vec::as_slice).unwrap_or(&[]), now),
                            "undo_panic" => u.panic(s("by"), req.get("identity").and_then(Value::as_str)),
                            "undo_due" => u.due(now),
                            "undo_execute" => u.execute(s("pid"), now),
                            _ => json!({"ok": false, "reason": "unknown op"}),
                        }
                    }
                },
                _ => json!({"ok": false, "reason": "unknown op"}),
            }
        }
    }
}

fn serve_lines<R: BufRead, W: Write>(ks: &Svc, input: R, mut out: W, fake_clock: bool) {
    for line in input.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > 4 * 1024 * 1024 {
            let _ = writeln!(out, "{}", json!({"ok": false, "reason": "request too large"}));
            continue;
        }
        let resp = handle(ks, &line, fake_clock);
        if writeln!(out, "{resp}").and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}

/// Mutual-TLS listener (TLS 1.3 only). Clients must present a certificate issued by --tls-client-ca;
/// anything else fails the handshake before a single request is read.
fn serve_tls(addr: &str, cert: &str, key: &str, ca: &str, svc: Arc<Svc>, fake_clock: bool) {
    use std::io::Read;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let load_certs = |p: &str| mastyf_keyservice::ha::load_certs(p).unwrap_or_else(|e| die(&e));
    let key = mastyf_keyservice::ha::load_key(key).unwrap_or_else(|e| die(&e));
    let mut roots = rustls::RootCertStore::empty();
    for c in load_certs(ca) {
        roots.add(c).unwrap_or_else(|e| die(&e.to_string()));
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build().unwrap_or_else(|e| die(&e.to_string()));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap_or_else(|e| die(&e.to_string()))
            .with_client_cert_verifier(verifier)
            .with_single_cert(load_certs(cert), key).unwrap_or_else(|e| die(&e.to_string())),
    );
    let listener = std::net::TcpListener::bind(addr).unwrap_or_else(|e| die(&e.to_string()));
    eprintln!("mastyf-keyservice: mutual TLS on {addr}");
    for conn in listener.incoming() {
        let Ok(tcp) = conn else { continue };
        let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(60)));
        let _ = tcp.set_write_timeout(Some(std::time::Duration::from_secs(60)));
        let (svc, config) = (Arc::clone(&svc), Arc::clone(&config));
        std::thread::spawn(move || {
            let Ok(conn) = rustls::ServerConnection::new(config) else { return };
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut pending: Vec<u8> = Vec::new();
            let mut buf = [0u8; 16384];
            loop {
                while let Some(pos) = pending.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = pending.drain(..=pos).collect();
                    let text = String::from_utf8_lossy(&line[..line.len() - 1]).to_string();
                    if text.trim().is_empty() {
                        continue;
                    }
                    let resp = handle(&svc, &text, fake_clock);
                    if writeln!(tls, "{resp}").and_then(|_| tls.flush()).is_err() {
                        return;
                    }
                }
                if pending.len() > 4 * 1024 * 1024 {
                    let _ = writeln!(tls, "{}", json!({"ok": false, "reason": "request too large"}));
                    return;
                }
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => pending.extend_from_slice(&buf[..n]),
                }
            }
        });
    }
}

/// Device registry (--devices file) and case system key (--case-key PEM), attached before journal replay.
fn attach_registries(ks: &KeyService, args: &[String], outside_allowance: u64) {
    if let Some(p) = arg(args, "--devices") {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| die(&e.to_string())))
            .unwrap_or_else(|e| die(&e.to_string()));
        ks.set_devices(DeviceRegistry::from_json(&v).unwrap_or_else(|e| die(&e)));
    }
    if let Some(p) = arg(args, "--case-key") {
        let pk = VerifyingKey::from_public_key_pem(&std::fs::read_to_string(p).unwrap_or_else(|e| die(&e.to_string())))
            .unwrap_or_else(|e| die(&e.to_string()));
        ks.set_cases(CaseRegistry::new(pk, outside_allowance));
    }
}

/// The key-encryption key: from --kek-command (e.g. a KMS decrypt), or --kek-file (0600).
/// --init-kek creates the file once. Never generated silently: losing it loses every record key.
fn load_kek(args: &[String], dir: &std::path::Path) -> [u8; 32] {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let decode = |s: &str| -> [u8; 32] {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .or_else(|_| URL_SAFE_NO_PAD.decode(s.trim()))
            .unwrap_or_else(|_| die("KEK is not valid base64"));
        raw.try_into().unwrap_or_else(|_| die("KEK must be exactly 32 bytes"))
    };
    if let Some(cmd) = arg(args, "--kek-command") {
        let out = std::process::Command::new("/bin/sh").arg("-c").arg(&cmd).output()
            .unwrap_or_else(|e| die(&format!("kek command failed: {e}")));
        if !out.status.success() {
            die("kek command exited with an error");
        }
        return decode(&String::from_utf8_lossy(&out.stdout));
    }
    let path = arg(args, "--kek-file").map(std::path::PathBuf::from).unwrap_or_else(|| dir.join("kek.b64"));
    if !path.exists() {
        if !args.iter().any(|a| a == "--init-kek") {
            die("no KEK: pass --kek-command, --kek-file, or --init-kek to create one (then back it up / wrap it in a KMS)");
        }
        let mut k = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut k);
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)
            .unwrap_or_else(|e| die(&e.to_string()));
        std::io::Write::write_all(&mut f, base64::engine::general_purpose::STANDARD.encode(k).as_bytes())
            .unwrap_or_else(|e| die(&e.to_string()));
        eprintln!("mastyf-keyservice: created new KEK at {} — back it up now; losing it loses all record keys",
                  path.display());
        return k;
    }
    let mode = std::fs::metadata(&path).map(|m| m.permissions().mode()).unwrap_or(0);
    if mode & 0o077 != 0 {
        die("KEK file must not be readable by group/others (chmod 600)");
    }
    decode(&std::fs::read_to_string(&path).unwrap_or_else(|e| die(&e.to_string())))
}

/// One process per state directory (also stops KEK rotation while the service runs).
fn lock_state_dir(dir: &std::path::Path) -> std::fs::File {
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("lock"))
        .unwrap_or_else(|e| die(&e.to_string()));
    if f.try_lock().is_err() {
        die("state directory is in use by another mastyf-keyservice process");
    }
    f
}

fn die(msg: &str) -> ! {
    eprintln!("mastyf-keyservice: {msg}");
    std::process::exit(2)
}

fn ha_tls(args: &[String]) -> mastyf_keyservice::ha::TlsFiles {
    let need = |n: &str| arg(args, n).unwrap_or_else(|| die(&format!("{n} required for high availability")));
    mastyf_keyservice::ha::TlsFiles { cert: need("--ha-cert"), key: need("--ha-key"), ca: need("--ha-ca") }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("rotate-kek") {
        // mastyf-keyservice rotate-kek --state-dir D (--old-kek-file F | --old-kek-command C)
        //                              (--new-kek-file F | --new-kek-command C)
        let dir = std::path::PathBuf::from(arg(&args, "--state-dir").unwrap_or_else(|| die("--state-dir required")));
        let _lock = lock_state_dir(&dir);
        let pick = |p: &str| -> Vec<String> {
            let mut v = vec![String::new()];
            for k in ["file", "command"] {
                if let Some(x) = arg(&args, &format!("--{p}-kek-{k}")) {
                    v.push(format!("--kek-{k}"));
                    v.push(x);
                }
            }
            if v.len() == 1 {
                die(&format!("--{p}-kek-file or --{p}-kek-command required"));
            }
            v
        };
        let (old, new) = (load_kek(&pick("old"), &dir), load_kek(&pick("new"), &dir));
        let n = mastyf_keyservice::rewrap_journal(&dir.join("keyservice.journal"), old, new).unwrap_or_else(|e| die(&e));
        eprintln!("mastyf-keyservice: re-wrapped {n} record keys under the new KEK. Start the service with the new KEK, \
                   check it, then delete keyservice.pre-rotation and retire the old KEK.");
        return;
    }
    if args.get(1).map(String::as_str) == Some("witness") {
        let need = |n: &str| arg(&args, n).unwrap_or_else(|| die(&format!("witness: {n} required")));
        mastyf_keyservice::ha::run_witness(&need("--listen"), &need("--state"), &ha_tls(&args)).unwrap_or_else(|e| die(&e));
        return;
    }
    let policy_path = arg(&args, "--policy").unwrap_or_else(|| die("--policy required"));
    let key_paths = args_all(&args, "--authority-key");
    if key_paths.is_empty() {
        die("--authority-key required");
    }
    let fake_clock = args.iter().any(|a| a == "--fake-clock");
    if fake_clock {
        eprintln!("mastyf-keyservice: WARNING --fake-clock is for tests only");
    }

    let pol: Value = serde_json::from_str(&std::fs::read_to_string(&policy_path).unwrap_or_else(|e| die(&e.to_string())))
        .unwrap_or_else(|e| die(&e.to_string()));
    let budgets = pol.get("data_budgets").unwrap_or(&pol);
    let policy = BudgetPolicy::from_json(budgets).unwrap_or_else(|e| die(&e));
    let load_key = |p: &String| {
        VerifyingKey::from_public_key_pem(&std::fs::read_to_string(p).unwrap_or_else(|e| die(&e.to_string())))
            .unwrap_or_else(|e| die(&e.to_string()))
    };
    let threshold: usize = arg(&args, "--threshold").map(|t| t.parse().unwrap_or_else(|_| die("bad --threshold"))).unwrap_or(1);
    // each enforcement point keeps its own single-use record of grants
    let make_check = || if key_paths.len() == 1 && threshold == 1 {
        GrantCheck::Single(Box::new(GrantVerifier::new(load_key(&key_paths[0]))))
    } else {
        let keys = key_paths.iter().enumerate().map(|(i, p)| (format!("node{i}"), load_key(p))).collect();
        GrantCheck::Quorum(QuorumVerifier::new(keys, threshold).unwrap_or_else(|e| die(&e)))
    };
    let check = make_check();
    let mut approvers = HashMap::new();
    if let Some(p) = arg(&args, "--approvers") {
        let m: HashMap<String, String> = serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| die(&e.to_string())))
            .unwrap_or_else(|e| die(&e.to_string()));
        for (name, pem) in m {
            approvers.insert(name, VerifyingKey::from_public_key_pem(&pem).unwrap_or_else(|e| die(&e.to_string())));
        }
    }
    let gate = pol.get("change_gates").map(|g| {
        ChangeGate::new(GatePolicy::from_json(g).unwrap_or_else(|e| die(&e)), make_check(), approvers.clone())
    });
    let undo_approvers = approvers.clone();
    let outside_allowance = budgets.get("outside_case_allowance").and_then(Value::as_u64).unwrap_or(20);
    let state_dir = arg(&args, "--state-dir");
    // high availability: stand by until this node holds the witness lease, then serve
    let ha = arg(&args, "--ha-node").map(|node| {
        let need = |n: &str| arg(&args, n).unwrap_or_else(|| die(&format!("{n} required with --ha-node")));
        let cfg = mastyf_keyservice::ha::HaConfig {
            node, listen: need("--ha-listen"), peer: need("--ha-peer"), peer_node: need("--ha-peer-node"),
            witnesses: {
                let w = args_all(&args, "--ha-witness");
                if w.is_empty() {
                    die("--ha-witness required (once per witness; use 1 or 3)");
                }
                w
            },
            tls: ha_tls(&args), dir: std::path::PathBuf::from(state_dir.clone().unwrap_or_else(|| die("--ha-node needs --state-dir"))),
        };
        std::fs::create_dir_all(&cfg.dir).unwrap_or_else(|e| die(&e.to_string()));
        STATE_LOCK.set(lock_state_dir(&cfg.dir)).ok();
        let lease = mastyf_keyservice::ha::wait_until_primary(&cfg).unwrap_or_else(|e| die(&e));
        (cfg, lease)
    });
    let keysvc = match &state_dir {
        None => {
            eprintln!("mastyf-keyservice: WARNING no --state-dir: EPHEMERAL MODE. Budgets reset and record keys are \
                       lost on restart. Never use this in production.");
            let ks = KeyService::with_verifier(policy, check, approvers);
            attach_registries(&ks, &args, outside_allowance);
            ks
        }
        Some(dir) => {
            use std::os::unix::fs::PermissionsExt;
            let dir = std::path::Path::new(dir);
            std::fs::create_dir_all(dir).unwrap_or_else(|e| die(&e.to_string()));
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap_or_else(|e| die(&e.to_string()));
            if STATE_LOCK.get().is_none() {
                STATE_LOCK.set(lock_state_dir(dir)).ok();
            }
            let kek = load_kek(&args, dir);
            let ks = KeyService::with_kek(policy, check, approvers, kek);
            attach_registries(&ks, &args, outside_allowance);
            let (j, events) = Journal::open(&dir.join("keyservice.journal")).unwrap_or_else(|e| die(&e));
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
            let n = ks.attach_journal(j, events, now).unwrap_or_else(|e| die(&e));
            eprintln!("mastyf-keyservice: state restored from journal ({n} live events)");
            if !ks.kek_matches() {
                die("the configured KEK does not open the stored record keys (wrong KEK or KMS key?)");
            }
            ks
        }
    };
    if let (Some(dir), Some(g)) = (&state_dir, &gate) {
        let (j, events) = Journal::open(&std::path::Path::new(dir).join("gates.journal")).unwrap_or_else(|e| die(&e));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        let n = g.attach_journal(j, events, now).unwrap_or_else(|e| die(&e));
        eprintln!("mastyf-keyservice: gate state restored ({n} live events)");
    }
    if let Some((cfg, lease)) = ha {
        mastyf_keyservice::ha::start_primary(cfg, lease).unwrap_or_else(|e| die(&e));
    }
    // approvers' passkeys: --approver-devices, or the people's --devices registry (approvers are people)
    let appr_path = arg(&args, "--approver-devices").or_else(|| arg(&args, "--devices"));
    let appr_devs: mastyf_keyservice::ApproverDevices = Default::default();
    if let Some(p) = &appr_path {
        let reg = std::fs::read_to_string(p).map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
            .and_then(|v| DeviceRegistry::from_json(&v)).unwrap_or_else(|e| die(&format!("{p}: {e}")));
        *appr_devs.lock().unwrap() = Some(reg);
        keysvc.approver_devices.set(Arc::clone(&appr_devs)).ok();
        if let Some(g) = &gate {
            g.approver_devices.set(Arc::clone(&appr_devs)).ok();
        }
    }
    let undo = pol.get("undo_windows").map(|u| {
        mastyf_keyservice::undo::UndoGate::new(mastyf_keyservice::undo::UndoPolicy::from_json(u).unwrap_or_else(|e| die(&e)),
                                               make_check(), undo_approvers.clone())
    });
    if let (Some(dir), Some(u)) = (&state_dir, &undo) {
        let (j, events) = Journal::open(&std::path::Path::new(dir).join("undo.journal")).unwrap_or_else(|e| die(&e));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        let n = u.attach_journal(j, events, now).unwrap_or_else(|e| die(&e));
        eprintln!("mastyf-keyservice: undo state restored ({n} live events)");
    }
    if let Some(u) = &undo {
        u.approver_devices.set(Arc::clone(&appr_devs)).ok();
    }
    let ks = Arc::new(Svc { ks: keysvc, gate, undo });
    if let Some(p) = appr_path {
        let a = Arc::clone(&appr_devs);
        std::thread::spawn(move || {
            let mtime = |p: &str| std::fs::metadata(p).and_then(|m| m.modified()).ok();
            let mut seen = mtime(&p);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let now = mtime(&p);
                if now == seen {
                    continue;
                }
                seen = now;
                match std::fs::read_to_string(&p).map_err(|e| e.to_string())
                    .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
                    .and_then(|v| DeviceRegistry::from_json(&v)) {
                    Ok(mut reg) => {
                        let mut g = a.lock().unwrap();
                        if let Some(old) = g.take() {
                            reg.counters = old.counters;
                            reg.cloned = old.cloned;
                        }
                        *g = Some(reg);
                    }
                    Err(e) => eprintln!("mastyf-keyservice: ALERT approver passkeys unreadable, keeping previous: {e}"),
                }
            }
        });
    }
    // device enrolment writes the --devices file atomically; pick up additions and removals
    if let Some(p) = arg(&args, "--devices") {
        let f = Arc::clone(&ks);
        std::thread::spawn(move || {
            let mtime = |p: &str| std::fs::metadata(p).and_then(|m| m.modified()).ok();
            let mut seen = mtime(&p);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let now = mtime(&p);
                if now == seen {
                    continue;
                }
                seen = now;
                match std::fs::read_to_string(&p).map_err(|e| e.to_string())
                    .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
                    .and_then(|v| DeviceRegistry::from_json(&v)) {
                    Ok(reg) => {
                        f.ks.update_devices(reg);
                        eprintln!("mastyf-keyservice: device registry reloaded");
                    }
                    Err(e) => eprintln!("mastyf-keyservice: ALERT device registry unreadable, keeping previous: {e}"),
                }
            }
        });
    }
    if state_dir.is_some() {
        let f = Arc::clone(&ks);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(200));
            if let Err(e) = f.ks.flush() {
                eprintln!("mastyf-keyservice: journal flush failed: {e}");
            }
            if let Some(g) = &f.gate {
                if let Err(e) = g.flush() {
                    eprintln!("mastyf-keyservice: gate journal flush failed: {e}");
                }
            }
            if let Some(u) = &f.undo {
                if let Err(e) = u.flush() {
                    eprintln!("mastyf-keyservice: undo journal flush failed: {e}");
                }
            }
        });
    }

    if let Some(addr) = arg(&args, "--tls-listen") {
        let need = |n: &str| arg(&args, n).unwrap_or_else(|| die(&format!("{n} required with --tls-listen")));
        serve_tls(&addr, &need("--tls-cert"), &need("--tls-key"), &need("--tls-client-ca"), ks, fake_clock);
        return;
    }
    if let Some(path) = arg(&args, "--socket") {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        use std::os::unix::net::UnixListener;
        if let Ok(m) = std::fs::symlink_metadata(&path) {
            if m.file_type().is_socket() {
                let _ = std::fs::remove_file(&path);
            } else {
                die("refusing to replace a non-socket file at --socket path");
            }
        }
        // the socket lives in a private 0700 directory, so no other account can reach it even
        // in the moment between bind() and the chmod below
        let dir = std::path::Path::new(&path).parent().unwrap_or_else(|| die("bad --socket path"));
        std::fs::create_dir_all(dir).unwrap_or_else(|e| die(&e.to_string()));
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap_or_else(|e| die(&e.to_string()));
        let listener = UnixListener::bind(&path).unwrap_or_else(|e| die(&e.to_string()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap_or_else(|e| die(&e.to_string()));
        eprintln!("mastyf-keyservice: listening on {path} (mode 0600)");
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let ks = Arc::clone(&ks);
            std::thread::spawn(move || {
                let Ok(reader) = stream.try_clone() else { return };
                serve_lines(&ks, BufReader::new(reader), stream, fake_clock);
            });
        }
        return;
    }
    let stdin = std::io::stdin();
    serve_lines(&ks, stdin.lock(), std::io::stdout().lock(), fake_clock);
}

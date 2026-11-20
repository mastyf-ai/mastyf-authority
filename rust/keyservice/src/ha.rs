//! High availability: an active/passive pair of key services plus a small witness.
//!
//! Roles
//!   primary  serves clients. Every journal batch is sent to the standby and acknowledged (written and
//!            fsynced there) *before* anything that depends on it is handed out.
//!   standby  receives the journal stream, serves nobody, and takes over when the primary goes quiet.
//!   witness  a tiny referee holding one lease: who is primary, under which epoch, and which nodes are
//!            known to hold every committed write ("synced"). Run 1 or (recommended) 3 witnesses on
//!            separate hosts; every decision needs a MAJORITY of them, so any one can be lost.
//!
//! Safety rules (why there are never two primaries handing out keys, and nothing is lost on failover)
//!   1. A primary commits a batch only if the standby acknowledged it, OR a majority of witnesses first
//!      recorded "only the primary is synced" under the primary's own epoch at each (degraded mode).
//!   2. A witness gives the lease to a new node only after the old lease expired (+ grace) AND that node
//!      is in its synced set. A node becomes primary only with a majority of such grants. Two
//!      majorities always share a witness, and a witness serves one holder at a time, so: never two
//!      primaries; and a takeover majority always includes a witness that saw any degrade, so a node
//!      that may be missing writes can never take over (recovery is then manual).
//!   3. A standby stops accepting the stream before it asks for the lease, so after it is promoted the
//!      old primary can no longer get acknowledgements, nor a degrade majority, so it refuses
//!      everything. A primary refused by a majority of witnesses exits (fenced).
//!
//! All links use mutual TLS 1.3 with the HA certificate authority.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

pub const LEASE: Duration = Duration::from_secs(4);
pub const GRACE: Duration = Duration::from_secs(1);
const RENEW_EVERY: Duration = Duration::from_millis(1000);
const PING_EVERY: Duration = Duration::from_millis(500);
const PEER_SILENCE: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_MSG: usize = 1 << 30;
pub const JOURNALS: [&str; 3] = ["keyservice", "gates", "undo"];

// ------------------------------------------------------------------------------------------- TLS

#[derive(Clone)]
pub struct TlsFiles {
    pub cert: String,
    pub key: String,
    pub ca: String,
}

type Certs = Vec<rustls::pki_types::CertificateDer<'static>>;

/// PEM certificates (rustls' own parser).
pub fn load_certs(p: &str) -> Result<Certs, String> {
    use rustls::pki_types::pem::PemObject;
    let certs = rustls::pki_types::CertificateDer::pem_file_iter(p).map_err(|e| format!("{p}: {e}"))?
        .collect::<Result<Vec<_>, _>>().map_err(|e| format!("{p}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{p}: no certificates"));
    }
    Ok(certs)
}

/// PEM private key (PKCS#8, SEC1 or PKCS#1).
pub fn load_key(p: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivateKeyDer::from_pem_file(p).map_err(|e| format!("{p}: no private key ({e})"))
}

fn roots(ca: &str) -> Result<rustls::RootCertStore, String> {
    let mut r = rustls::RootCertStore::empty();
    for c in load_certs(ca)? {
        r.add(c).map_err(|e| e.to_string())?;
    }
    Ok(r)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn server_config(f: &TlsFiles) -> Result<Arc<rustls::ServerConfig>, String> {
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots(&f.ca)?), provider())
        .build().map_err(|e| e.to_string())?;
    Ok(Arc::new(rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13]).map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(&f.cert)?, load_key(&f.key)?).map_err(|e| e.to_string())?))
}

pub fn client_config(f: &TlsFiles) -> Result<Arc<rustls::ClientConfig>, String> {
    Ok(Arc::new(rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13]).map_err(|e| e.to_string())?
        .with_root_certificates(roots(&f.ca)?)
        .with_client_auth_cert(load_certs(&f.cert)?, load_key(&f.key)?).map_err(|e| e.to_string())?))
}

// ------------------------------------------------------------------------------- JSON-line link

trait Rw: Read + Write + Send {}
impl<T: Read + Write + Send> Rw for T {}

pub struct Conn {
    s: Box<dyn Rw>,
    buf: Vec<u8>,
}

impl Conn {
    fn send(&mut self, v: &Value) -> Result<(), String> {
        let mut line = serde_json::to_vec(v).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.s.write_all(&line).and_then(|_| self.s.flush()).map_err(|e| e.to_string())
    }

    fn recv(&mut self) -> Result<Value, String> {
        let mut tmp = [0u8; 65536];
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return serde_json::from_slice(&line[..line.len() - 1]).map_err(|e| e.to_string());
            }
            if self.buf.len() > MAX_MSG {
                return Err("message too large".into());
            }
            match self.s.read(&mut tmp) {
                Ok(0) => return Err("closed".into()),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    fn call(&mut self, v: &Value) -> Result<Value, String> {
        self.send(v)?;
        self.recv()
    }
}

fn tune(tcp: &TcpStream, timeout: Duration) {
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let _ = tcp.set_nodelay(true);
}

pub fn dial(cfg: &Arc<rustls::ClientConfig>, addr: &str) -> Result<Conn, String> {
    let host = addr.rsplit_once(':').map(|x| x.0).unwrap_or(addr).trim_matches(['[', ']']);
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let sa = addr.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("no address")?;
    let tcp = TcpStream::connect_timeout(&sa, IO_TIMEOUT).map_err(|e| e.to_string())?;
    // snapshots can be large: allow longer than the per-message timeout for writes
    tune(&tcp, IO_TIMEOUT);
    let c = rustls::ClientConnection::new(Arc::clone(cfg), name).map_err(|e| e.to_string())?;
    Ok(Conn { s: Box::new(rustls::StreamOwned::new(c, tcp)), buf: vec![] })
}

fn accept(cfg: &Arc<rustls::ServerConfig>, tcp: TcpStream, timeout: Duration) -> Result<Conn, String> {
    tune(&tcp, timeout);
    let c = rustls::ServerConnection::new(Arc::clone(cfg)).map_err(|e| e.to_string())?;
    Ok(Conn { s: Box::new(rustls::StreamOwned::new(c, tcp)), buf: vec![] })
}

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("incoming");
    {
        let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600)
            .open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    if let Some(d) = path.parent() {
        if let Ok(df) = std::fs::File::open(d) {
            let _ = df.sync_all();
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------------------------- witness

#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Debug, PartialEq)]
struct WState {
    holder: Option<String>,
    epoch: u64,
    /// nodes known to hold every write the holder ever committed
    #[serde(default)]
    synced: Vec<String>,
}

struct Witness {
    path: PathBuf,
    st: WState,
    expires: Instant,
}

impl Witness {
    fn persist(&self) -> Result<(), String> {
        write_atomic(&self.path, &serde_json::to_vec(&self.st).map_err(|e| e.to_string())?)
    }

    fn handle(&mut self, req: &Value) -> Value {
        let now = Instant::now();
        let node = req["node"].as_str().unwrap_or("");
        if node.is_empty() {
            return json!({"ok": false, "reason": "node required"});
        }
        let before = self.st.clone();
        let resp = match req["op"].as_str() {
            Some("lease") => {
                let in_sync = req["in_sync"].as_bool().unwrap_or(false);
                let peer = req["peer"].as_str().unwrap_or("");
                if self.st.holder.as_deref() == Some(node) {
                    if in_sync && !peer.is_empty() {
                        let mut v = vec![node.to_string(), peer.to_string()];
                        v.sort();
                        self.st.synced = v;
                    }
                    self.expires = now + LEASE;
                    json!({"ok": true, "epoch": self.st.epoch})
                } else if self.st.holder.is_none() || now > self.expires + GRACE {
                    if self.st.holder.is_some() && !self.st.synced.iter().any(|n| n == node) {
                        json!({"ok": false, "reason": "this node may be missing writes: manual recovery needed"})
                    } else {
                        if self.st.holder.is_none() {
                            self.st.synced = vec![node.to_string()];
                        }
                        self.st.holder = Some(node.into());
                        self.st.epoch += 1;
                        self.expires = now + LEASE;
                        json!({"ok": true, "epoch": self.st.epoch, "new": true})
                    }
                } else {
                    json!({"ok": false, "reason": "lease held by another node"})
                }
            }
            Some("degrade") => {
                if self.st.holder.as_deref() == Some(node) && req["epoch"].as_u64() == Some(self.st.epoch) {
                    self.st.synced = vec![node.to_string()];
                    json!({"ok": true})
                } else {
                    json!({"ok": false, "reason": "not the lease holder"})
                }
            }
            Some("status") => json!({"ok": true, "holder": self.st.holder, "epoch": self.st.epoch,
                                     "synced": self.st.synced}),
            _ => json!({"ok": false, "reason": "unknown op"}),
        };
        if before != self.st {
            if let Err(e) = self.persist() {
                // could not record the decision: undo it and refuse
                self.st = before;
                return json!({"ok": false, "reason": format!("witness state not saved: {e}")});
            }
        }
        resp
    }
}

/// Run the witness (blocks). State survives restarts; after a restart the old lease is treated as
/// still held for a full lease + grace so a restart never hands out a second lease early.
pub fn run_witness(listen: &str, state: &str, tls: &TlsFiles) -> Result<(), String> {
    let path = PathBuf::from(state);
    let st: WState = match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{state}: {e}"))?,
        Err(_) => WState::default(),
    };
    eprintln!("mastyf-witness: state {st:?}");
    let w = Arc::new(Mutex::new(Witness { path, st, expires: Instant::now() + LEASE }));
    let cfg = server_config(tls)?;
    let listener = std::net::TcpListener::bind(listen).map_err(|e| e.to_string())?;
    eprintln!("mastyf-witness: listening on {listen} (mutual TLS)");
    for tcp in listener.incoming().flatten() {
        let (w, cfg) = (Arc::clone(&w), Arc::clone(&cfg));
        std::thread::spawn(move || {
            let Ok(mut c) = accept(&cfg, tcp, Duration::from_secs(30)) else { return };
            while let Ok(req) = c.recv() {
                let resp = w.lock().unwrap().handle(&req);
                if c.send(&resp).is_err() {
                    return;
                }
            }
        });
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------- nodes

#[derive(Clone)]
pub struct HaConfig {
    pub node: String,
    pub listen: String,
    pub peer: String,
    /// the peer's node name (as given to its --ha-node)
    pub peer_node: String,
    /// 1 or 3 (or 5) witness addresses; decisions need a majority
    pub witnesses: Vec<String>,
    pub tls: TlsFiles,
    pub dir: PathBuf,
}

struct Standby {
    last_msg: Mutex<Instant>,
    max_epoch: AtomicU64,
    promoting: AtomicBool,
    io: Mutex<()>,
    dir: PathBuf,
}

impl Standby {
    fn apply(&self, req: &Value) -> Value {
        let _g = self.io.lock().unwrap();
        if self.promoting.load(Ordering::SeqCst) {
            return json!({"ok": false, "reason": "promoting"});
        }
        let epoch = req["epoch"].as_u64().unwrap_or(0);
        if epoch < self.max_epoch.load(Ordering::SeqCst) {
            return json!({"ok": false, "reason": "stale epoch"});
        }
        self.max_epoch.store(epoch, Ordering::SeqCst);
        let t = req["t"].as_str().unwrap_or("");
        let res = if t == "ping" {
            Ok(())
        } else {
            let j = req["j"].as_str().unwrap_or("");
            if !JOURNALS.contains(&j) {
                return json!({"ok": false, "reason": "unknown journal"});
            }
            let bytes = match STANDARD.decode(req["b"].as_str().unwrap_or("")) {
                Ok(b) => b,
                Err(_) => return json!({"ok": false, "reason": "bad payload"}),
            };
            let path = self.dir.join(format!("{j}.journal"));
            match t {
                "snap" => write_atomic(&path, &bytes),
                "app" => (|| {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&path)
                        .map_err(|e| e.to_string())?;
                    f.write_all(&bytes).map_err(|e| e.to_string())?;
                    f.sync_data().map_err(|e| e.to_string())
                })(),
                _ => Err("unknown message".into()),
            }
        };
        match res {
            Ok(()) => {
                *self.last_msg.lock().unwrap() = Instant::now();
                json!({"ok": true})
            }
            Err(e) => json!({"ok": false, "reason": e}),
        }
    }
}

/// Witness connections; one call goes to every witness in parallel.
struct Witnesses {
    cfg: HaConfig,
    client: Arc<rustls::ClientConfig>,
    slots: Vec<Option<Conn>>,
    /// epoch each witness last granted to this node (needed for degrade)
    epochs: Vec<Option<u64>>,
}

enum Vote {
    Yes(Value),
    No(String),
    Unreachable(String),
}

impl Witnesses {
    fn new(cfg: &HaConfig, client: Arc<rustls::ClientConfig>) -> Self {
        let n = cfg.witnesses.len();
        Witnesses { cfg: cfg.clone(), client, slots: (0..n).map(|_| None).collect(), epochs: vec![None; n] }
    }

    fn majority(&self) -> usize {
        self.cfg.witnesses.len() / 2 + 1
    }

    /// `make(i)` builds the request for witness i (so degrade can carry each witness's own epoch).
    fn ask(&mut self, make: impl Fn(usize) -> Option<Value> + Sync) -> Vec<Vote> {
        let (client, addrs) = (&self.client, &self.cfg.witnesses);
        let make = &make;
        let votes: Vec<Vote> = std::thread::scope(|sc| {
            let hs: Vec<_> = self.slots.iter_mut().enumerate().map(|(i, slot)| {
                sc.spawn(move || {
                    let Some(req) = make(i) else { return Vote::No("no epoch at this witness".into()) };
                    let mut last = String::from("unreachable");
                    for _ in 0..2 {
                        if slot.is_none() {
                            match dial(client, &addrs[i]) {
                                Ok(c) => *slot = Some(c),
                                Err(e) => {
                                    last = e;
                                    continue;
                                }
                            }
                        }
                        match slot.as_mut().map(|c| c.call(&req)) {
                            Some(Ok(v)) if v["ok"].as_bool() == Some(true) => return Vote::Yes(v),
                            Some(Ok(v)) => return Vote::No(v["reason"].as_str().unwrap_or("").to_string()),
                            Some(Err(e)) => {
                                last = e;
                                *slot = None;
                            }
                            None => {}
                        }
                    }
                    Vote::Unreachable(format!("witness {}: {last}", addrs[i]))
                })
            }).collect();
            hs.into_iter().map(|h| h.join().unwrap_or(Vote::Unreachable("panic".into()))).collect()
        });
        for (i, v) in votes.iter().enumerate() {
            if let Vote::Yes(r) = v {
                if let Some(e) = r["epoch"].as_u64() {
                    self.epochs[i] = Some(e);
                }
            }
        }
        votes
    }

    fn lease(&mut self, in_sync: bool) -> Vec<Vote> {
        let (node, peer) = (self.cfg.node.clone(), self.cfg.peer_node.clone());
        self.ask(|_| Some(json!({"op": "lease", "node": node, "in_sync": in_sync, "peer": peer})))
    }

    fn degrade(&mut self) -> Vec<Vote> {
        let node = self.cfg.node.clone();
        let epochs = self.epochs.clone();
        self.ask(|i| epochs[i].map(|e| json!({"op": "degrade", "node": node, "epoch": e})))
    }

    fn epoch(&self) -> u64 {
        self.epochs.iter().flatten().copied().max().unwrap_or(0)
    }
}

fn tally(votes: &[Vote]) -> (usize, usize, String) {
    let yes = votes.iter().filter(|v| matches!(v, Vote::Yes(_))).count();
    let no = votes.iter().filter(|v| matches!(v, Vote::No(_))).count();
    let why = votes.iter().filter_map(|v| match v {
        Vote::No(r) | Vote::Unreachable(r) => Some(r.as_str()),
        Vote::Yes(_) => None,
    }).collect::<Vec<_>>().join("; ");
    (yes, no, why)
}

/// Run as standby until this node holds a majority of witness leases. Returns the witness
/// connections (with their epochs). The journals in `cfg.dir` then hold every committed write.
fn wait_for_lease(cfg: &HaConfig) -> Result<Witnesses, String> {
    std::fs::create_dir_all(&cfg.dir).map_err(|e| e.to_string())?;
    if cfg.witnesses.is_empty() || cfg.witnesses.len().is_multiple_of(2) {
        return Err("use an odd number of witnesses (1, 3 or 5)".into());
    }
    let sb = Arc::new(Standby { last_msg: Mutex::new(Instant::now()), max_epoch: AtomicU64::new(0),
                                promoting: AtomicBool::new(false), io: Mutex::new(()), dir: cfg.dir.clone() });
    let server = server_config(&cfg.tls)?;
    let client = client_config(&cfg.tls)?;
    let listener = std::net::TcpListener::bind(&cfg.listen).map_err(|e| format!("{}: {e}", cfg.listen))?;
    eprintln!("mastyf-keyservice: HA node {} standing by on {}", cfg.node, cfg.listen);
    {
        let sb = Arc::clone(&sb);
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let (sb, server) = (Arc::clone(&sb), Arc::clone(&server));
                std::thread::spawn(move || {
                    let Ok(mut c) = accept(&server, tcp, Duration::from_secs(60)) else { return };
                    while let Ok(req) = c.recv() {
                        let resp = sb.apply(&req);
                        let stop = !resp["ok"].as_bool().unwrap_or(false) && sb.promoting.load(Ordering::SeqCst);
                        if c.send(&resp).is_err() || stop {
                            return;
                        }
                    }
                });
            }
        });
    }
    let mut w = Witnesses::new(cfg, client);
    let mut last_reason = String::new();
    loop {
        std::thread::sleep(Duration::from_millis(300));
        if sb.last_msg.lock().unwrap().elapsed() < PEER_SILENCE {
            continue;
        }
        // stop accepting the stream first (rule 3), then ask for the lease
        {
            let _g = sb.io.lock().unwrap();
            sb.promoting.store(true, Ordering::SeqCst);
        }
        let (yes, _, why) = tally(&w.lease(false));
        if yes >= w.majority() {
            eprintln!("mastyf-keyservice: HA node {} promoted to primary ({yes} of {} witnesses, epoch {})",
                      cfg.node, cfg.witnesses.len(), w.epoch());
            return Ok(w);
        }
        if why != last_reason {
            eprintln!("mastyf-keyservice: HA standby: lease refused ({yes} of {} witnesses): {why}", cfg.witnesses.len());
            last_reason = why;
        }
        sb.promoting.store(false, Ordering::SeqCst);
    }
}

pub struct Primary {
    cfg: HaConfig,
    client: Arc<rustls::ClientConfig>,
    peer: Mutex<Option<Conn>>,
    witness: Mutex<Witnesses>,
    in_sync: AtomicBool,
    degraded_ok: AtomicBool,
    commit_lock: Mutex<()>,
}

impl Primary {
    fn epoch(&self) -> u64 {
        self.witness.lock().unwrap().epoch()
    }

    /// Renew at every witness. Exits if a majority says another node holds the lease.
    fn renew(&self) {
        let mut w = self.witness.lock().unwrap();
        let in_sync = self.in_sync.load(Ordering::SeqCst); // read under the lock: never stale
        let (_, no, why) = tally(&w.lease(in_sync));
        if no >= w.majority() {
            fenced(&why);
        }
    }

    fn replicate(&self, journal: &str, bytes: &[u8]) -> Result<(), String> {
        if self.in_sync.load(Ordering::SeqCst) {
            let mut p = self.peer.lock().unwrap();
            let msg = json!({"t": "app", "j": journal, "b": STANDARD.encode(bytes), "epoch": self.epoch()});
            if let Some(Ok(r)) = p.as_mut().map(|c| c.call(&msg)) {
                if r["ok"].as_bool() == Some(true) {
                    return Ok(());
                }
            }
            *p = None;
            self.in_sync.store(false, Ordering::SeqCst);
            eprintln!("mastyf-keyservice: HA standby lost; asking witnesses to continue without it");
        }
        if self.degraded_ok.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut w = self.witness.lock().unwrap();
        let (yes, _, why) = tally(&w.degrade());
        if yes >= w.majority() {
            self.degraded_ok.store(true, Ordering::SeqCst);
            Ok(())
        } else {
            Err(format!("HA: not replicated and no witness majority ({yes} of {}): {why}", w.cfg.witnesses.len()))
        }
    }

    /// Bring a (re)connected standby fully in sync: full journal snapshot under the commit lock.
    fn resync(&self) -> Result<(), String> {
        let mut c = dial(&self.client, &self.cfg.peer)?;
        let _g = self.commit_lock.lock().unwrap();
        let epoch = self.epoch();
        for j in JOURNALS {
            let bytes = std::fs::read(self.cfg.dir.join(format!("{j}.journal"))).unwrap_or_default();
            let r = c.call(&json!({"t": "snap", "j": j, "b": STANDARD.encode(&bytes), "epoch": epoch}))?;
            if r["ok"].as_bool() != Some(true) {
                return Err(format!("standby refused snapshot: {}", r["reason"].as_str().unwrap_or("")));
            }
        }
        *self.peer.lock().unwrap() = Some(c);
        self.in_sync.store(true, Ordering::SeqCst);
        self.renew(); // reports "standby in sync" (enables automatic failover again)
        self.degraded_ok.store(false, Ordering::SeqCst);
        eprintln!("mastyf-keyservice: HA standby in sync");
        Ok(())
    }
}

fn fenced(reason: &str) -> ! {
    eprintln!("mastyf-keyservice: HA lease lost ({reason}); exiting so this node restarts as standby");
    std::process::exit(3)
}

impl crate::Replicator for Primary {
    fn commit(&self, journal: &str, bytes: &[u8], local: &mut dyn FnMut() -> Result<(), String>) -> Result<(), String> {
        let _g = self.commit_lock.lock().unwrap();
        // standby first: if this node then dies before its own fsync, the standby holds more, not less
        let rep = self.replicate(journal, bytes);
        let loc = local();
        loc?;
        rep
    }
}

/// Stand by until this node holds a majority lease. Returns a handle to start serving with.
pub fn wait_until_primary(cfg: &HaConfig) -> Result<PrimaryLease, String> {
    Ok(PrimaryLease(wait_for_lease(cfg)?))
}

pub struct PrimaryLease(Witnesses);

/// Install replication and start the lease, ping and resync loops. Call after the journals are
/// attached (they are compacted at start, so the first thing the standby gets is a full snapshot).
pub fn start_primary(cfg: HaConfig, lease: PrimaryLease) -> Result<(), String> {
    let p = Arc::new(Primary { client: lease.0.client.clone(), cfg, peer: Mutex::new(None),
                               witness: Mutex::new(lease.0), in_sync: AtomicBool::new(false),
                               degraded_ok: AtomicBool::new(false), commit_lock: Mutex::new(()) });
    struct Shared(Arc<Primary>);
    impl crate::Replicator for Shared {
        fn commit(&self, j: &str, b: &[u8], l: &mut dyn FnMut() -> Result<(), String>) -> Result<(), String> {
            self.0.commit(j, b, l)
        }
    }
    crate::REPLICATOR.set(Box::new(Shared(Arc::clone(&p)))).map_err(|_| "replicator already set")?;
    {
        let p = Arc::clone(&p);
        std::thread::spawn(move || loop {
            std::thread::sleep(RENEW_EVERY);
            p.renew();
        });
    }
    {
        let p = Arc::clone(&p);
        std::thread::spawn(move || {
            let mut last_err = String::new();
            loop {
                std::thread::sleep(PING_EVERY);
                if p.in_sync.load(Ordering::SeqCst) {
                    let epoch = p.epoch();
                    let mut g = p.peer.lock().unwrap();
                    let ok = g.as_mut().map(|c| c.call(&json!({"t": "ping", "epoch": epoch})))
                        .is_some_and(|r| r.is_ok_and(|v| v["ok"].as_bool() == Some(true)));
                    if !ok {
                        *g = None;
                        p.in_sync.store(false, Ordering::SeqCst);
                        eprintln!("mastyf-keyservice: HA standby stopped answering");
                    }
                } else if let Err(e) = p.resync() {
                    if e != last_err {
                        eprintln!("mastyf-keyservice: HA standby not reachable: {e}");
                        last_err = e;
                    }
                }
            }
        });
    }
    Ok(())
}

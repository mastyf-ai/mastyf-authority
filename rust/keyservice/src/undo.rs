//! Undo windows for irreversible actions. Port of `authority/undo.py` (same rules, same messages).
//! Every state change is journaled and fsynced before the caller hears about it; state is rebuilt
//! from the journal at start, so nothing is executed twice, lost, or executed early after a restart.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

use ed25519_dalek::VerifyingKey;
use serde_json::{json, Map, Value};

use crate::{fnmatch, Action, Durability, GrantCheck, Journal};

const HOUR: f64 = 3600.0;

pub fn undo_message(pid: &str, fp: &str) -> Vec<u8> {
    format!("mastyf-undo|{pid}|{fp}").into_bytes()
}

struct Rule {
    action: String,
    resource: String,
    min_count: u64,
    delay: f64,
}

pub struct UndoPolicy {
    rules: Vec<Rule>,
    signatures: usize,
    burst_per_hour: usize,
    security: Vec<String>,
}

impl UndoPolicy {
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let mut rules = vec![];
        for r in v.get("rules").and_then(Value::as_array).ok_or("undo_windows.rules required")? {
            rules.push(Rule {
                action: r.get("action").and_then(Value::as_str).ok_or("rule action required")?.into(),
                resource: r.get("resource").and_then(Value::as_str).unwrap_or("*").into(),
                min_count: r.get("min_count").and_then(Value::as_u64).unwrap_or(0),
                delay: r.get("delay_seconds").and_then(Value::as_u64).ok_or("delay_seconds required")? as f64,
            });
        }
        let security = v.get("security").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
        Ok(UndoPolicy { rules, signatures: v.get("signatures").and_then(Value::as_u64).unwrap_or(2) as usize,
                        burst_per_hour: v.get("burst_per_hour").and_then(Value::as_u64).unwrap_or(5) as usize, security })
    }
}

struct Entry {
    action: Value,
    fp: String,
    requester: String,
    execute_after: f64,
    state: String,
}

struct Inner {
    journal: Option<Journal>,
    verifier: GrantCheck,
    pending: HashMap<String, Entry>,
    recent: HashMap<String, VecDeque<f64>>,
    frozen: HashMap<String, String>,
}

pub struct UndoGate {
    p: UndoPolicy,
    approvers: HashMap<String, VerifyingKey>,
    durable: OnceLock<Durability>,
    pub approver_devices: OnceLock<crate::ApproverDevices>,
    inner: Mutex<Inner>,
}

fn res(ok: bool, reason: impl Into<String>) -> Value {
    json!({"ok": ok, "reason": reason.into()})
}

impl UndoGate {
    pub fn new(p: UndoPolicy, verifier: GrantCheck, approvers: HashMap<String, VerifyingKey>) -> Self {
        UndoGate { p, approvers, durable: OnceLock::new(), approver_devices: OnceLock::new(),
                   inner: Mutex::new(Inner { journal: None, verifier, pending: HashMap::new(), recent: HashMap::new(),
                                             frozen: HashMap::new() }) }
    }

    pub fn attach_journal(&self, mut j: Journal, events: Vec<Value>, now: f64) -> Result<usize, String> {
        let mut inner = self.inner.lock().unwrap();
        let mut keep = vec![];
        for ev in events {
            let pid = ev["pid"].as_str().unwrap_or("").to_string();
            match ev["e"].as_str() {
                Some("gid") => {
                    let exp = ev["exp"].as_f64().unwrap_or(0.0);
                    if exp >= now {
                        inner.verifier.mark_used(ev["node"].as_str().unwrap_or(""), ev["gid"].as_str().unwrap_or(""), exp);
                        keep.push(ev);
                    }
                    continue;
                }
                Some("queued") => {
                    let e = &ev["entry"];
                    inner.pending.insert(pid, Entry { action: e["action"].clone(), fp: e["fingerprint"].as_str().unwrap_or("").into(),
                        requester: e["requester"].as_str().unwrap_or("").into(),
                        execute_after: e["execute_after"].as_f64().unwrap_or(f64::MAX),
                        state: e["state"].as_str().unwrap_or("pending").into() });
                }
                Some("expedited") => {
                    if let Some(e) = inner.pending.get_mut(&pid) {
                        e.execute_after = ev["at"].as_f64().unwrap_or(e.execute_after);
                    }
                }
                Some(k @ ("cancelled" | "executed")) => {
                    if let Some(e) = inner.pending.get_mut(&pid) {
                        e.state = k.into();
                    }
                }
                Some("freeze") => {
                    inner.frozen.insert(ev["identity"].as_str().unwrap_or("").into(), ev["why"].as_str().unwrap_or("").into());
                }
                Some("unfreeze") => {
                    inner.frozen.remove(ev["identity"].as_str().unwrap_or(""));
                }
                _ => continue,
            }
            keep.push(ev);
        }
        let n = keep.len();
        j.rewrite(&keep)?;
        let _ = self.durable.set(j.durability()?);
        inner.journal = Some(j);
        Ok(n)
    }

    pub fn flush(&self) -> Result<(), String> {
        self.durable.get().map(|d| d.flush()).unwrap_or(Ok(()))
    }

    fn j(inner: &mut Inner, v: Value) -> Result<(), String> {
        match inner.journal.as_mut() {
            Some(j) => j.write(&v),
            None => Ok(()),
        }
    }

    /// Persist before answering (fail closed).
    fn sync(&self, r: Value) -> Value {
        if let Some(d) = self.durable.get() {
            let seq = self.inner.lock().unwrap().journal.as_ref().map(|j| j.seq).unwrap_or(0);
            if let Err(e) = d.sync(seq) {
                return res(false, format!("journal sync failed: refusing (fail closed): {e}"));
            }
        }
        r
    }

    fn cancel_where(inner: &mut Inner, pred: impl Fn(&Entry) -> bool, by: &str) -> Result<usize, String> {
        let pids: Vec<String> = inner.pending.iter().filter(|(_, e)| e.state == "pending" && pred(e)).map(|(k, _)| k.clone()).collect();
        for pid in &pids {
            Self::j(inner, json!({"e": "cancelled", "pid": pid, "by": by}))?;
            if let Some(e) = inner.pending.get_mut(pid) {
                e.state = "cancelled".into();
            }
        }
        Ok(pids.len())
    }

    pub fn submit(&self, grant: &str, a: &Action, now: f64) -> Value {
        let r = (|| {
            let mut inner = self.inner.lock().unwrap();
            let payload: Map<String, Value> = match inner.verifier.verify_pub(grant, a, now) {
                Ok(p) => p,
                Err(e) => return res(false, format!("grant rejected: {e}")),
            };
            for (node, g, exp) in GrantCheck::consumed(&payload) {
                if Self::j(&mut inner, json!({"e": "gid", "node": node, "gid": g, "exp": exp})).is_err() {
                    return res(false, "journal write failed: refusing (fail closed)");
                }
            }
            if let Some(why) = inner.frozen.get(&a.identity) {
                return res(false, format!("identity frozen: {why}"));
            }
            let Some(rule) = self.p.rules.iter().find(|r| fnmatch(&a.action_type, &r.action) && fnmatch(&a.resource, &r.resource))
            else { return res(false, format!("{} on {}: no undo rule (fail closed)", a.action_type, a.resource)) };
            if a.count < rule.min_count {
                return res(true, format!("below {}: executes now", rule.min_count));
            }
            let dq = inner.recent.entry(a.identity.clone()).or_default();
            while dq.front().is_some_and(|t| *t <= now - HOUR) {
                dq.pop_front();
            }
            if dq.len() + 1 > self.p.burst_per_hour {
                let why = format!("{} irreversible actions in one hour (ransomware/wiper pattern)", dq.len() + 1);
                let who = a.identity.clone();
                let n = match Self::cancel_where(&mut inner, |e| e.requester == who, "burst") {
                    Ok(n) => n,
                    Err(_) => return res(false, "journal write failed: refusing (fail closed)"),
                };
                let _ = Self::j(&mut inner, json!({"e": "freeze", "identity": a.identity, "why": why}));
                inner.frozen.insert(a.identity.clone(), why.clone());
                return res(false, format!("refused and frozen: {why}; {n} queued actions cancelled"));
            }
            dq.push_back(now);
            let pid = payload.get("gid").and_then(Value::as_str).unwrap_or("").to_string();
            let exec = now + rule.delay;
            let entry = json!({"action": a.to_json(), "fingerprint": a.fingerprint(), "requester": a.identity,
                               "queued_at": now, "execute_after": exec, "state": "pending"});
            if Self::j(&mut inner, json!({"e": "queued", "pid": pid, "entry": entry})).is_err() {
                return res(false, "journal write failed: refusing (fail closed)");
            }
            inner.pending.insert(pid.clone(), Entry { action: a.to_json(), fp: a.fingerprint(), requester: a.identity.clone(),
                                                      execute_after: exec, state: "pending".into() });
            json!({"ok": false, "reason": format!("queued: executes after {} h unless cancelled", rule.delay / HOUR),
                   "pending_id": pid, "execute_after": exec})
        })();
        self.sync(r)
    }

    pub fn cancel(&self, pid: &str, by: &str) -> Value {
        let r = {
            let mut inner = self.inner.lock().unwrap();
            match inner.pending.get(pid) {
                Some(e) if e.state == "pending" && (by == e.requester || self.approvers.contains_key(by)
                                                    || self.p.security.iter().any(|s| s == by)) => {
                    if Self::j(&mut inner, json!({"e": "cancelled", "pid": pid, "by": by})).is_err() {
                        return res(false, "journal write failed");
                    }
                    inner.pending.get_mut(pid).unwrap().state = "cancelled".into();
                    res(true, "cancelled")
                }
                _ => res(false, "not cancellable"),
            }
        };
        self.sync(r)
    }

    pub fn expedite(&self, pid: &str, sigs: &[Value], now: f64) -> Value {
        let r = {
            let mut inner = self.inner.lock().unwrap();
            let Some(e) = inner.pending.get(pid).filter(|e| e.state == "pending") else { return res(false, "not pending") };
            let msg = undo_message(pid, &e.fp);
            let mut ok = HashSet::new();
            for s in sigs {
                if let Some(n) = crate::approver_signed(&self.approvers, self.approver_devices.get(), s, &msg) {
                    if n != e.requester {
                        ok.insert(n);
                    }
                }
            }
            if ok.len() < self.p.signatures {
                return res(false, format!("needs {} approver signatures", self.p.signatures));
            }
            let mut by: Vec<_> = ok.into_iter().collect();
            by.sort();
            if Self::j(&mut inner, json!({"e": "expedited", "pid": pid, "at": now, "by": by})).is_err() {
                return res(false, "journal write failed");
            }
            inner.pending.get_mut(pid).unwrap().execute_after = now;
            res(true, "released early")
        };
        self.sync(r)
    }

    pub fn panic(&self, by: &str, identity: Option<&str>) -> Value {
        let r = {
            if !self.p.security.iter().any(|s| s == by) && !self.approvers.contains_key(by) {
                return json!({"ok": false, "cancelled": 0, "reason": "security team or approvers only"});
            }
            let mut inner = self.inner.lock().unwrap();
            let n = match Self::cancel_where(&mut inner, |e| identity.is_none_or(|i| e.requester == i), &format!("panic:{by}")) {
                Ok(n) => n,
                Err(_) => return res(false, "journal write failed"),
            };
            if let Some(i) = identity {
                let _ = Self::j(&mut inner, json!({"e": "freeze", "identity": i, "why": format!("panic by {by}")}));
                inner.frozen.insert(i.into(), format!("panic by {by}"));
            }
            json!({"ok": true, "cancelled": n})
        };
        self.sync(r)
    }

    pub fn due(&self, now: f64) -> Value {
        let inner = self.inner.lock().unwrap();
        let mut d: Vec<&String> = inner.pending.iter().filter(|(_, e)| e.state == "pending" && e.execute_after <= now)
            .map(|(k, _)| k).collect();
        d.sort();
        json!({"ok": true, "due": d})
    }

    pub fn execute(&self, pid: &str, now: f64) -> Value {
        let r = {
            let mut inner = self.inner.lock().unwrap();
            let ok = inner.pending.get(pid).is_some_and(|e| e.state == "pending" && e.execute_after <= now)
                && !inner.pending.get(pid).is_some_and(|e| inner.frozen.contains_key(&e.requester));
            if !ok {
                return res(false, "not due");
            }
            if Self::j(&mut inner, json!({"e": "executed", "pid": pid})).is_err() {
                return res(false, "journal write failed");
            }
            let e = inner.pending.get_mut(pid).unwrap();
            e.state = "executed".into();
            json!({"ok": true, "action": e.action})
        };
        self.sync(r)
    }
}

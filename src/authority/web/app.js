"use strict";
// Approver and device pages. No third-party code. Private keys stay in the passkey / browser.

const enc = new TextEncoder();
const $ = (id) => document.getElementById(id);
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0), out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) { if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v); }
  for (const k of kids) e.append(k);
  return e;
}
function say(node, text, ok) { node.textContent = text; node.className = "msg " + (ok ? "ok" : "bad"); }

let KEY = "";
try { KEY = sessionStorage.getItem("mastyf-key") || ""; } catch (_) { /* storage blocked */ }
async function api(path, body) {
  const r = await fetch(path, { method: body === undefined ? "GET" : "POST", headers: { Authorization: "Bearer " + KEY, "Content-Type": "application/json" },
                                body: body === undefined ? undefined : JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}
function setupKey(onLoad) {
  $("apikey").value = KEY;
  $("load").addEventListener("click", async () => {
    KEY = $("apikey").value.trim();
    try { sessionStorage.setItem("mastyf-key", KEY); } catch (_) { /* fine */ }
    try { await onLoad(); say($("keymsg"), "Loaded.", true); } catch (e) { say($("keymsg"), e.message, false); }
  });
}

// passkey assertion over a server challenge, from one of my registered devices
async function assert(challenge, rpId, devices) {
  const allow = devices.filter((d) => d.cred_id).map((d) => ({ type: "public-key", id: unb64u(d.cred_id) }));
  const cred = await navigator.credentials.get({ publicKey: { challenge, rpId, allowCredentials: allow, userVerification: "required", timeout: 120000 } });
  const id = b64u(cred.rawId);
  const dev = devices.find((d) => d.cred_id === id);
  if (!dev) throw new Error("that passkey is not one of your registered devices");
  const r = cred.response;
  return { device: dev.device, proof: JSON.stringify({ device: dev.device, ad: b64u(r.authenticatorData), cd: b64u(r.clientDataJSON), sig: b64u(r.signature) }) };
}

// ------------------------------------------------------------------ approvals page
async function approvePage() {
  let mine = { devices: [], rp_id: location.hostname };
  async function load() {
    mine = await api("/v1/devices");
    const { pending } = await api("/v1/pending");
    const box = $("actions"); box.replaceChildren();
    if (!pending.length) box.append(el("p", { class: "empty" }, "Nothing waiting."));
    for (const p of pending) {
      const a = p.action, msg = el("div", { class: "msg" }), reason = el("input", { placeholder: "Reason or ticket (at least 8 characters)" });
      const card = el("div", { class: "card" },
        el("div", {}, el("strong", {}, p.requester), " wants ", el("strong", {}, `${a.action_type} ${a.count} × ${a.resource}`), a.destination ? ` → ${a.destination}` : ""),
        ...p.reasons.map((r) => el("div", { class: "reason" }, r)),
        el("div", { class: "mono" }, p.fingerprint), el("label", {}, "Reason"), reason,
        el("div", { class: "row" },
          el("button", { class: "primary", onclick: async () => {
            try {
              const why = reason.value.trim();
              if (why.length < 8) throw new Error("give a reason of at least 8 characters");
              const chal = await sha256(enc.encode(`mastyf-approve|${p.fingerprint}|${p.requester}|${why}`));
              const s = await assert(chal, mine.rp_id, mine.devices);
              const r = await api("/v1/approve", { fingerprint: p.fingerprint, requester: p.requester, approver: mine.identity, reason: why, signature: s.proof });
              say(msg, "Approved (" + r.approval_id + "). The requester can retry now.", true);
            } catch (e) { say(msg, e.message, false); }
          } }, "Approve with passkey"),
          el("button", { class: "danger", onclick: async () => {
            try { await api("/v1/deny", { fingerprint: p.fingerprint, approver: mine.identity, reason: reason.value.trim() || "denied" }); card.remove(); }
            catch (e) { say(msg, e.message, false); }
          } }, "Deny")), msg);
      box.append(card);
    }
    const dbox = $("devices"); dbox.replaceChildren();
    let enr = [];
    try { enr = (await api("/v1/enroll/pending")).pending; } catch (_) { /* enrolment off */ }
    if (!enr.length) dbox.append(el("p", { class: "empty" }, "Nothing waiting."));
    for (const r of enr) {
      const msg = el("div", { class: "msg" });
      dbox.append(el("div", { class: "card" }, el("div", {}, el("strong", {}, r.identity), " wants to add a new device."),
        el("div", { class: "reason" }, "Only approve after confirming with them in person or by a call you placed."),
        el("div", { class: "row" }, el("button", { class: "primary", onclick: async () => {
          try { const s = await assert(unb64u(r.challenge), mine.rp_id, mine.devices); const x = await api("/v1/enroll/approve", { rid: r.rid, device: s.device, proof: s.proof }); say(msg, x.status, true); }
          catch (e) { say(msg, e.message, false); }
        } }, "Approve with passkey")), msg));
    }
  }
  setupKey(load);

  const labels = { gate: ["Grant id", "Action fingerprint"], overrun: ["Grant id", "Extra records allowed"], unfreeze: ["Identity", "Valid until (unix time, max 1 hour ahead)"] };
  $("kind").addEventListener("change", () => { const [a, b] = labels[$("kind").value]; $("l1").textContent = a; $("l2").textContent = b; });
  $("signit").addEventListener("click", async () => {
    const out = $("signmsg"), kind = $("kind").value, a = $("f1").value.trim(), b = $("f2").value.trim();
    try {
      if (!mine.identity) mine = await api("/v1/devices");
      if (!a || !b) throw new Error("fill in both fields");
      if (kind !== "gate" && !/^[0-9]+$/.test(b)) throw new Error("second field must be a whole number");
      const msg = kind === "gate" ? `mastyf-gate|${a}|${b}` : kind === "overrun" ? `mastyf-overrun|${a}|${b}` : `mastyf-unfreeze|${a}|${b}`;
      const s = await assert(await sha256(enc.encode(msg)), mine.rp_id, mine.devices);
      const entry = { approver: mine.identity, device: s.device, proof: s.proof };
      if (kind === "overrun") entry.amount = Number(b);
      $("signout").textContent = JSON.stringify(entry);
      say(out, "Signed. Copy the line below to the requester.", true);
    } catch (e) { say(out, e.message, false); }
  });
}

// ------------------------------------------------------------------ device page
function idb() {
  return new Promise((res, rej) => { const r = indexedDB.open("mastyf", 1); r.onupgradeneeded = () => r.result.createObjectStore("keys"); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
}
async function keepKey(name, key) {
  const db = await idb();
  await new Promise((res, rej) => { const t = db.transaction("keys", "readwrite"); t.objectStore("keys").put(key, name); t.oncomplete = res; t.onerror = () => rej(t.error); });
}

async function enrollPage() {
  let mine = null;
  async function load() {
    mine = await api("/v1/devices");
    const list = $("list"); list.replaceChildren();
    const card = el("div", { class: "card" }, el("strong", {}, mine.identity));
    if (!mine.devices.length) card.append(el("p", { class: "empty" }, "No devices yet."));
    for (const d of mine.devices) {
      card.append(el("div", { class: "row" }, el("span", { class: "mono" }, d.device),
        el("button", { class: "danger", onclick: async () => { if (confirm(`Remove ${d.device}? It will stop receiving data keys.`)) { await api("/v1/devices/remove", { device: d.device }); await load(); } } }, "Remove")));
    }
    list.append(card);
    $("add").hidden = false;
  }
  setupKey(load);

  $("begin").addEventListener("click", async () => {
    const out = $("addmsg"), step = $("step");
    try {
      const name = $("devname").value.trim();
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) throw new Error("name: letters, digits, - and _ only");
      if (!window.PublicKeyCredential) throw new Error("this browser has no passkey support");
      const b = await api("/v1/enroll/begin", {});
      step.replaceChildren();
      let started = false;
      const finish = async () => {
        if (started) return;
        started = true;
        clearInterval(poll);
        try { await register(); } catch (e) { started = false; throw e; }
      };
      const register = async () => {
        // device encryption key: private half stays in this browser (non-extractable)
        const kp = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
        const kex = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
        const chal = await sha256(cat(enc.encode(`mastyf-enroll|${b.rid}|${b.identity}|${b.exp}`), enc.encode("|"), kex));
        const cred = await navigator.credentials.create({ publicKey: {
          challenge: chal, rp: { id: b.rp_id, name: "Mastyf" }, user: { id: enc.encode(b.identity), name: b.identity, displayName: b.identity },
          pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }],
          authenticatorSelection: { userVerification: "required", residentKey: "preferred" }, attestation: "none", timeout: 120000 } });
        const r = await api("/v1/enroll/finish", { rid: b.rid, device_name: name, attestation: b64u(cred.response.attestationObject),
                                                   client_data: b64u(cred.response.clientDataJSON), kex: b64u(kex) });
        await keepKey("kex:" + name, kp.privateKey);
        say(out, `Added ${r.device}.`, true); step.replaceChildren(); await load();
      };
      const showRegister = () => step.replaceChildren(el("p", {}, "Approved."), el("button", { class: "primary", onclick: async () => {
        try { await finish(); } catch (e) { say(out, e.message, false); } } }, "Register this device"));
      if (b.has_devices) {
        step.append(el("p", {}, "Confirm on a device you already have registered."),
          el("button", { class: "primary", onclick: async () => {
            try { const s = await assert(unb64u(b.challenge), b.rp_id, b.allow); await api("/v1/enroll/authorise", { rid: b.rid, device: s.device, proof: s.proof }); clearInterval(poll); showRegister(); }
            catch (e) { say(out, e.message, false); }
          } }, "Confirm with existing device"));
      }
      step.append(el("p", { class: "empty" }, "No other device? Ask two approvers to approve request " + b.rid + " on their Approvals page. This page continues on its own."));
      var poll = setInterval(async () => {
        try {
          const s = await api("/v1/enroll/status?rid=" + encodeURIComponent(b.rid));
          if (s.authorised) {  // passkey creation needs a click (Safari), so ask for one
            clearInterval(poll);
            showRegister();
          }
        }
        catch (e) { clearInterval(poll); say(out, e.message, false); }
      }, 3000);
    } catch (e) { say(out, e.message, false); }
  });
}

// ---------------------------------------------------------------- team limits (admin)
const fmtN = (v) => v === null || v === undefined ? "no limit" : Number(v).toLocaleString();

function ceilingCard(ceil, before) {
  const box = el("div", { class: "card" });
  const classes = Object.keys(ceil).sort();
  if (!classes.length) { box.append(el("p", { class: "empty" }, "No budgeted data classes.")); return box; }
  for (const c of classes) {
    const now = ceil[c].per_day;
    const row = el("div", { class: "row" }, el("span", { class: "mono" }, c), el("strong", {}, fmtN(now) + " / day"));
    if (before && before[c] && before[c].per_day !== now) {
      const up = now === null || (before[c].per_day !== null && now > before[c].per_day);
      row.append(el("span", { class: up ? "reason" : "msg ok" }, (up ? "up from " : "down from ") + fmtN(before[c].per_day)));
    }
    if (ceil[c].who && ceil[c].who.length) row.append(el("span", { class: "empty" }, "worst: " + ceil[c].who.join(", ")));
    box.append(row);
  }
  return box;
}

function limitsPage() {
  setupKey(async () => {
    const data = await api("/v1/teams");
    $("ceiling").replaceChildren(ceilingCard(data.ceiling));
    const host = $("teams");
    host.replaceChildren();
    if (!data.teams.length) host.append(el("p", { class: "empty" }, "No teams in the policy yet."));
    for (const t of data.teams) {
      const card = el("div", { class: "card" });
      card.append(el("h2", {}, t.name + "  ·  " + t.members.length + (t.members.length === 1 ? " person" : " people")));
      if (t.idp_groups.length) card.append(el("p", { class: "empty" }, "From identity-provider groups: " + t.idp_groups.join(", ")));
      card.append(el("p", { class: "mono" }, "may: " + (t.allowed_actions.join(", ") || "nothing")));
      const out = el("div", {});
      const classes = Object.keys(t.budgets).sort();
      if (!classes.length) card.append(el("p", { class: "empty" }, "No data limits: this team can read no budgeted data."));
      for (const c of classes) {
        const inp = el("input", { type: "number", min: "0", step: "10", value: String(t.budgets[c] ?? 0), "aria-label": t.name + " " + c + " per day" });
        const go = el("button", { onclick: async () => {
          go.disabled = true;
          try {
            const r = await api("/v1/teams/preview", { team: t.name, class: c, limit: Number(inp.value) });
            out.replaceChildren(el("p", { class: "empty" }, "If " + t.name + " could read " + fmtN(r.limit) + " " + c + " a day, the worst case would be:"), ceilingCard(r.after, r.before));
          } catch (e) { out.replaceChildren(el("p", { class: "msg bad" }, e.message)); }
          go.disabled = false;
        } }, "Preview");
        card.append(el("div", { class: "lim" }, el("label", {}, c + " · per person per day"), inp, go));
      }
      card.append(out);
      if (t.members.length) card.append(el("p", { class: "empty" }, "Members: " + t.members.join(", ")));
      host.append(card);
    }
  });
}

if (document.body.dataset.page === "limits") limitsPage();
if (document.body.dataset.page === "approve") approvePage();
if (document.body.dataset.page === "enroll") enrollPage();

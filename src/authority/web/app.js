"use strict";
// Mastyf Authority console: overview, approvals, devices, team limits. No third-party code.
// Private keys stay in the passkey / browser. Strict CSP: no inline script or style attributes.

const enc = new TextEncoder();
const $ = (id) => document.getElementById(id);
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0), out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const PRICING = "https://www.mastyf.ai/authority#pricing";

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids) if (k !== null && k !== undefined && k !== false) e.append(k);
  return e;
}
function say(node, text, ok) { node.textContent = text; node.className = "msg " + (ok ? "ok" : "bad"); }
const short = (id) => String(id || "").split(":").pop();
const avatar = (id) => el("span", { class: "avatar", "aria-hidden": "true" }, (short(id)[0] || "?"));

let KEY = "";
try { KEY = sessionStorage.getItem("mastyf-key") || ""; } catch (_) { /* storage blocked */ }
async function api(path, body) {
  const r = await fetch(path, { method: body === undefined ? "GET" : "POST", headers: { Authorization: "Bearer " + KEY, "Content-Type": "application/json" },
                                body: body === undefined ? undefined : JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}
// Single sign-on (OIDC authorization code + PKCE, a public client: no secret in the page). The token only says
// who you are; approving still needs your passkey.
const SS = { get: (k) => { try { return sessionStorage.getItem(k); } catch (_) { return null; } },
             set: (k, v) => { try { sessionStorage.setItem(k, v); } catch (_) { /* fine */ } },
             del: (k) => { try { sessionStorage.removeItem(k); } catch (_) { /* fine */ } } };
async function ssoConfig() {
  const c = await fetch("/web/sso.json").then((r) => r.json()).catch(() => ({}));
  if (!c.issuer || !c.client_id) return null;
  const d = await fetch(c.issuer + "/.well-known/openid-configuration").then((r) => r.json());
  if (d.issuer !== c.issuer) throw new Error("identity provider answered for a different issuer");
  return { ...c, auth: d.authorization_endpoint, token: d.token_endpoint };
}
const here = () => location.origin + location.pathname;
async function ssoStart(c) {
  const rnd = (n) => b64u(crypto.getRandomValues(new Uint8Array(n)));
  const verifier = rnd(32), state = rnd(16);
  SS.set("mastyf-pkce", JSON.stringify({ verifier, state }));
  const challenge = b64u(await sha256(enc.encode(verifier)));
  const q = new URLSearchParams({ response_type: "code", client_id: c.client_id, redirect_uri: here(), scope: c.scope,
                                  state, code_challenge: challenge, code_challenge_method: "S256" });
  location.assign(c.auth + "?" + q.toString());
}
async function ssoFinish(c) {
  const q = new URLSearchParams(location.search);
  if (!q.get("code")) return false;
  history.replaceState(null, "", here());  // never leave the code in the address bar or history
  const saved = JSON.parse(SS.get("mastyf-pkce") || "{}");
  SS.del("mastyf-pkce");
  if (!saved.state || q.get("state") !== saved.state) throw new Error("sign-in answer does not match this browser's request");
  const r = await fetch(c.token, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: q.get("code"), redirect_uri: here(),
                                client_id: c.client_id, code_verifier: saved.verifier }) });
  const t = await r.json().catch(() => ({}));
  if (!r.ok || !t.access_token) throw new Error("sign-in failed: " + (t.error_description || t.error || r.status));
  KEY = t.access_token;  // kept for this tab only
  SS.set("mastyf-key", KEY);
  return true;
}

// ------------------------------------------------------------------ shared chrome: top bar, footer, edition
let HEALTH = null;
const isPaid = () => HEALTH && HEALTH.edition === "enterprise";
async function health() { try { HEALTH = await fetch("/healthz").then((r) => r.json()); } catch (_) { HEALTH = null; } return HEALTH; }

function chrome() {
  const page = document.body.dataset.page;
  const links = [["home", "/", "Overview"], ["approve", "/approve", "Approvals"], ["enroll", "/enroll", "Devices"], ["limits", "/limits", "Team limits"], ["lab", "/lab", "Risk model lab"]];
  const badge = el("span", { class: "count", hidden: true });
  const nav = el("nav", { class: "nav", "aria-label": "Console" }, ...links.map(([id, href, text]) =>
    el("a", { href, "aria-current": id === page ? "page" : null }, text, id === "approve" ? badge : null,
      id === "lab" ? el("span", { class: "new" }, "try") : null)));
  const status = el("span", { class: "status", title: "Engine status" }, el("i", { class: "dot" }), el("span", {}, "connecting…"));
  const edition = el("span", { class: "edition" }, "Community");
  const up = el("a", { class: "btn primary sm", href: PRICING, target: "_blank", rel: "noopener" }, "Upgrade");
  $("top").append(el("div", { class: "top__in" },
    el("a", { class: "brand", href: "/" }, el("img", { src: "/web/mark.png", alt: "" }), el("span", {}, "Mastyf Authority", el("small", {}, "Console"))),
    nav, el("div", { class: "top__right" }, status, edition, up)));
  $("foot").append(el("div", { class: "in" }, el("img", { src: "/web/mark.png", alt: "" }),
    el("span", {}, "Mastyf Authority · open core, AGPL-3.0"), el("span", { class: "spacer" }),
    el("a", { href: "https://github.com/mastyf-ai/mastyf-authority", target: "_blank", rel: "noopener" }, "GitHub"),
    el("a", { href: "https://www.mastyf.ai/authority", target: "_blank", rel: "noopener" }, "Docs"),
    el("a", { href: PRICING, target: "_blank", rel: "noopener" }, "Plans and pricing")));

  const paint = () => {
    const ok = HEALTH && HEALTH.ok;
    status.firstChild.className = "dot " + (ok ? "on" : "off");
    status.lastChild.textContent = ok ? `engine ${HEALTH.role}` : "engine offline";
    if (isPaid()) { edition.textContent = "Enterprise"; edition.className = "edition paid"; up.hidden = true; }
  };
  const tick = async () => {
    await health(); paint();
    if (KEY) {
      try { const n = (await api("/v1/pending")).pending.length; badge.textContent = n; badge.hidden = !n; }
      catch (_) { badge.hidden = true; }
    }
  };
  tick(); setInterval(tick, 5000);
}

// A small, page-specific upgrade nudge (Community edition only).
function nudge(text, cta) {
  const host = $("nudge");
  if (!host) return;
  const show = () => {
    if (isPaid()) { host.replaceChildren(); return; }
    host.replaceChildren(el("div", { class: "nudge" }, el("p", {}, ...text),
      el("a", { class: "btn primary sm", href: PRICING, target: "_blank", rel: "noopener" }, cta || "See plans")));
  };
  health().then(show);
}

// Sign-in card. onLoad() loads the page's data and returns the signed-in identity.
function signin(onLoad, what) {
  const host = $("signin"), work = $("work");
  const input = el("input", { id: "apikey", type: "password", autocomplete: "off", placeholder: "Paste your key" });
  const go = el("button", { class: "primary" }, "Sign in");
  const msg = el("div", { class: "msg" });
  const btnRow = el("div", { class: "fields" }, input, go);
  const form = el("div", { class: "card signin" }, el("div", { class: "lock", "aria-hidden": "true" }, "🔑"),
    el("div", {}, el("label", { for: "apikey" }, what || "Your API key"), btnRow,
      el("div", { class: "faint" }, "Your admin gives you this key. Trying it on your own computer? Run ",
        el("span", { class: "mono" }, "authority local keys"), " to see yours. The key is kept in this browser tab only."), msg));
  const done = (who) => {
    host.replaceChildren(el("div", { class: "who" }, avatar(who), el("div", {}, "Signed in as ", el("strong", {}, short(who)),
      el("span", { class: "faint" }, " · " + who)), el("span", { class: "spacer" }),
      el("button", { class: "ghost sm", onclick: () => { KEY = ""; SS.del("mastyf-key"); location.reload(); } }, "Sign out")));
    work.hidden = false;
  };
  const attempt = async () => {
    go.disabled = true;
    try { done(await onLoad()); } catch (e) { host.replaceChildren(form); work.hidden = true; say(msg, e.message === "unauthorized" ? "That key was not accepted." : e.message, false); }
    go.disabled = false;
  };
  go.addEventListener("click", () => { KEY = input.value.trim(); SS.set("mastyf-key", KEY); attempt(); });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });
  host.replaceChildren(form);
  if (KEY) attempt();
  ssoConfig().then(async (c) => {
    if (!c) return;
    btnRow.prepend(el("button", { class: "primary", onclick: () => ssoStart(c).catch((e) => say(msg, e.message, false)) }, "Sign in with your company account"));
    go.className = "";
    if (await ssoFinish(c)) attempt();
  }).catch((e) => say(msg, e.message, false));
}

// passkey assertion over a server challenge, from one of my registered devices
async function assert(challenge, rpId, devices) {
  const allow = devices.filter((d) => d.cred_id).map((d) => ({ type: "public-key", id: unb64u(d.cred_id) }));
  if (!allow.length) throw new Error("you have no passkey yet: add one on the Devices page first");
  const cred = await navigator.credentials.get({ publicKey: { challenge, rpId, allowCredentials: allow, userVerification: "required", timeout: 120000 } });
  const id = b64u(cred.rawId);
  const dev = devices.find((d) => d.cred_id === id);
  if (!dev) throw new Error("that passkey is not one of your registered devices");
  const r = cred.response;
  return { device: dev.device, proof: JSON.stringify({ device: dev.device, ad: b64u(r.authenticatorData), cd: b64u(r.clientDataJSON), sig: b64u(r.signature) }) };
}

// ------------------------------------------------------------------ overview
const VERBS = { "data.export": "export", "data.read": "read", "data.delete": "delete", "data.write": "change", "secret.read": "read the secret",
                "repo.push": "push to", "repo.force_push": "force-push to", "auth.login": "sign in to", "payment.send": "send a payment from" };
function parseMetrics(text) {
  const m = { ALLOW: 0, ESCALATE: 0, DENY: 0 };
  for (const line of text.split("\n")) {
    const d = line.match(/^authority_decisions_total\{verdict="(\w+)".*\}\s+([\d.e+]+)/);
    if (d) m[d[1]] = (m[d[1]] || 0) + Number(d[2]);
    const g = line.match(/^(authority_\w+)\s+(-?[\d.e+]+)$/);
    if (g) m[g[1]] = Number(g[2]);
  }
  return m;
}
function setStat(id, n) {
  const box = $(id), b = box.firstChild, txt = Number(n).toLocaleString();
  if (b.textContent === txt) return;
  b.textContent = txt;
  box.classList.remove("bump"); void box.offsetWidth; box.classList.add("bump");
}
function homePage() {
  const tick = async () => {
    const st = $("livestate");
    try {
      const [h, mt] = await Promise.all([fetch("/healthz").then((r) => r.json()), fetch("/metrics").then((r) => r.text())]);
      HEALTH = h;
      const m = parseMetrics(mt), total = m.ALLOW + m.ESCALATE + m.DENY;
      setStat("s-allow", m.ALLOW); setStat("s-hold", m.ESCALATE); setStat("s-deny", m.DENY);
      const [a, e, d] = $("bar").children;
      a.style.width = total ? (100 * m.ALLOW / total) + "%" : "0";
      e.style.width = total ? (100 * m.ESCALATE / total) + "%" : "0";
      d.style.width = total ? (100 * m.DENY / total) + "%" : "0";
      $("l-wait").textContent = `${m.authority_pending_requests || 0} waiting for approval`;
      $("l-frozen").textContent = `${m.authority_frozen_identities || 0} frozen accounts`;
      $("l-model").textContent = "risk model: " + (h.model ? "on" : "off");
      st.replaceChildren(el("i", { class: "dot on" }), el("span", {}, `${h.role} · policy ${h.policy}`));
      const note = $("modelnote");
      if (!h.model && !note.firstChild) {
        note.append(el("div", { class: "callout" }, el("span", { class: "ic" }, "◐"), el("p", {},
          el("strong", {}, "No risk model is loaded, so every sensitive action waits for a person. "),
          "That is safe, but it interrupts people more than it needs to. ",
          el("a", { href: "/lab" }, "See what a model would change in the lab"), ". ",
          isPaid() ? "Load your model with --model." : el("a", { href: "#upgrade" }, "Paid plans include a ready-made model"),
          isPaid() ? "" : ", or train your own with ", isPaid() ? "" : el("span", { class: "mono" }, "authority train"), isPaid() ? "" : ".")));
      } else if (h.model) note.replaceChildren();
      if (isPaid()) $("upgrade").hidden = true;
    } catch (_) {
      st.replaceChildren(el("i", { class: "dot off" }), el("span", {}, "engine offline"));
    }
  };
  tick(); setInterval(tick, 3000);
  if (KEY) api("/v1/devices").then((d) => { if (d.devices.length) $("st1").classList.add("done"); }).catch(() => {});
}

// ------------------------------------------------------------------ approvals page
function approvePage() {
  let mine = { devices: [], rp_id: location.hostname };
  const shown = new Map();  // fingerprint -> card

  function actionCard(p) {
    const a = p.action, who = short(p.requester);
    const reason = el("textarea", { rows: "2", placeholder: "Why you are approving (at least 8 characters), e.g. a ticket number" });
    const msg = el("div", { class: "msg" });
    const quick = ["Confirmed with them by phone", "Matches an approved ticket", "Expected, routine for this team"]
      .map((t) => el("button", { class: "chip", type: "button", onclick: () => { reason.value = t; reason.focus(); } }, t));
    const verb = VERBS[a.action_type];
    const ask = el("div", { class: "req__ask" }, el("strong", {}, who), " wants to ",
      verb ? el("strong", {}, verb) : el("strong", { class: "mono" }, a.action_type), " ",
      a.count != null ? el("strong", {}, Number(a.count).toLocaleString() + (a.count === 1 ? " item" : " records")) : "",
      a.count != null ? " from " : "", el("span", { class: "res" }, a.resource),
      a.destination ? " to " : "", a.destination ? el("span", { class: "res" }, a.destination) : "");
    const approve = el("button", { class: "primary" }, "Approve with passkey");
    const deny = el("button", { class: "danger" }, "Deny");
    const foot = el("div", { class: "req__foot" }, approve, deny, el("span", { class: "spacer" }), el("span", { class: "faint" }, "Your passkey will ask for your Mac password or Touch ID"));
    const card = el("div", { class: "card req" },
      el("div", { class: "req__top" }, avatar(p.requester), el("div", {}, ask, el("div", { class: "chips" },
        el("span", { class: "chip warn" }, "Held"), ...p.reasons.map((r) => el("span", { class: "chip" }, r))))),
      el("div", { class: "req__body" }, el("label", {}, "Your reason"), reason, el("div", { class: "chips" }, ...quick),
        el("details", {}, el("summary", {}, "Technical details"), el("div", { class: "mono faint" }, "requester " + p.requester), el("div", { class: "mono faint" }, "fingerprint " + p.fingerprint)), msg),
      foot);
    approve.addEventListener("click", async () => {
      try {
        const why = reason.value.trim();
        if (why.length < 8) { reason.focus(); throw new Error("Give a reason of at least 8 characters."); }
        approve.disabled = deny.disabled = true;
        const chal = await sha256(enc.encode(`mastyf-approve|${p.fingerprint}|${p.requester}|${why}`));
        const s = await assert(chal, mine.rp_id, mine.devices);
        const r = await api("/v1/approve", { fingerprint: p.fingerprint, requester: p.requester, approver: mine.identity, reason: why, signature: s.proof });
        card.classList.add("done");
        foot.replaceChildren(el("span", { class: "chip ok" }, "✓ Approved"), el("span", {}, `${who} can retry now.`), el("span", { class: "spacer" }), el("span", { class: "mono faint" }, r.approval_id));
        msg.textContent = "";
      } catch (e) { approve.disabled = deny.disabled = false; say(msg, e.message, false); }
    });
    deny.addEventListener("click", async () => {
      try {
        approve.disabled = deny.disabled = true;
        await api("/v1/deny", { fingerprint: p.fingerprint, approver: mine.identity, reason: reason.value.trim() || "denied" });
        card.classList.add("done", "denied");
        foot.replaceChildren(el("span", { class: "chip bad" }, "✕ Denied"), el("span", {}, `${who} was not allowed to do this.`));
        setTimeout(() => { card.remove(); shown.delete(p.fingerprint); refreshEmpty(); }, 5000);
      } catch (e) { approve.disabled = deny.disabled = false; say(msg, e.message, false); }
    });
    return card;
  }
  const allClear = el("div", { class: "card allclear" }, el("img", { src: "/web/mark.png", alt: "" }), el("h3", {}, "All clear"),
    el("p", { class: "empty" }, "Nothing is waiting for you. New requests appear here on their own."));
  function refreshEmpty() {
    const box = $("actions");
    if (!shown.size) { if (!box.contains(allClear)) box.replaceChildren(allClear); } else if (box.contains(allClear)) allClear.remove();
  }
  async function refresh() {
    const { pending } = await api("/v1/pending");
    const box = $("actions"), live = new Set(pending.map((p) => p.fingerprint));
    for (const p of pending) if (!shown.has(p.fingerprint)) { const c = actionCard(p); shown.set(p.fingerprint, c); box.append(c); }
    for (const [fp, c] of shown) if (!live.has(fp) && !c.classList.contains("done")) { c.remove(); shown.delete(fp); }
    refreshEmpty();

    const dbox = $("devices");
    let enr = [];
    try { enr = (await api("/v1/enroll/pending")).pending; } catch (_) { /* enrolment off */ }
    const keep = new Set(enr.map((r) => r.rid));
    for (const c of [...dbox.querySelectorAll("[data-rid]")]) if (!keep.has(c.dataset.rid) && !c.classList.contains("done")) c.remove();
    for (const r of enr) {
      if (dbox.querySelector(`[data-rid="${CSS.escape(r.rid)}"]`)) continue;
      const msg = el("div", { class: "msg" });
      const card = el("div", { class: "card req", "data-rid": r.rid },
        el("div", { class: "req__top" }, avatar(r.identity), el("div", {}, el("div", { class: "req__ask" }, el("strong", {}, short(r.identity)), " wants to add a new device."),
          el("div", { class: "chips" }, el("span", { class: "chip warn" }, "Only approve after confirming with them in person or by a call you placed")))),
        el("div", { class: "req__body" }, msg));
      const btn = el("button", { class: "primary", onclick: async () => {
        try { const s = await assert(unb64u(r.challenge), mine.rp_id, mine.devices); const x = await api("/v1/enroll/approve", { rid: r.rid, device: s.device, proof: s.proof }); card.classList.add("done"); say(msg, x.status, true); }
        catch (e) { say(msg, e.message, false); }
      } }, "Approve with passkey");
      card.append(el("div", { class: "req__foot" }, btn));
      dbox.append(card);
    }
    const none = dbox.querySelector(".empty-dev");
    if (!dbox.querySelector("[data-rid]")) { if (!none) dbox.append(el("p", { class: "empty empty-dev" }, "No device requests waiting.")); }
    else if (none) none.remove();
  }
  let timer = null;
  signin(async () => {
    mine = await api("/v1/devices");
    await refresh();
    if (!timer) timer = setInterval(() => refresh().catch(() => {}), 4000);
    return mine.identity;
  });
  nudge([el("strong", {}, "Approving routine work all day? "), "A risk model lets everyday work through on its own, so only the unusual reaches you. ",
    el("a", { href: "/lab" }, "Try it on your own requests in the lab.")], "See plans");

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

function enrollPage() {
  let mine = null;
  const steps = () => [...$("steps").children];
  const stage = (n) => steps().forEach((li, i) => { li.className = i < n ? "ok" : i === n ? "on" : ""; });
  async function load() {
    mine = await api("/v1/devices");
    const list = $("list"); list.replaceChildren();
    if (!mine.devices.length) list.append(el("p", { class: "empty" }, "No devices yet. Add this one below: it takes a minute."));
    for (const d of mine.devices) {
      list.append(el("div", { class: "device" }, el("span", { class: "ic", "aria-hidden": "true" }, "🔑"),
        el("div", {}, el("b", {}, d.device), el("span", { class: "faint" }, d.cred_id ? "Passkey ready" : "Signing key")), el("span", { class: "spacer" }),
        el("button", { class: "danger sm", onclick: async () => { if (confirm(`Remove ${d.device}? It will stop receiving data keys.`)) { await api("/v1/devices/remove", { device: d.device }); await load(); } } }, "Remove")));
    }
    return mine.identity;
  }
  signin(load);
  nudge([el("strong", {}, "Rolling this out to a whole company? "), "Paid plans keep people and teams in sync with Okta, Entra ID or Google, so access follows your directory."], "See plans");

  $("begin").addEventListener("click", async () => {
    const out = $("addmsg"), step = $("step");
    try {
      const name = $("devname").value.trim();
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) throw new Error("Use letters, digits, - and _ only, e.g. work-mac.");
      if (!window.PublicKeyCredential) throw new Error("This browser has no passkey support.");
      const b = await api("/v1/enroll/begin", {});
      out.textContent = ""; out.className = "msg";
      stage(1);
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
        stage(3);
        say(out, `Added ${r.device}. You can approve requests now.`, true); step.replaceChildren(); await load();
      };
      const showRegister = () => {
        stage(2);
        step.replaceChildren(el("div", { class: "waiting" }, el("span", { class: "chip ok" }, "✓ Approved"), el("span", {}, "Last step: your Mac asks for your password or Touch ID.")),
          el("div", { class: "row" }, el("button", { class: "primary", onclick: async () => {
            try { await finish(); } catch (e) { say(out, e.message, false); } } }, "Register this device")));
      };
      if (b.has_devices) {
        step.append(el("div", { class: "row" }, el("button", { class: "primary", onclick: async () => {
            try { const s = await assert(unb64u(b.challenge), b.rp_id, b.allow); await api("/v1/enroll/authorise", { rid: b.rid, device: s.device, proof: s.proof }); clearInterval(poll); showRegister(); }
            catch (e) { say(out, e.message, false); }
          } }, "Confirm with a device I already have")));
      }
      step.append(el("div", { class: "waiting" }, el("span", { class: "spin" }),
        el("span", {}, (b.has_devices ? "Or ask " : "Waiting for ") + "two approvers to approve request ", el("span", { class: "mono" }, b.rid),
          " on their Approvals page. This page moves on by itself.")));
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
  const classes = Object.keys(ceil).sort();
  if (!classes.length) return el("p", { class: "empty" }, "No budgeted data classes.");
  const box = el("div", { class: "ceil" });
  for (const c of classes) {
    const now = ceil[c].per_day;
    let delta = null;
    if (before && before[c] && before[c].per_day !== now) {
      const up = now === null || (before[c].per_day !== null && now > before[c].per_day);
      delta = el("span", { class: "delta " + (up ? "up" : "down") }, (up ? "▲ up from " : "▼ down from ") + fmtN(before[c].per_day));
    }
    box.append(el("div", { class: "stat" + (delta ? (delta.classList.contains("up") ? " warn" : " ok") : "") }, el("b", {}, fmtN(now)), el("span", {}, c + " a day"),
      ceil[c].who && ceil[c].who.length ? el("span", { class: "faint" }, "worst: " + ceil[c].who.map(short).join(", ")) : null, delta));
  }
  return box;
}

function limitsPage() {
  signin(async () => {
    const data = await api("/v1/teams");
    $("ceiling").replaceChildren(ceilingCard(data.ceiling));
    const host = $("teams");
    host.replaceChildren();
    if (!data.teams.length) host.append(el("p", { class: "empty" }, "No teams in the policy yet."));
    for (const t of data.teams) {
      const card = el("div", { class: "card team" });
      card.append(el("h3", {}, t.name, el("span", { class: "chip" }, t.members.length + (t.members.length === 1 ? " person" : " people")),
        ...t.idp_groups.map((g) => el("span", { class: "chip gold" }, "from " + g))));
      card.append(el("div", { class: "chips" }, el("span", { class: "faint" }, "May: "), ...(t.allowed_actions.length ? t.allowed_actions.map((a) => el("span", { class: "chip" }, a)) : [el("span", { class: "faint" }, "nothing")])));
      const out = el("div", { class: "preview" });
      const classes = Object.keys(t.budgets).sort();
      if (!classes.length) card.append(el("p", { class: "empty" }, "No data limits: this team can read no budgeted data."));
      for (const c of classes) {
        const start = Number(t.budgets[c] ?? 0);
        const max = String(Math.max(1000, start * 4));
        const num = el("input", { type: "number", min: "0", step: "10", value: String(start), "aria-label": t.name + " " + c + " per day" });
        const rng = el("input", { type: "range", min: "0", max, step: "10", value: String(start), "aria-label": t.name + " " + c + " slider" });
        let wait = null;
        const preview = () => {
          clearTimeout(wait);
          wait = setTimeout(async () => {
            if (Number(num.value) === start) { out.replaceChildren(); $("ceiling").replaceChildren(ceilingCard(data.ceiling)); return; }
            try {
              const r = await api("/v1/teams/preview", { team: t.name, class: c, limit: Number(num.value) });
              out.replaceChildren(el("p", {}, "If ", el("strong", {}, t.name), " could read ", el("strong", {}, fmtN(r.limit) + " " + c), " a day, the worst case would be:"), ceilingCard(r.after, r.before));
            } catch (e) { out.replaceChildren(el("p", { class: "msg bad" }, e.message)); }
          }, 250);
        };
        rng.addEventListener("input", () => { num.value = rng.value; preview(); });
        num.addEventListener("input", () => { rng.value = num.value; preview(); });
        card.append(el("div", { class: "lim" }, el("label", {}, c, el("small", {}, "per person, per day · now " + fmtN(t.budgets[c]))), rng, num));
      }
      card.append(out);
      if (t.members.length) card.append(el("div", { class: "chips" }, el("span", { class: "faint" }, "Members: "), ...t.members.map((m) => el("span", { class: "chip" }, short(m)))));
      host.append(card);
    }
    return "admin";
  }, "Admin API key");
  nudge([el("strong", {}, "Typing team members by hand? "), "With SCIM sync (paid plans) teams follow your identity provider, and shadow mode shows what a new limit would have held across a month of real logs."], "See plans");
}

// ---------------------------------------------------------------- risk model lab
const VLABEL = { ALLOW: "Allowed", ESCALATE: "Held for a person", DENY: "Blocked" };
const VICON = { ALLOW: "✓", ESCALATE: "⏸", DENY: "✕" };
const PRESETS = [
  { t: "Alice's weekly report", d: "1,200 customer records to the usual reports bucket, 2 p.m.", kind: ["ok", "Everyday work"],
    a: { identity: "human:alice", action_type: "data.export", resource: "db://crm/customers", count: 1200, destination: "s3://corp-reports/weekly" }, h: 14 },
  { t: "Alice's export from earlier", d: "500 customer records, the kind of request that waits for you today", kind: ["ok", "Everyday work"],
    a: { identity: "human:alice", action_type: "data.export", resource: "db://crm/customers/export", count: 500 }, h: 11 },
  { t: "Bob on call at 2 a.m.", d: "Reads the database password, as he does when on call", kind: ["ok", "Everyday work"],
    a: { identity: "human:bob", action_type: "secret.read", resource: "vault://prod/db/password", count: 1 }, h: 2 },
  { t: "Nightly warehouse export", d: "The export job's usual 7,000 records at 2 a.m.", kind: ["ok", "Everyday work"],
    a: { identity: "svc:export-job", action_type: "data.export", resource: "db://crm/customers", count: 7000, destination: "s3://corp-warehouse/nightly" }, h: 2 },
  { t: "Bob deletes the backups", d: "50 backup sets wiped at 3 a.m., the first step of a ransomware attack", kind: ["bad", "Attack"],
    a: { identity: "human:bob", action_type: "backup.delete", resource: "backup://vault/nightly", count: 50 }, h: 3 },
  { t: "Bob rewrites 5,000 files at night", d: "Mass file writes on production at 3 a.m., as when files are being encrypted", kind: ["bad", "Attack"],
    a: { identity: "human:bob", action_type: "file.write_bulk", resource: "fs://prod/data", count: 5000 }, h: 3 },
  { t: "Quiet theft", d: "800 customer records to an unknown website at 3 a.m.", kind: ["warn", "Attack"],
    a: { identity: "human:alice", action_type: "data.export", resource: "db://crm/customers", count: 800, destination: "https://dropfile.top/u" }, h: 3 },
];
const RES_HINT = { "data.read": "db://crm/customers/query", "data.export": "db://crm/customers", "secret.read": "vault://prod/db/password",
                   "repo.push": "github://org/app/feature/12", "process.exec": "proc://prod/ops/runbook", "artifact.publish": "cdn://static/js/tag.js",
                   "network.egress": "net://out", "file.write_bulk": "backup://vault/nightly" };
const cntFrom = (v) => { const n = Math.pow(10, v / 10); return n < 10 ? Math.round(n) : n < 1000 ? Math.round(n / 10) * 10 : Math.round(n / 100) * 100; };
const cntTo = (n) => Math.round(10 * Math.log10(Math.max(1, n)));
const hh = (h) => String(h).padStart(2, "0") + ":00";

function labPage() {
  let status = null, saved = 0, caught = 0, tries = 0;
  const history = el("div", { class: "history" });
  const pill = (v) => el("span", { class: "pill " + v }, VICON[v] + " " + VLABEL[v]);

  function fillWho() {
    const who = $("who");
    const ids = status.identities.slice().sort((x, y) => (y.history - x.history) || x.id.localeCompare(y.id));
    who.replaceChildren(...ids.map((i) => el("option", { value: i.id }, short(i.id) + (i.history ? "" : " (no history yet)"))));
    who.addEventListener("change", fillTypes);
    fillTypes();
  }
  function fillTypes(keep) {
    const me = status.identities.find((i) => i.id === $("who").value);
    $("atype").replaceChildren(...(me ? me.allowed : []).map((t) => el("option", { value: t }, t)));
    if (typeof keep === "string") $("atype").value = keep;
    if (typeof keep !== "string") $("res").value = RES_HINT[$("atype").value] || "";
  }
  $("atype").addEventListener("change", () => { $("res").value = RES_HINT[$("atype").value] || $("res").value; });
  const cnt = $("cnt"), hour = $("hour");
  cnt.addEventListener("input", () => { $("cntv").textContent = cntFrom(Number(cnt.value)).toLocaleString(); });
  hour.addEventListener("input", () => { $("hourv").textContent = hh(hour.value); });
  $("destchips").append(
    el("button", { class: "chip", type: "button", onclick: () => { $("dest").value = "s3://corp-reports/weekly"; } }, "usual: reports bucket"),
    el("button", { class: "chip", type: "button", onclick: () => { $("dest").value = "https://dropfile.top/u"; } }, "unknown website"),
    el("button", { class: "chip", type: "button", onclick: () => { $("dest").value = ""; } }, "nothing leaves"));

  function setForm(p) {
    $("who").value = p.a.identity; fillTypes(p.a.action_type);
    $("res").value = p.a.resource; cnt.value = cntTo(p.a.count); $("cntv").textContent = p.a.count.toLocaleString();
    $("dest").value = p.a.destination || ""; hour.value = p.h; $("hourv").textContent = hh(p.h);
  }
  function current() {
    const a = { identity: $("who").value, action_type: $("atype").value, resource: $("res").value.trim(), count: cntFrom(Number(cnt.value)) };
    if ($("dest").value.trim()) a.destination = $("dest").value.trim();
    return a;
  }
  function verdictLine(w0, w1, who, risk) {
    if (w0 === "ESCALATE" && w1 === "ALLOW") { saved++; return el("div", { class: "verdictline ok" }, el("strong", {}, "No interruption. "), `The model recognised this as normal for ${who}, so nobody had to stop and approve it.`); }
    if (w1 === "DENY" && w0 !== "DENY") { caught++; return el("div", { class: "verdictline bad" }, el("strong", {}, "Blocked outright. "), "Without a model this only waits in someone's queue next to routine requests, where it is easy to approve by mistake. The model refused it."); }
    if (w1 === "ESCALATE" && w0 === "ALLOW") { caught++; return el("div", { class: "verdictline bad" }, el("strong", {}, "Caught. "), "Without a model this would have gone straight through. The model asked a person to check it."); }
    if (w1 === "ALLOW") return el("div", { class: "verdictline" }, el("strong", {}, "Allowed either way. "), "Ordinary work that no rule or model objects to.");
    if (w1 === "DENY") return el("div", { class: "verdictline" }, el("strong", {}, "Blocked either way. "), "Your policy forbids this, with or without a model.");
    if (risk != null && risk >= status.escalate_at) return el("div", { class: "verdictline" }, el("strong", {}, "Held either way, "), `and the model agrees it is unusual for ${who}, so the approver can see why.`);
    return el("div", { class: "verdictline" }, el("strong", {}, "Held either way by your rules. "), "A limit or the destination allowlist catches this one before the model is needed. The model is there for what rules cannot see.");
  }
  function render(a, r) {
    const who = short(a.identity), m = r.with;
    const risk = m.risk == null ? null : m.risk;
    const gauge = el("div", { class: "gauge" }, el("i"), el("em", {}, risk == null ? "not scored" : "risk " + risk.toFixed(2)));
    const notice = el("div", { class: "notice" }, ...r.explain.map((f) => {
      const bar = el("i");
      requestAnimationFrame(() => { bar.style.width = Math.round(f.level * 100) + "%"; });
      return el("div", { class: f.level >= 0.5 ? "hot" : "" }, el("span", {}, f.label), el("span", { class: "meter" }, bar));
    }));
    const line = verdictLine(r.without.verdict, m.verdict, who, risk);
    tries++;
    $("sc-tries").textContent = tries; $("sc-saved").textContent = saved; $("sc-caught").textContent = caught;
    $("result").replaceChildren(
      el("div", { class: "vs" },
        el("div", { class: "vcard" }, el("h4", {}, "Today · no model"), pill(r.without.verdict), el("ul", {}, ...r.without.reasons.slice(0, 3).map((x) => el("li", {}, x)))),
        el("div", { class: "vcard model" }, el("h4", {}, status.model === "yours" ? "With your risk model" : "With the risk model"), pill(m.verdict), el("ul", {}, ...m.reasons.slice(0, 3).map((x) => el("li", {}, x))))),
      line,
      el("div", { class: "card flat" }, el("h3", {}, "How risky the model thinks it is"), gauge,
        el("div", { class: "gscale" }, el("span", {}, "0 · normal"), el("span", {}, `${status.escalate_at} · ask a person`), el("span", {}, `${status.deny_at} · block`), el("span", {}, "1")),
        el("h3", { class: "spaced" }, `What the model noticed about ${who}`), notice),
      history);
    if (risk != null) requestAnimationFrame(() => { gauge.firstChild.style.left = `calc(${risk * 100}% - 2px)`; gauge.lastChild.style.left = Math.min(94, Math.max(6, risk * 100)) + "%"; });
    history.prepend(el("div", {}, el("span", { class: "sp " + r.without.verdict }, VLABEL[r.without.verdict]), "→",
      el("span", { class: "sp " + m.verdict }, VLABEL[m.verdict]), el("span", {}, `${who} · ${a.action_type} · ${a.count.toLocaleString()}`), el("span", { class: "spacer" }), el("span", { class: "mono faint" }, r.lab_time)));
    while (history.children.length > 6) history.lastChild.remove();
    $("labtime").textContent = "Lab clock: " + r.lab_time;
  }
  async function run(a, h) {
    const btn = $("run"); btn.disabled = true;
    try { render(a, await api("/v1/lab/try", { action: a, hour: h })); }
    catch (e) { $("result").replaceChildren(el("div", { class: "card flat" }, el("p", { class: "msg bad" }, e.message))); }
    btn.disabled = false;
  }
  $("run").addEventListener("click", () => {
    if (!$("res").value.trim()) { $("res").focus(); return; }
    document.querySelectorAll(".preset.on").forEach((x) => x.classList.remove("on"));
    run(current(), Number(hour.value));
  });
  $("reset").addEventListener("click", async () => {
    try { await api("/v1/lab/reset", {}); saved = caught = tries = 0; ["sc-tries", "sc-saved", "sc-caught"].forEach((i) => { $(i).textContent = "0"; });
      history.replaceChildren(); $("result").replaceChildren(el("div", { class: "card flat placeholder" }, el("img", { src: "/web/mark.png", alt: "" }), el("p", { class: "empty" }, "Lab reset to its 30 days of normal history.")));
    } catch (e) { alert(e.message); }
  });

  $("replay").addEventListener("click", async () => {
    const out = $("replayout"), msg = $("replaymsg"), btn = $("replay");
    btn.disabled = true; msg.textContent = "Replaying in a fresh copy of the lab, a few seconds…"; msg.className = "msg";
    try {
      const r = await api("/v1/lab/replay", {});
      const s = r.summary;
      msg.textContent = "";
      if (!r.items.length) { out.replaceChildren(el("p", { class: "empty" }, "Your engine has not held or refused anything yet. Try a request, then replay.")); btn.disabled = false; return; }
      out.replaceChildren(
        el("div", { class: "grid g4 spaced" },
          el("div", { class: "stat warn" }, el("b", {}, String(s.held)), el("span", {}, "held for a person by your engine")),
          el("div", { class: "stat ok" }, el("b", {}, String(s.model_would_allow)), el("span", {}, "the model would have let through")),
          el("div", { class: "stat" }, el("b", {}, `${s.model_also_stopped}/${s.denied_by_you}`), el("span", {}, "of your denials the model also stopped")),
          el("div", { class: "stat bad" }, el("b", {}, String(s.blocked_by_policy)), el("span", {}, "blocked by policy (same with a model)"))),
        el("div", { class: "tablewrap" }, el("table", { class: "replay" },
          el("thead", {}, el("tr", {}, ...["Request", "Your engine", "You", "With the model"].map((h) => el("th", {}, h)))),
          el("tbody", {}, ...r.items.slice().reverse().map((i) => el("tr", {},
            el("td", {}, el("strong", {}, short(i.action.identity)), ` ${i.action.action_type} · ${Number(i.action.count).toLocaleString()}`, el("div", { class: "mono faint" }, i.action.resource)),
            el("td", {}, el("span", { class: "sp " + i.live.verdict }, VLABEL[i.live.verdict])),
            el("td", {}, i.person === "-" ? el("span", { class: "faint" }, "–") : el("span", { class: "sp " + i.person }, i.person)),
            el("td", {}, i.model ? el("span", { class: "sp " + i.model.verdict }, VLABEL[i.model.verdict]) : el("span", { class: "faint" }, i.error || "–"),
              i.model && i.model.risk != null ? el("span", { class: "faint" }, "  risk " + i.model.risk.toFixed(2)) : null)))))),
        el("p", { class: "faint" }, "Replayed in the lab, against its 30 days of synthetic history. On your own logs the numbers will differ."));
    } catch (e) { say(msg, e.message === "approvers only" ? "Replaying other people's requests is for approvers and admins." : e.message, false); }
    btn.disabled = false;
  });

  async function poll() {
    status = await api("/v1/lab");
    const st = $("labstate");
    if (status.state === "ready") {
      st.replaceChildren();
      if ($("labui").hidden) {
        $("labui").hidden = false;
        fillWho();
        const ids = new Set(status.identities.map((i) => i.id));
        $("presets").replaceChildren(...PRESETS.filter((p) => ids.has(p.a.identity)).map((p) => {
          const b = el("button", { class: "preset", type: "button" }, el("b", {}, p.t), el("span", {}, p.d), el("span", { class: "tag " + p.kind[0] }, p.kind[1]));
          b.addEventListener("click", () => { document.querySelectorAll(".preset.on").forEach((x) => x.classList.remove("on")); b.classList.add("on"); setForm(p); run(p.a, p.h); });
          return b;
        }));
        if (status.model === "yours") {
          $("up-eyebrow").textContent = "Your model";
          $("up-title").textContent = "This lab runs your engine's own risk model";
          $("up-text").textContent = "Every result on this page comes from the model your engine loaded, against a sandbox with synthetic history.";
          $("upgrade").querySelector(".row").hidden = true;
        }
      }
      return;
    }
    if (status.state === "error") { st.replaceChildren(el("div", { class: "callout" }, el("span", { class: "ic" }, "!"), el("p", {}, "The lab could not start: " + status.error))); return; }
    st.replaceChildren(el("div", { class: "waiting" }, el("span", { class: "spin" }),
      el("span", {}, status.state === "training" ? (status.model === "yours" ? "Loading your model…" : "Training a preview model on synthetic incidents. About 15 seconds…")
        : "Giving the lab 30 days of normal activity…")));
    setTimeout(() => poll().catch(() => {}), 1200);
  }
  signin(async () => {
    status = await api("/v1/lab");  // also checks the key
    const me = await api("/v1/devices").catch(() => null);
    poll();
    if (isPaid() && status.model !== "yours") $("upgrade").hidden = true;
    return me ? me.identity : "signed in";
  });
}

chrome();
const PAGES = { home: homePage, approve: approvePage, enroll: enrollPage, limits: limitsPage, lab: labPage };
(PAGES[document.body.dataset.page] || (() => {}))();

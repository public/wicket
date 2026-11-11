"use strict";
// The console's script, served as a static file under a strict CSP (no inline script or style, no
// eval). Every string from the ledger is untrusted (agents influence paths and reasons): set as textContent only.
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = String(text); return e; };
const strip = s => String(s ?? "").replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, " ");
const ago = (now, t) => { const s = Math.max(0, now - t); return s < 90 ? s + "s ago" : s < 5400 ? Math.round(s / 60) + "m ago" : Math.round(s / 3600) + "h ago"; };
const riskClass = r => ({ R0Read: "r0", R1ReadScoped: "r1", R2WriteReversible: "r2", R3ExternalOrIrreversible: "r3", R4ExecOrPrivilege: "r4" })[r] || "r4";
const riskLabel = r => ({ R0Read: "R0 read", R1ReadScoped: "R1 read", R2WriteReversible: "R2 write", R3ExternalOrIrreversible: "R3 external", R4ExecOrPrivilege: "R4 exec/privilege" })[r] || r;

let toastTimer;
function toast(t) { const m = document.getElementById("msg"); m.textContent = t; m.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { m.hidden = true; }, 3000); }

// ---- passkeys (WebAuthn) ----
const b2a = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const a2b = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); s += "===".slice((s.length + 3) % 4); return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json", "x-wicket-csrf": "1" }, body: JSON.stringify(body || {}) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}
function getOptions(pk) {
  return { ...pk, challenge: a2b(pk.challenge), allowCredentials: (pk.allowCredentials || []).map(c => ({ ...c, id: a2b(c.id) })) };
}
async function assertWith(pk) {
  const cred = await navigator.credentials.get({ publicKey: getOptions(pk) });
  return { challenge: pk.challenge, id: b2a(cred.rawId), clientDataJSON: b2a(cred.response.clientDataJSON),
           authenticatorData: b2a(cred.response.authenticatorData), signature: b2a(cred.response.signature) };
}
async function registerPasskey() {
  try {
    const { publicKey: pk } = await post("/api/register/begin");
    const opts = { ...pk, challenge: a2b(pk.challenge), user: { ...pk.user, id: a2b(pk.user.id) }, excludeCredentials: (pk.excludeCredentials || []).map(c => ({ ...c, id: a2b(c.id) })) };
    const cred = await navigator.credentials.create({ publicKey: opts });
    const name = (document.getElementById("pkname") || {}).value || "passkey";
    const j = await post("/api/register/finish", { challenge: pk.challenge, name, clientDataJSON: b2a(cred.response.clientDataJSON), attestationObject: b2a(cred.response.attestationObject) });
    toast(j.ok); boot();
  } catch (e) { toast("passkey: " + e.message); }
}
async function signIn() {
  try { const { publicKey } = await post("/api/login/begin"); const j = await post("/api/login/finish", await assertWith(publicKey)); toast(j.ok); boot(); }
  catch (e) { toast("sign-in: " + e.message); }
}
// Every action is signed: the passkey challenge is the hash of exactly the action the server
// returns from begin, and the toast spells out that action (not what the page asked for).
function describe(a) {
  const s = x => strip(x);
  if (a.action === "decide") return a.decision + " " + s(a.method + " " + a.host + a.path) + (a.prefix ? "* (every path under it)" : "") + (a.agent ? " for agent " + s(a.agent) : "") + ((a.requested_by || []).length ? " (" + a.requested_by.map(s).join(", ") + ")" : "");
  if (a.action === "say") return "send to " + s(a.run) + ": \u201c" + s(a.text).slice(0, 80) + "\u201d";
  if (a.action === "revoke") return "revoke " + s(a.run) + " (" + s(a.agent) + "): " + s(a.reason);
  if (a.action === "start_run") return "start " + s(a.root + "/" + a.manifest) + " as " + s(a.principal && a.principal.id) + (a.task ? " with task \u201c" + s(a.task).slice(0, 60) + "\u201d" : "");
  return s(a.action);
}
async function signed(body) {
  try {
    const begin = await post("/api/action/begin", body);
    toast("Confirm with your passkey: " + describe(begin.action));
    const j = await post("/api/action/finish", await assertWith(begin.publicKey));
    toast(j.ok);
  } catch (e) { toast(e.message); }
  refresh();
}
const act = (kind, body) => signed({ ...body, action: "decide", decision: kind });

// The requesting agent's identity, verified by the console against wicket's issuer. Approve is
// disabled when an agent's identity does not verify: you can't approve without knowing who for.
function renderAgent(c, id) {
  const w = el("div", "agent");
  if (id.verified) {
    w.append(el("span", "ok", "✓ "), el("b", "", strip(id.agent)), document.createTextNode(" · zone " + strip(id.zone)));
    w.append(el("div", "chain", "Acting for: " + (id.acting_for || []).map(strip).join(" → ")));
    w.append(el("div", "idline", strip(id.id)));
    c.append(w); return true;
  }
  if ((id.error || "").startsWith("no identity was issued")) {
    w.append(el("div", "", "Program run (no agent identity)")); c.append(w); return true;
  }
  w.append(el("div", "bad", "Agent identity NOT verified: " + strip(id.error || "unknown") + ". Approval is disabled."));
  c.append(w); return false;
}

// Who in the box asked, from the agent's own event stream: helpful, not proof.
function renderWho(list) {
  const w = el("div", "who");
  const line = r => strip(r.agent) + " — " + strip(r.tool) + ": " + strip(r.call).slice(0, 120);
  if (!list.length) { w.append(el("div", "", "For: unknown (no agent event stream)")); }
  for (const a of list) {
    const rs = a.requesters || [];
    if (a.basis === "none" || !rs.length) w.append(el("div", "", "For: unknown — no tool call was in flight"));
    else if (a.basis === "ambiguous") { w.append(el("div", "", "For: one of " + rs.length + " concurrent calls:")); for (const r of rs) w.append(el("div", "cand", "• " + line(r))); }
    else w.append(el("div", "", "For: " + line(r0(rs))));
  }
  if (list.length > 1) w.append(el("div", "warn", "Asked by more than one agent: one grant would serve all of them."));
  w.append(el("div", "note", "Reported by the agent's event stream, not proven. Anything in this box could use the grant."));
  return w;
}
const r0 = rs => rs[0];

function renderPending(s) {
  const box = document.getElementById("pending"); box.replaceChildren();
  if (!s.pending.length) { box.append(el("div", "empty", "Nothing is waiting for a decision.")); return; }
  for (const p of s.pending) {
    const c = el("div", "card req");
    const head = el("div"); head.append(el("span", "risk " + riskClass(p.risk), riskLabel(p.risk)));
    c.append(head, el("div", "what", strip(p.method + " " + p.host + p.path) + (p.scope_prefix ? "*  (every path under it)" : "")));
    c.append(el("div", "why", strip(p.reason)));
    const idOk = renderAgent(c, p.identity || {});
    c.append(renderWho(p.attribution || []));
    c.append(el("div", "meta", p.id + " · zone " + p.zone + " · " + p.run + " · " + ago(s.now, p.created_at)));
    const b = el("div", "buttons");
    const once = el("button", "approve", p.scope_prefix ? "Approve prefix once (10 min)" : "Approve once (10 min)"); once.onclick = () => act("approve", { id: p.id, uses: 1, ttl_secs: 600 });
    const hour = el("button", "", p.scope_prefix ? "Allow prefix for 1 hour" : "Allow for 1 hour"); hour.onclick = () => act("approve", { id: p.id, unlimited: true, ttl_secs: 3600 });
    const deny = el("button", "deny", "Deny"); deny.onclick = () => act("deny", { id: p.id });
    if (!idOk) { once.disabled = true; hour.disabled = true; }
    if (p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible") b.append(once, deny); else b.append(once, hour, deny);
    c.append(b); box.append(c);
  }
}

function renderRows(id, rows, f, emptyText) {
  const box = document.getElementById(id); box.replaceChildren();
  if (!rows.length) { box.append(el("div", "empty", emptyText)); return; }
  for (const r of rows) box.append(f(r));
}

function line(op) {
  const b = op.body || {};
  if (op.kind === "op" && b.kind === "egress") {
    const cls = b.outcome === "allow" ? "ok" : b.outcome === "pending" ? "pend" : "blocked";
    const d = el("div"); d.append(el("span", cls, b.outcome.toUpperCase().padEnd(9)), document.createTextNode(strip(b.method + " " + b.host + b.path)));
    return d;
  }
  if (op.kind === "op" && b.kind === "llm") return el("div", "", "model  #" + b.requests + " " + strip(b.model || "?") + " → " + b.status + "  in " + b.input_tokens + " / out " + b.output_tokens);
  if (op.kind === "decision") return el("div", b.decision === "approve" ? "ok" : "blocked", b.decision + " " + b.request + " by " + strip(b.by) + (b.signed ? " (passkey-signed)" : ""));
  if (op.kind === "operator.passkey_added") return el("div", "", "passkey added: " + strip(b.name) + " via " + strip(b.via));
  if (op.kind === "run.start") return el("div", "", "start  " + op.run + " zone " + strip(b.zone) + " agent " + strip(b.agent));
  if (op.kind === "operator.message") return el("div", "", "say    " + op.run + " by " + strip(b.by) + " · " + b.chars + " chars" + (b.signed ? " (passkey-signed)" : ""));
  if (op.kind === "identity.revoked") return el("div", "blocked", "revoke " + op.run + " by " + strip(b.by) + ": " + strip(b.reason) + (b.signed ? " (passkey-signed)" : ""));
  if (op.kind === "run.console_start") return el("div", "", "launch " + op.run + " " + strip(b.root + "/" + b.manifest) + " by " + strip(b.by) + " (passkey-signed)");
  if (op.kind === "run.end") return el("div", "", "end    " + op.run + " " + strip(b.status) + " · " + b.model_requests + " model calls");
  return el("div", "", op.kind);
}

// A running agent can be sent a follow-up or have its identity revoked; both are signed.
function renderRun(s, x) {
  const d = el("div", "row");
  const left = el("span"); left.append(el("span", "mono", x.id), document.createTextNode(" " + strip(x.zone + " · " + (x.revoked ? "revoked" : x.status) + " · " + ago(s.now, x.started_at))));
  d.append(left);
  if (x.status === "running" && x.has_identity && !x.revoked) {
    const acts = el("span", "acts");
    const say = el("button", "", "Follow-up…");
    say.onclick = () => openRunForm("say", x.id);
    const rev = el("button", "deny", "Revoke…");
    rev.onclick = () => openRunForm("revoke", x.id);
    acts.append(say, rev); d.append(acts);
  }
  return d;
}

// The follow-up and revoke forms: one in-page form (no browser dialogs), kept outside the runs list
// so the 2-second refresh doesn't wipe what the operator is typing.
function openRunForm(kind, run) {
  const f = document.getElementById("runform"), text = document.getElementById("runform-text");
  f.dataset.kind = kind; f.dataset.run = run;
  f.className = "card " + kind;
  document.getElementById("runform-title").textContent = kind === "say"
    ? "Follow-up for " + run + " (it arrives as the agent's next turn):"
    : "Revoke " + run + "'s identity: its box is stopped and its requests can't be approved. Reason:";
  const go = document.getElementById("runform-go");
  go.textContent = kind === "say" ? "Send" : "Revoke";
  go.className = kind === "say" ? "approve" : "deny";
  text.value = kind === "say" ? "" : "revoked by the operator";
  f.hidden = false; text.focus();
}
function closeRunForm() { const f = document.getElementById("runform"); f.hidden = true; document.getElementById("runform-text").value = ""; }
function submitRunForm(ev) {
  ev.preventDefault();
  const f = document.getElementById("runform"), text = document.getElementById("runform-text").value;
  const run = f.dataset.run, kind = f.dataset.kind;
  if (kind === "say") { if (!text.trim()) return; signed({ action: "say", run, text }); }
  else signed({ action: "revoke", run, reason: text });
  closeRunForm();
}

// Runs start only from manifests the server lists (its allowlisted directories); the page sends a
// root and a file name, never a path.
function renderStart(s) {
  const box = document.getElementById("start");
  const ms = s.manifests || [];
  // Rebuild only when the list changes, so what the operator is typing survives the poll.
  const key = JSON.stringify(ms);
  if (box.dataset.key === key) return;
  box.dataset.key = key;
  box.replaceChildren();
  if (!ms.length) { box.append(el("div", "empty", "No manifests to start: put one in the installation's manifests directory.")); return; }
  const sel = el("select");
  for (const m of ms) {
    const o = el("option", "", strip(m.root + "/" + m.name) + (m.valid ? " · " + strip(m.agent ? "agent " + m.agent : "program " + m.program) + " · zone " + strip(m.zone) : " · invalid"));
    o.value = JSON.stringify([m.root, m.name]); o.disabled = !m.valid; sel.append(o);
  }
  const task = el("textarea"); task.placeholder = "Task (optional; replaces the manifest's task, agents only)";
  const b = el("div", "buttons"); const go = el("button", "approve", "Start run");
  go.onclick = () => { const [root, manifest] = JSON.parse(sel.value); signed({ action: "start_run", root, manifest, task: task.value }); task.value = ""; };
  b.append(go);
  box.append(sel, task, b, el("div", "meta", "The run's principal is you (this passkey), not the host user."));
}

function renderOperator(s) {
  const box = document.getElementById("operator"); box.replaceChildren();
  for (const k of s.passkeys) { const d = el("div", "row"); d.append(el("span", "", "passkey: " + strip(k.name)), el("span", "mono", String(k.id).slice(0, 16) + "…")); box.append(d); }
  const b = el("div", "buttons");
  const out = el("button", "", "Sign out"); out.onclick = async () => { try { await post("/api/logout"); } catch (e) { /* signed out anyway */ } boot(); };
  b.append(out); box.append(b);
  box.append(el("div", "note", "To add a passkey, run `wicket operator enrol-link` on the host and open the link on the new device."));
}

// Signed out, the server answers /api/me with 401 and tells the page nothing else: the page offers
// passkey sign-in (and says where enrolment links come from) whatever the server's state.
async function boot() {
  const r = await fetch("/api/me");
  const me = r.ok ? await r.json() : { who: { state: "none" } };
  const auth = document.getElementById("auth"), con = document.getElementById("console");
  auth.replaceChildren();
  if (me.who.state === "operator") { auth.hidden = true; con.hidden = false; refresh(); return; }
  con.hidden = true; auth.hidden = false;
  document.getElementById("tenant").textContent = "";
  if (me.who.state === "bootstrap") {
    auth.append(el("div", "", "Enrol this device's passkey. It signs you in, and you will sign every approval with it."));
    const name = el("input", "text"); name.id = "pkname"; name.value = "my phone"; name.maxLength = 40;
    const b = el("div", "buttons"); const go = el("button", "approve", "Create passkey"); go.onclick = registerPasskey; b.append(go);
    auth.append(name, b);
  } else {
    auth.append(el("div", "", "Sign in to approve or deny what your agents are waiting on, start runs and steer them."));
    const b = el("div", "buttons"); const go = el("button", "approve", "Sign in with passkey"); go.onclick = signIn; b.append(go); auth.append(b);
    auth.append(el("div", "note", "No passkey yet? Open a one-time enrolment link from the host (`wicket serve` prints one at first start; `wicket operator enrol-link` makes another)."));
  }
}

async function refresh() {
  try {
    const r = await fetch("/api/state");
    if (!r.ok) { boot(); return; }
    const s = await r.json();
    document.getElementById("tenant").textContent = "tenant " + s.tenant;
    renderPending(s);
    renderRows("runs", s.runs, x => renderRun(s, x), "No runs yet.");
    renderStart(s);
    renderRows("decided", s.decided, x => { const d = el("div", "row"); d.append(el("span", "mono", strip(x.id + " " + x.method + " " + x.host + x.path)), el("span", x.status === "granted" ? "ok" : "blocked", x.status)); return d; }, "No decisions yet.");
    renderRows("audit", s.audit.slice().reverse(), line, "No activity yet.");
    renderOperator(s);
  } catch (e) { /* keep polling */ }
}
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("runform").addEventListener("submit", submitRunForm);
  document.getElementById("runform-cancel").addEventListener("click", closeRunForm);
  boot();
  setInterval(() => { if (!document.getElementById("console").hidden) refresh(); }, 2000);
});

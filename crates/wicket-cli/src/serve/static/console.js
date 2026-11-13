"use strict";
// The console's script, served as a static file under a strict CSP (no inline script or style, no
// eval). Every string from the ledger is untrusted (agents influence paths and reasons): set as textContent only.
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = String(text); return e; };
// The same set as wicket_core::text::is_unsafe: C0, DEL, C1, bidi, zero-width, line separators (#128).
const strip = s => String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, " ");
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
// returns from begin. Signing takes two steps (#124): the click asks the server for that action, and
// an in-page confirmation, built from what the server returned (not what the page asked for), states
// it with its own sign button. The authenticator's own sheet shows only the site's name, so this is
// what tells the operator what the passkey signs; it stays at the top of the screen, above where a
// phone's passkey sheet opens, until the ceremony ends.
function describe(a) {
  const s = x => strip(x);
  if (a.action === "decide") {
    const verb = a.decision === "deny" ? "Deny" : a.uses === 1 ? "Approve once" : "Allow" + (a.uses ? " " + a.uses + " uses" : "");
    const how = a.decision === "deny" ? "" : " for " + Math.round((a.ttl_secs || 0) / 60) + " min";
    return verb + how + ": " + s(a.method + " " + a.host + a.path) + (a.prefix ? "\u2026 (every path under it)" : "") +
      " \u00b7 " + riskLabel(a.risk) + " \u00b7 request " + s(a.request) + " \u00b7 run " + s(a.run) +
      (a.agent ? " \u00b7 agent " + s(a.agent) : "") + ((a.requested_by || []).length ? " (" + a.requested_by.map(s).join(", ") + ")" : "");
  }
  if (a.action === "say") return "Send to " + s(a.run) + ": \u201c" + s(a.text).slice(0, 80) + "\u201d";
  if (a.action === "revoke") return "Revoke " + s(a.run) + " (" + s(a.agent) + "): " + s(a.reason);
  if (a.action === "save_manifest" || a.action === "restore_manifest") {
    const verb = a.action === "restore_manifest" ? "Restore " + s(a.name) + " to " + s(a.restored_from) : "Save " + s(a.root + "/" + a.name);
    const w = a.widens ? " \u00b7 WIDENS authority: " + (a.widening || []).map(s).join("; ") : " \u00b7 does not widen authority";
    return verb + " (sha256 " + s(a.sha256).slice(0, 12) + "\u2026" + (a.previous_sha256 ? ", replacing " + s(a.previous_sha256).slice(0, 12) + "\u2026" : ", new") + ")" + w +
      " \u00b7 " + (a.changes || []).length + " change(s)";
  }
  if (a.action === "start_run") return "Start " + s(a.root + "/" + a.manifest) + " as " + s(a.principal && a.principal.id) + (a.image ? " \u00b7 image " + s(a.image) : "") + (a.task ? " with task \u201c" + s(a.task).slice(0, 60) + "\u201d" : "");
  return s(a.action);
}

// While a confirmation or a passkey ceremony is open, nothing on the page is re-rendered, so what
// the operator is looking at and tapping can't change under them.
let ceremony = false;
// When the pending cards last moved (added, removed, reordered or resized). A tap on a card's button
// just after is ignored: it may have been aimed at whatever was there before.
let layoutAt = 0;
const SETTLE_MS = 800;
const settled = () => performance.now() - layoutAt >= SETTLE_MS;

async function signed(body) {
  if (ceremony) return;
  ceremony = true;
  let begin;
  try { begin = await post("/api/action/begin", body); }
  catch (e) { toast(e.message); closeConfirm(); return; }
  const go = document.getElementById("confirm-go");
  document.getElementById("confirm-what").textContent = describe(begin.action);
  document.getElementById("confirm-state").textContent = "";
  const deny = begin.action.decision === "deny" || begin.action.action === "revoke";
  go.textContent = deny ? "Sign: " + (begin.action.action === "revoke" ? "revoke" : "deny") : "Sign with passkey";
  go.className = deny ? "deny" : "approve";
  // Not tappable at once: a second tap aimed at the card mustn't land on it.
  go.disabled = true; setTimeout(() => { go.disabled = false; }, SETTLE_MS);
  go.onclick = async () => {
    go.disabled = true;
    document.getElementById("confirm-state").textContent = "Waiting for your passkey\u2026";
    try { const j = await post("/api/action/finish", await assertWith(begin.publicKey)); toast(j.ok); }
    catch (e) { toast(e.message); }
    closeConfirm();
  };
  document.getElementById("confirm").hidden = false;
  go.focus();
}
function closeConfirm() {
  document.getElementById("confirm").hidden = true;
  document.getElementById("confirm-go").onclick = null;
  ceremony = false;
  refresh();
}
const act = (kind, body) => {
  if (!settled()) { toast("The list just changed: check the card and tap again."); return; }
  signed({ ...body, action: "decide", decision: kind });
};

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

// Pending cards are kept by request id: a card whose content hasn't changed is the same element
// from one poll to the next, so its buttons don't move or get replaced under the cursor. When the
// cards do move, `layoutAt` is set and taps are ignored for a moment.
const cards = new Map();
function pendingCard(s, p) {
  const key = JSON.stringify([p.risk, p.method, p.host, p.path, p.scope_prefix, p.reason, p.identity, p.attribution, p.zone, p.run]);
  const had = cards.get(p.id);
  if (had && had.key === key) { had.meta.textContent = p.id + " \u00b7 zone " + strip(p.zone) + " \u00b7 " + strip(p.run) + " \u00b7 " + ago(s.now, p.created_at); return had.node; }
  const c = el("div", "card req"); c.dataset.id = p.id;
  const head = el("div"); head.append(el("span", "risk " + riskClass(p.risk), riskLabel(p.risk)));
  c.append(head, el("div", "what", strip(p.method + " " + p.host + p.path) + (p.scope_prefix ? "\u2026  (every path under it)" : "")));
  c.append(el("div", "why", strip(p.reason)));
  const idOk = renderAgent(c, p.identity || {});
  c.append(renderWho(p.attribution || []));
  const meta = el("div", "meta", p.id + " \u00b7 zone " + strip(p.zone) + " \u00b7 " + strip(p.run) + " \u00b7 " + ago(s.now, p.created_at));
  c.append(meta);
  const b = el("div", "buttons");
  const once = el("button", "approve", p.scope_prefix ? "Approve prefix once (10 min)" : "Approve once (10 min)"); once.onclick = () => act("approve", { id: p.id, uses: 1, ttl_secs: 600 });
  const hour = el("button", "", p.scope_prefix ? "Allow prefix for 1 hour" : "Allow for 1 hour"); hour.onclick = () => act("approve", { id: p.id, unlimited: true, ttl_secs: 3600 });
  const deny = el("button", "deny", "Deny"); deny.onclick = () => act("deny", { id: p.id });
  if (!idOk) { once.disabled = true; hour.disabled = true; }
  if (p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible") b.append(once, deny); else b.append(once, hour, deny);
  c.append(b);
  cards.set(p.id, { key, node: c, meta });
  return c;
}

function renderPending(s) {
  const box = document.getElementById("pending");
  const live = new Set(s.pending.map(p => p.id));
  for (const id of [...cards.keys()]) if (!live.has(id)) cards.delete(id);
  const nodes = s.pending.length ? s.pending.map(p => pendingCard(s, p)) : [el("div", "empty", "Nothing is waiting for a decision.")];
  const same = nodes.length === box.children.length && nodes.every((n, i) => n === box.children[i]);
  if (same) return;
  const empty = !s.pending.length && box.children.length === 1 && box.children[0].className === "empty";
  if (empty) return;
  box.replaceChildren(...nodes);
  layoutAt = performance.now();
}

function renderRows(id, rows, f, emptyText) {
  const box = document.getElementById(id); box.replaceChildren();
  if (!rows.length) { box.append(el("div", "empty", emptyText)); return; }
  for (const r of rows) box.append(f(r));
}

// A decision on a request, from the control host (`op`) or shipped by a node (`node.audit`, its
// record as a JSON string), with a link to explain it (#173).
function egressOf(op) {
  const b = op.body || {};
  if (op.kind === "op" && b.kind === "egress") return [b, ""];
  if (op.kind === "node.audit" && typeof b.body === "string") {
    try { const n = JSON.parse(b.body); if (n && n.kind === "egress") return [n, " (node)"]; } catch (e) { /* not a decision */ }
  }
  return null;
}

function line(op) {
  const b = op.body || {};
  const eg = egressOf(op);
  if (eg) {
    const [x, where] = eg;
    const outcome = String(x.outcome || "?");
    const cls = outcome === "allow" || outcome === "spliced" ? "ok" : outcome === "pending" ? "pend" : "blocked";
    const d = el("div"); d.append(el("span", cls, outcome.toUpperCase().padEnd(9)), document.createTextNode(strip(x.method + " " + x.host + x.path + where) + " "));
    if (op.run) { const why = el("button", "link", "explain"); why.onclick = () => showExplain(op.seq); d.append(why); }
    return d;
  }
  if (op.kind === "op" && b.kind === "llm") return el("div", "", "model  #" + b.requests + " " + strip(b.model || "?") + " → " + b.status + "  in " + b.input_tokens + " / out " + b.output_tokens);
  if (op.kind === "decision") return el("div", b.decision === "approve" ? "ok" : "blocked", b.decision + " " + b.request + " by " + strip(b.by) + (b.signed ? " (passkey-signed)" : ""));
  if (op.kind === "operator.passkey_added") return el("div", "", "passkey added: " + strip(b.name) + " via " + strip(b.via));
  if (op.kind === "run.start") return el("div", "", "start  " + op.run + " zone " + strip(b.zone) + " agent " + strip(b.agent));
  if (op.kind === "operator.message") return el("div", "", "say    " + op.run + " by " + strip(b.by) + " · " + b.chars + " chars" + (b.signed ? " (passkey-signed)" : ""));
  if (op.kind === "identity.revoked") return el("div", "blocked", "revoke " + op.run + " by " + strip(b.by) + ": " + strip(b.reason) + (b.signed ? " (passkey-signed)" : ""));
  if (op.kind === "run.console_start") return el("div", "", "launch " + op.run + " " + strip(b.root + "/" + b.manifest) + " by " + strip(b.by) + " (passkey-signed)");
  if (op.kind === "op" && b.kind === "box") return el("div", "pend", "box    " + strip(b.what) + ": " + strip(b.detail));
  if (op.kind === "run.exit_cause") return el("div", "blocked", "ended  " + op.run + " (exit status " + b.code + "): " + strip(b.cause));
  if (op.kind === "run.end") return el("div", b.cause ? "blocked" : "", "end    " + op.run + " " + strip(b.status) + " · " + b.model_requests + " model calls");
  return el("div", "", op.kind);
}

// A running agent can be sent a follow-up or have its identity revoked; both are signed.
function renderRun(s, x) {
  const d = el("div", "row");
  const left = el("span"); left.append(el("span", "mono", x.id), document.createTextNode(" " + strip(x.zone + " · " + (x.revoked ? "revoked" : x.status) + " · " + ago(s.now, x.started_at))));
  d.append(left);
  // A remote session (#169): where the owner drives it, in the vendor's app.
  if (x.remote_url && x.remote_url.startsWith("https://")) {
    const a = el("a", "mono", "open session");
    a.href = x.remote_url; a.target = "_blank"; a.rel = "noopener noreferrer";
    left.append(document.createTextNode(" · "), a);
  }
  const auth = el("button", "link", "authority");
  auth.onclick = () => showAuthority(x.id);
  left.append(document.createTextNode(" · "), auth);
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
  // The zone view (#62): which hosts the egress proxy inspects and which it splices through.
  const hosts = el("div", "meta");
  const showHosts = () => {
    const [root, name] = JSON.parse(sel.value || "[]");
    const m = ms.find((x) => x.root === root && x.name === name);
    hosts.replaceChildren();
    // The image its box starts from (#171), or why it can't start.
    if (m && m.valid) hosts.append(m.image ? el("div", "", "image " + strip(m.image)) : el("div", "pend", "image refused: " + strip(m.image_error)));
    for (const h of (m && m.hosts) || []) {
      const d = el("div");
      d.append(el("span", h.mode === "spliced" ? "pend" : "ok", (h.mode === "spliced" ? "spliced" : "inspected").padEnd(10)),
        document.createTextNode(strip(h.host) + (h.mode === "spliced" ? " (every method and path; not inspected)" : " (" + strip(h.why) + ")")));
      hosts.append(d);
    }
  };
  sel.onchange = showHosts; showHosts();
  const task = el("textarea"); task.placeholder = "Task (optional; replaces the manifest's task, agents only)";
  const b = el("div", "buttons"); const go = el("button", "approve", "Start run");
  go.onclick = () => { const [root, manifest] = JSON.parse(sel.value); signed({ action: "start_run", root, manifest, task: task.value }); task.value = ""; };
  b.append(go);
  box.append(sel, hosts, task, b, el("div", "meta", "The run's principal is you (this passkey), not the host user."));
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

// ---- read-only views of authority (#173) ----
// Everything here is text: block sources hold strings an agent chose (a grant's path), so nothing
// is ever parsed as markup.
async function getJson(path) {
  const r = await fetch(path);
  const j = await r.json().catch(() => ({ error: "unreadable answer" }));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function openDetail(title) {
  const d = document.getElementById("detail");
  document.getElementById("detail-title").textContent = title;
  const body = document.getElementById("detail-body"); body.replaceChildren(el("div", "meta", "loading…"));
  d.hidden = false; d.scrollIntoView({ block: "nearest" });
  return body;
}

const kv = (k, v) => { const d = el("div", "row"); d.append(el("span", "meta", k), el("span", "mono", strip(v))); return d; };
const when = s => s ? new Date(s * 1000).toISOString().replace(".000", "") : "—";
const whenMs = ms => ms ? new Date(ms).toISOString().replace(/\.\d+Z$/, "Z") : "—";

async function showAuthority(run) {
  const body = openDetail("authority of " + run);
  try {
    const a = await getJson("/api/runs/" + encodeURIComponent(run) + "/authority");
    const out = [];
    out.push(kv("status", a.status + (a.revoked ? " · identity revoked by " + a.revoked.by + ": " + a.revoked.reason : "")));
    out.push(kv("node", a.node + (a.feed ? " · its feed at epoch " + a.feed.epoch : "")));
    out.push(kv("policy", (a.policy.version || "no org policy") + (a.policy.version ? (a.policy.current ? " (current)" : " (not the installed " + (a.policy.installed || "none") + ")") : "")));
    if (a.deadline) out.push(kv("authority until", whenMs(a.deadline.until_ms) + (a.deadline.stopped ? " · box stopped" : "")));
    if (a.holdings) {
      out.push(kv("secrets on its node", a.holdings.secrets.length ? a.holdings.secrets.join(", ") + " (names only)" : "none"));
      const s = a.holdings.slice;
      out.push(kv("budget slice", s ? s.requests + " requests, " + s.output_tokens + " output tokens" + (s.input_tokens != null ? ", " + s.input_tokens + " input tokens" : "") : "none"));
    }
    const t = a.token || {};
    if (!t.held) { out.push(el("div", "note", "No token: " + strip(t.why))); body.replaceChildren(...out); return; }
    out.push(kv("token", "box " + t.box_path + " · epoch " + t.epoch + " · zone " + t.zone + " · minted by " + t.issued_by + (t.loads === true ? " · loads" : " · does NOT load: " + (t.loads.error || ""))));
    for (const b of t.blocks) {
      const h = el("div", "row");
      h.append(el("span", b.revoked ? "blocked" : "ok", "block " + b.index + " · " + b.kind + (b.revoked ? " · REVOKED" : "")),
        el("span", "meta", "revocation " + b.revocation_fingerprint + (b.signed_by ? " · signed by " + b.signed_by : "")));
      out.push(h, el("pre", "src", b.source));
    }
    if (t.grants.length) {
      out.push(el("div", "meta", "grants"));
      for (const g of t.grants) {
        out.push(kv(g.id, g.method + " " + g.host + g.path + " · " + (g.uses == null ? "unlimited uses" : g.uses + " uses (counted on the node)") +
          " · until " + when(g.expires_at) + " · approved by " + (g.approved_by || "?") + " at " + when(g.approved_at) +
          (g.revoked ? " · revoked" : "") + (g.reached_node === false ? " · not yet on its node" : "")));
      }
    }
    if (t.zone_cedar) { out.push(el("div", "meta", "zone policy (Cedar, generated from the manifest)"), el("pre", "src", t.zone_cedar)); }
    body.replaceChildren(...out);
  } catch (e) { body.replaceChildren(el("div", "blocked", strip(e.message))); }
}

async function showExplain(seq) {
  const body = openDetail("decision #" + seq);
  try {
    const x = await getJson("/api/explain/" + encodeURIComponent(seq));
    const r = x.recorded, n = x.against_token_now;
    const out = [
      kv("request", r.method + " " + r.host + r.path + " (" + (r.risk || "?") + ")"),
      kv("recorded", String(r.outcome) + " on " + r.decided_on + " at " + when(r.at) + ": " + strip(r.detail)),
      kv("run", x.run + " · policy " + (x.policy || "none")),
    ];
    if (n.available) {
      out.push(kv("token now", n.decision), el("pre", "src", n.why), kv("zone says", n.zone_says));
      out.push(el("div", "note", "Against the run's token as its node's feed holds it now: grants and policy may have changed since it was decided."));
    } else out.push(el("div", "note", "Can't evaluate it now: " + strip(n.why)));
    body.replaceChildren(...out);
  } catch (e) { body.replaceChildren(el("div", "blocked", strip(e.message))); }
}

let policyShown = 0;
async function renderPolicy() {
  // The policy changes rarely: fetched at most every 30 s.
  if (performance.now() - policyShown < 30000 && policyShown) return;
  policyShown = performance.now();
  const box = document.getElementById("policy");
  try {
    const p = await getJson("/api/policy");
    const out = [];
    if (!p.installed) out.push(el("div", "note", "No org policy applied: tokens carry their zone's policy only (wicket policy apply)."));
    else {
      out.push(kv("applied", p.installed + (p.current.matches_applied === false ? " · org.cedar was changed by hand: every mint is refused until it is applied" : "")));
      out.push(el("pre", "src", p.current.cedar || ""));
    }
    for (const v of p.versions) {
      const a = v.applied.length ? v.applied[v.applied.length - 1] : null;
      out.push(kv("version " + v.version + (v.current ? " (current)" : ""), a ? "applied " + when(a.at) + " by " + a.by : "kept"));
    }
    for (const r of p.runs) out.push(kv(r.run, "zone " + r.zone + " · policy " + (r.policy || "none") + " · " + r.status));
    box.replaceChildren(...out);
  } catch (e) { box.replaceChildren(el("div", "blocked", strip(e.message))); }
}

// ---- manifests (#172): view, check as you type, save and restore as signed actions ----
async function fetchJson(path) {
  const r = await fetch(path);
  const j = await r.json().catch(() => ({ error: "unreadable answer" }));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const kvRow = (k, v, cls) => { const d = el("div", "row"); d.append(el("span", "meta", k), el("span", cls || "mono", strip(v))); return d; };

function renderManifests(s) {
  const box = document.getElementById("manifests");
  const ms = s.manifests || [];
  const key = JSON.stringify(ms.map(m => [m.root, m.name, m.valid]));
  if (box.dataset.key === key) return;
  box.dataset.key = key;
  box.replaceChildren();
  for (const m of ms) {
    const d = el("div", "row");
    d.append(el("span", m.valid ? "mono" : "blocked mono", strip(m.root + "/" + m.name) + (m.valid ? "" : " · invalid")));
    const open = el("button", "link", m.root === "manifests" ? "view / edit" : "view");
    open.onclick = () => openManifest(m.root, m.name);
    d.append(open); box.append(d);
  }
  const add = el("button", "link", "new manifest");
  add.onclick = () => openManifest("manifests", null);
  box.append(add);
}

function grantsView(g) {
  const out = [];
  out.push(kvRow("task", g.task || "(none)"));
  if (g.agent) out.push(kvRow("agent", g.agent.name + " · " + g.agent.kind + " · max_turns " + (g.agent.max_turns ?? "default") + " · children " + g.agent.max_children + " · idle " + g.agent.idle_timeout + (g.agent.remote ? " · remote session " + g.agent.remote : "")));
  if (g.program) out.push(kvRow("program", g.program.name + ": " + g.program.command.join(" ")));
  out.push(kvRow("image", g.image.Ok || ("refused: " + g.image.Err), g.image.Ok ? "mono" : "blocked"));
  out.push(kvRow("isolation", g.isolation + " · unlisted hosts " + JSON.stringify(g.unlisted_hosts)));
  for (const r of g.reach) out.push(kvRow("reach", r.host + " " + (r.methods || []).join(",") + " " + (r.paths || ["/**"]).join(" ") + (r.allow_dangerous ? " · DANGEROUS allowed" : "")));
  for (const h of g.hosts) out.push(kvRow(h.mode, h.host + (h.mode === "spliced" ? " (every method and path; not inspected)" : " (" + h.why + ")"), h.mode === "spliced" ? "pend" : "mono"));
  for (const f of g.forbid) out.push(kvRow("forbid", f.host + " " + (f.paths || ["everything"]).join(" "), "blocked"));
  for (const i of g.inject) out.push(kvRow("inject", "secret " + i.secret + " → " + i.host + " " + i.header + (i.secret_set ? "" : " · NOT SET in the vault") + (i.bound_to_host ? "" : " · not bound to this host") + (i.optional ? " · optional" : ""), i.secret_set && i.bound_to_host ? "mono" : "pend"));
  if (g.llm) out.push(kvRow("model", g.llm.provider + " via " + g.llm.upstream + " · secret " + g.llm.secret + (g.llm.secret_set ? "" : " (NOT SET)") + " · " + g.llm.max_requests + " requests, " + g.llm.max_output_tokens + " output tokens" + (g.llm.max_input_tokens != null ? ", " + g.llm.max_input_tokens + " input tokens" : "")));
  for (const v of g.volumes) out.push(kvRow("volume", JSON.stringify(v)));
  out.push(kvRow("limits", JSON.stringify(g.limits)));
  const o = g.org_policy;
  if (o) out.push(kvRow("org policy " + o.version, o.error ? o.error : o.mints ? "allows this zone (groups: " + (o.groups || []).join(", ") + ")" : "REFUSES it: " + o.refused, o.mints ? "ok" : "blocked"));
  return out;
}

function fieldsView(fields) {
  const pre = el("pre", "src", fields.map(f => f.path + " = " + JSON.stringify(f.value) + (f.default ? "   (default)" : "")).join("\n"));
  return pre;
}

async function openManifest(root, name) {
  const card = document.getElementById("mfedit"), body = document.getElementById("mfedit-body");
  document.getElementById("mfedit-title").textContent = name ? root + "/" + name : "new manifest";
  body.replaceChildren(el("div", "meta", "loading…"));
  card.hidden = false; card.scrollIntoView({ block: "nearest" });
  let v = { root, name, yaml: "task: \nagent: { name: my-agent }\nzone:\n  name: my-zone\n  llm: {}\n", writable: true, history: [], valid: false, fields: [] };
  if (name) {
    try { v = await fetchJson("/api/manifests/" + encodeURIComponent(root) + "/" + encodeURIComponent(name)); }
    catch (e) { body.replaceChildren(el("div", "blocked", strip(e.message))); return; }
  }
  const out = [];
  const nameIn = el("input", "text"); nameIn.value = name || ""; nameIn.placeholder = "name.yaml"; nameIn.disabled = !!name;
  if (!name) out.push(nameIn);
  out.push(el("div", v.valid ? "ok" : "blocked", v.valid ? "valid" : "invalid: " + strip(v.error || "")));
  const grantsBox = el("div"); if (v.grants) grantsBox.append(...grantsView(v.grants));
  const fieldsBox = el("div"); fieldsBox.append(el("div", "meta", "every field, its effective value"), fieldsView(v.fields || []));
  const yaml = el("textarea", "yaml"); yaml.value = v.yaml; yaml.readOnly = !v.writable; yaml.spellcheck = false;
  const status = el("div", "meta");
  const diffBox = el("div");
  out.push(grantsBox, fieldsBox, el("div", "meta", v.writable ? "YAML (edit, then save: your passkey signs the change)" : "YAML (examples are read-only)"), yaml, status, diffBox);
  if (v.writable) {
    let timer = null, lastOk = false;
    const save = el("button", "approve", "Save…"); save.disabled = true;
    const check = async () => {
      const n = nameIn.value.trim();
      if (!n) { status.textContent = "name it first (name.yaml)"; save.disabled = true; return; }
      try {
        const c = await post("/api/manifests/check", { name: n, yaml: yaml.value });
        lastOk = c.valid;
        status.className = c.valid ? "ok" : "blocked";
        status.textContent = c.valid ? "valid" : "invalid: " + strip(c.error);
        diffBox.replaceChildren();
        if (c.diff) {
          if (c.diff.widens) { diffBox.append(el("div", "blocked", "WIDENS authority:")); for (const w of c.diff.widening) diffBox.append(el("div", "blocked", "  " + w)); }
          else diffBox.append(el("div", "ok", "does not widen authority"));
          if (c.diff.changes.length) diffBox.append(el("pre", "src", c.diff.changes.join("\n")));
          if (c.saved_sha256 && c.saved_sha256 === c.sha256) { diffBox.append(el("div", "meta", "no change")); lastOk = false; }
        }
        if (c.grants) grantsBox.replaceChildren(...grantsView(c.grants));
        if (c.fields) fieldsBox.replaceChildren(el("div", "meta", "every field, its effective value"), fieldsView(c.fields));
      } catch (e) { status.className = "blocked"; status.textContent = strip(e.message); lastOk = false; }
      save.disabled = !lastOk;
    };
    yaml.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(check, 400); });
    nameIn.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(check, 400); });
    save.onclick = () => signed({ action: "save_manifest", name: nameIn.value.trim(), yaml: yaml.value });
    const b = el("div", "buttons"); b.append(save); out.push(b);
    for (const h of v.history || []) {
      const r = el("div", "row");
      r.append(el("span", "mono", "version saved before " + new Date(h.saved_before * 1000).toISOString().replace(".000", "") + " · " + h.sha256_prefix));
      const rb = el("button", "link", "restore…"); rb.onclick = () => signed({ action: "restore_manifest", name, version: h.version });
      r.append(rb); out.push(r);
    }
    if (name) check();
  }
  body.replaceChildren(...out);
}

async function refresh() {
  if (ceremony) return;
  try {
    const r = await fetch("/api/state");
    if (!r.ok) { boot(); return; }
    const s = await r.json();
    if (ceremony) return; // opened while this poll was in flight
    document.getElementById("tenant").textContent = "tenant " + s.tenant;
    renderPending(s);
    renderRows("runs", s.runs, x => renderRun(s, x), "No runs yet.");
    renderStart(s);
    renderManifests(s);
    renderRows("decided", s.decided, x => { const d = el("div", "row"); d.append(el("span", "mono", strip(x.id + " " + x.method + " " + x.host + x.path)), el("span", x.status === "granted" ? "ok" : "blocked", x.status)); return d; }, "No decisions yet.");
    renderRows("audit", s.audit.slice().reverse(), line, "No activity yet.");
    renderOperator(s);
    renderPolicy();
  } catch (e) { /* keep polling */ }
}
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("runform").addEventListener("submit", submitRunForm);
  document.getElementById("runform-cancel").addEventListener("click", closeRunForm);
  document.getElementById("confirm-cancel").addEventListener("click", closeConfirm);
  document.getElementById("mfedit-close").addEventListener("click", () => { document.getElementById("mfedit").hidden = true; });
  document.getElementById("detail-close").addEventListener("click", () => { document.getElementById("detail").hidden = true; });
  boot();
  setInterval(() => { if (!document.getElementById("console").hidden) refresh(); }, 2000);
});

"use strict";
// The console's script, served as a static file under a strict CSP (no inline script or style, no
// eval). Every string from the ledger is untrusted (agents influence paths and reasons): set as textContent only.
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = String(text); return e; };
// The same set as wicket_core::text::is_unsafe: C0, DEL, C1, bidi, zero-width, line separators (#128).
const strip = s => String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, " ");
const ago = (now, t) => { const s = Math.max(0, now - t); return s < 90 ? s + "s ago" : s < 5400 ? Math.round(s / 60) + "m ago" : Math.round(s / 3600) + "h ago"; };
const riskClass = r => ({ R0Read: "r0", R1ReadScoped: "r1", R2WriteReversible: "r2", R3ExternalOrIrreversible: "r3", R4ExecOrPrivilege: "r4" })[r] || "r4";
// What a risk class means to whoever decides, with its code (docs/reference/risk-classes.md, #574).
const riskLabel = r => ({ R0Read: "R0 \u00b7 read", R1ReadScoped: "R1 \u00b7 read (scoped)", R2WriteReversible: "R2 \u00b7 changes data", R3ExternalOrIrreversible: "R3 \u00b7 visible to others, or can't be undone", R4ExecOrPrivilege: "R4 \u00b7 push, deploy or privilege" })[r] || r;
// A lifetime as the card and the sheet both say it: whole hours as hours, else minutes.
const span = secs => { const s = Math.round(secs || 0); return s >= 3600 && s % 3600 === 0 ? (s / 3600) + (s === 3600 ? " hour" : " hours") : Math.round(s / 60) + " min"; };

// What happened, at the foot of the page (#574): long enough to read (3 to 8 s by length), and an
// error in its own style, kept until tapped.
let toastTimer;
function toast(t, error) {
  const m = document.getElementById("msg");
  m.textContent = (t === undefined || t === null || t === "") ? "Done." : String(t);
  m.className = error ? "error" : "";
  m.hidden = false;
  m.onclick = () => { m.hidden = true; };
  clearTimeout(toastTimer);
  if (!error) toastTimer = setTimeout(() => { m.hidden = true; }, Math.min(8000, Math.max(3000, 40 * m.textContent.length)));
}
// An error, said plainly: a passkey sheet the operator closed is no failure of wicket's.
function toastError(e, what) {
  const name = e && e.name, msg = (e && e.message) || String(e);
  if (name === "NotAllowedError" || name === "AbortError") return toast("Passkey cancelled. Nothing was signed.", true);
  toast((what ? what + ": " : "") + msg, true);
}

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
  } catch (e) { toastError(e, "Passkey"); }
}
async function signIn() {
  try { const { publicKey } = await post("/api/login/begin"); const j = await post("/api/login/finish", await assertWith(publicKey)); toast(j.ok); boot(); }
  catch (e) { toastError(e, "Sign-in"); }
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
    // The terms are the effect's (what the passkey signs and the grant is made with), not the
    // page's ask: a git push's grant is a window, unlimited uses for 5 minutes (#26, #574).
    const t = (a.effect && a.effect.terms) || { uses: a.uses, ttl_secs: a.ttl_secs };
    const verb = a.decision === "deny" ? "Deny" : t.uses === 1 ? "Approve once" : "Approve" + (t.uses ? " " + t.uses + " uses" : " any number of uses");
    const how = a.decision === "deny" ? "" : " for " + span(t.ttl_secs);
    const what = a.path_prefix ? s(a.method + " " + a.host + a.path_prefix) : s(a.method + " " + a.host + a.path);
    // In lines (#574, item 1): the decision and its target first, as the passkey signs them; then
    // the risk, who it is for, and the ids last and apart.
    const agent = a.agent ? String(a.agent).split("/a/").pop() : "";
    const lines = [verb + how + ": " + what + (a.prefix ? "\u2026 (every path under it)" : ""),
      "Risk: " + riskLabel(a.risk) + (a.scope === "zone" ? " \u00b7 for any run in zone " + s(a.zone) : "")];
    if (agent || (a.requested_by || []).length) {
      lines.push((agent ? "For " + s(agent) : "For run " + s(a.run)) + ((a.requested_by || []).length ? " \u00b7 asked by " + a.requested_by.map(s).join(", ") : ""));
    }
    lines.push("Request " + s(a.request) + " \u00b7 run " + s(a.run) + (a.effect_sha256 ? " \u00b7 effect " + s(a.effect_sha256).slice(0, 16) : ""));
    return lines.join("\n");
  }
  if (a.action === "revoke") return "Revoke " + s(a.run) + " (" + s(a.agent) + "): " + s(a.reason);
  if (a.action === "save_manifest" || a.action === "restore_manifest") {
    const verb = a.action === "restore_manifest" ? "Restore " + s(a.name) + " to " + s(a.restored_from) : "Save " + s(a.root + "/" + a.name);
    const w = a.widens ? " \u00b7 WIDENS authority: " + (a.widening || []).map(s).join("; ") : " \u00b7 does not widen authority";
    return verb + " (sha256 " + s(a.sha256).slice(0, 12) + "\u2026" + (a.previous_sha256 ? ", replacing " + s(a.previous_sha256).slice(0, 12) + "\u2026" : ", new") + ")" + w +
      " \u00b7 " + (a.changes || []).length + " change(s)";
  }
  if (a.action === "push_subscribe") return (a.replaces ? "Re-register " : "Send notifications to ") + s(a.label) + " (" + s(a.service) + ", device " + s(a.device) + ")" +
    (a.details ? " \u00b7 showing the agent and what it asks for" : " \u00b7 showing only how many requests wait");
  if (a.action === "push_details") return "Show the agent and what it asks for in notifications on " + s(a.label) + " (" + s(a.service) + ", device " + s(a.device) + ")";
  if (a.action === "set_secret") return (a.replaces ? "Replace the value of secret " : "Store new secret ") + s(a.name) + " with the value you typed (not shown)" +
    " \u00b7 " + ((a.hosts || []).length ? "sent only to " + a.hosts.map(s).join(", ") : "bound to no host: sent nowhere") +
    ((a.zones || []).length ? " \u00b7 used by zone " + a.zones.map(s).join(", ") : "");
  if (a.action === "secret_hosts") return "Send secret " + s(a.name) + " only to " + (a.hosts || []).map(s).join(", ") +
    " (was: " + ((a.previous_hosts || []).length ? a.previous_hosts.map(s).join(", ") : "no host") + ")";
  if (a.action === "delete_secret") return "Delete " + (a.kind === "reference" ? "the reference " : "secret ") + s(a.name) +
    ((a.zones || []).length ? " \u00b7 zones using it: " + a.zones.map(s).join(", ") : " \u00b7 no zone uses it") +
    ((a.runs || []).length ? " \u00b7 running runs using it: " + a.runs.map(s).join(", ") : "");
  if (a.action === "capacity_grant" || a.action === "capacity_renew") {
    const t = a.terms || {};
    const what = (t.nodes || 0) + " node(s) at once of " + (t.plans || []).map(s).join(", ") + " in " + (t.regions || []).map(s).join(", ") +
      ", at most " + s(t.hourly_usd) + "/h and " + s(t.daily_usd) + " a day";
    const hours = Math.round((a.ttl_secs || 0) / 360) / 10;
    return (a.action === "capacity_grant" ? "Grant " + s(a.principal) + " " + what + ", for " + hours + " h"
      : "Renew capacity grant " + s(a.grant) + " (" + s(a.principal) + ": " + what + ") for " + hours + " h from now");
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

// `after`, if given, runs once the confirmation closes (signed, refused or cancelled). `extra`, if
// given, adds fields to finish's body only (a secret's value: never sent with begin, never signed).
let afterConfirm = null;
async function signed(body, after, extra) {
  if (ceremony) return;
  ceremony = true;
  afterConfirm = after || null;
  let begin;
  try { begin = await post("/api/action/begin", body); }
  catch (e) { toastError(e); closeConfirm(); return; }
  const go = document.getElementById("confirm-go");
  document.getElementById("confirm-what").textContent = describe(begin.action);
  renderBlast(document.getElementById("confirm-blast"), begin.action.blast);
  renderUpdate(document.getElementById("confirm-update"), begin.action.update);
  document.getElementById("confirm-state").textContent = "";
  const deny = begin.action.decision === "deny" || begin.action.action === "revoke" || begin.action.action === "delete_secret";
  go.textContent = deny ? "Sign: " + ({ revoke: "revoke", delete_secret: "delete" }[begin.action.action] || "deny") : "Sign with passkey";
  go.className = deny ? "deny" : "approve";
  // Not tappable at once: a second tap aimed at the card mustn't land on it.
  go.disabled = true; setTimeout(() => { go.disabled = false; }, SETTLE_MS);
  go.onclick = async () => {
    go.disabled = true;
    document.getElementById("confirm-state").textContent = "Waiting for your passkey\u2026";
    try { const j = await post("/api/action/finish", { ...(await assertWith(begin.publicKey)), ...(extra ? extra() : {}) }); toast(j.ok); }
    catch (e) { toastError(e); }
    closeConfirm();
  };
  document.getElementById("confirm").hidden = false;
  go.focus();
}
// #369: what else an approval that widens would allow, shown before the passkey is asked for.
function renderBlast(box, b) {
  box.replaceChildren();
  box.hidden = !b;
  if (!b) return;
  const list = (title, xs) => {
    if (!xs || !xs.length) return;
    box.append(el("div", "meta", title));
    const ul = el("ul");
    for (const x of xs) ul.append(el("li", "", strip(x)));
    box.append(ul);
  };
  list("This approval is wider than the one request:", b.widens);
  list("It would also allow, for example:", b.examples);
  box.append(el("div", "meta", "It would have covered " + b.covered + " of this run\u2019s last " + b.recent + " egress requests."));
  list("The zone already reaches this host by:", b.zone_rules);
}
// #465: approving an agent's update request installs its build. What, and where, before signing.
function renderUpdate(box, u) {
  box.replaceChildren();
  box.hidden = !u;
  if (!u) return;
  if (!u.applies) {
    box.append(el("div", "meta", "Approving accepts the build with sha256 " + strip(u.sha256).slice(0, 16) +
      "… once, but doesn’t install it: " + strip(u.why_not || "")));
    return;
  }
  box.append(el("div", "meta", "Approving installs this build now, blue/green with its health gate; a failed gate rolls back."));
  const ul = el("ul");
  const sha = strip(u.sha256).slice(0, 16) + "…";
  if (u.node) {
    ul.append(el("li", "", "artifact: the file with sha256 " + sha + " in the run’s /workspace/out on node " + strip(u.node) +
      ", fetched from there when you approve (not installed if it isn’t there)"));
  } else {
    const mib = (u.size / 1048576).toFixed(1);
    ul.append(el("li", "", "artifact: " + strip(u.artifact) + " (" + mib + " MiB) from the run’s /workspace/out, sha256 " + sha));
  }
  ul.append(el("li", "", "commit: " + (u.commit_said ? strip(u.commit_said) + " (as the agent says; not checked)" : "the agent didn’t say")));
  ul.append(el("li", "", "reaches: the control host" + ((u.nodes || []).length ? ", then nodes " + u.nodes.map(strip).join(", ") + " (the first is the canary)" : ", and no nodes")));
  box.append(ul);
}
function closeConfirm() {
  document.getElementById("confirm").hidden = true;
  document.getElementById("confirm-go").onclick = null;
  ceremony = false;
  const after = afterConfirm; afterConfirm = null;
  if (after) after();
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
  const once = el("button", "approve", p.scope_prefix ? "Approve prefix once (expires in 10 min)" : "Approve once (expires in 10 min)"); once.onclick = () => act("approve", { id: p.id, uses: 1, ttl_secs: 600 });
  const hour = el("button", "", p.scope_prefix ? "Approve prefix for 1 hour (any number of uses)" : "Approve for 1 hour (any number of uses)"); hour.onclick = () => act("approve", { id: p.id, unlimited: true, ttl_secs: 3600 });
  const deny = el("button", "deny", "Deny"); deny.onclick = () => act("deny", { id: p.id });
  if (!idOk) { once.disabled = true; hour.disabled = true; }
  if (p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible") {
    b.append(once, deny);
    c.append(el("div", "meta", "R3 and R4 are approved one use at a time."));
  } else b.append(once, hour, deny);
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
  if (openId) for (const [k, c] of cards) c.node.className = "card req" + (k === openId ? " opened" : "");
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
  // operator.message is from before `wicket say` was removed (#198); prompts are session.prompt.
  if (op.kind === "operator.message" || op.kind === "session.prompt") return el("div", "", "prompt " + op.run + " by " + strip(b.by) + " · " + b.chars + " chars" + (b.via ? " via " + strip(b.via) : "") + (b.signed ? " (passkey-signed)" : ""));
  if (op.kind === "identity.revoked") return el("div", "blocked", "revoke " + op.run + " by " + strip(b.by) + ": " + strip(b.reason) + (b.signed ? " (passkey-signed)" : ""));
  if (op.kind === "run.console_start") return el("div", "", "launch " + op.run + " " + strip(b.root + "/" + b.manifest) + " by " + strip(b.by) + " (passkey-signed)");
  if (op.kind === "op" && b.kind === "box") return el("div", "pend", "box    " + strip(b.what) + ": " + strip(b.detail));
  if (op.kind === "run.exit_cause") return el("div", "blocked", "ended  " + op.run + " (exit status " + b.code + "): " + strip(b.cause));
  if (op.kind === "run.end") return el("div", b.cause ? "blocked" : "", "end    " + op.run + " " + strip(b.status) + " · " + b.model_requests + " model calls");
  return el("div", "", op.kind);
}

// A node's latest health report (#377): disk, memory, what went wrong, and what is alerted.
function healthRow(n) {
  const d = el("div", "row");
  d.append(el("span", "mono", strip(n.node)));
  d.append(el("span", (n.alerts || []).length ? "blocked" : "", strip(n.summary) + " · reported " + whenMs(n.received_ms)));
  for (const a of n.alerts || []) d.append(el("div", "blocked", "! " + strip(a)));
  return d;
}

// A node from `wicket node create` (#294): past its lease it is released by the reconciler, unless
// a run still holds it, which is a warning until renewals exist (#56).
function placedRow(p) {
  const d = el("div", "row");
  d.append(el("span", "mono", strip(p.name + " " + p.id)));
  if (!p.past_lease) d.append(el("span", "", "lease until " + when(p.lease_until)));
  else if (p.held_by) d.append(el("span", "blocked", "PAST ITS LEASE (" + when(p.lease_until) + "): still held by run " + strip(p.held_by) + ", billing until released (wicket node release " + strip(p.id) + ")"));
  else d.append(el("span", "pend", "past its lease (" + when(p.lease_until) + "): released at the reconciler's next pass"));
  return d;
}

// Standing capacity grants (#256): a principal's `wicket node create` within one is approved at once
// and audited against it; beyond every one, it waits here as a request. Issuing and renewing a grant
// widen what may be spent, so each is signed with the passkey; revoking one only narrows, so it needs
// only the session.
function capacityRow(g) {
  const t = g.terms || {}, u = g.used || {}, left = g.left || {};
  const d = el("div", "row cap");
  const head = el("div");
  head.append(el("span", "mono", strip(g.id) + " "), el("span", "", strip(g.principal)));
  const what = el("div", "meta", (t.plans || []).map(strip).join(", ") + " in " + (t.regions || []).map(strip).join(", ") +
    " · " + t.nodes + " node(s) at once, " + strip(t.hourly_usd) + "/h, " + strip(t.daily_usd) + " a day");
  const use = el("div", "meta", "used " + u.nodes + " node(s), " + strip(u.hourly_usd) + "/h, " + strip(u.daily_usd) + " today · left " +
    left.nodes + " node(s), " + strip(left.hourly_usd) + "/h, " + strip(left.daily_usd) + " · until " + when(g.expires_at) + " · by " + strip(g.decided_by));
  const b = el("div", "buttons");
  const renew = el("button", "approve", "Renew");
  renew.onclick = () => signed({ action: "capacity_renew", id: g.id, ttl_secs: capacityTtl() });
  const revoke = el("button", "deny", "Revoke");
  revoke.onclick = async () => { try { toast((await post("/api/capacity/revoke", { id: g.id })).ok); } catch (e) { toastError(e); } refresh(); };
  b.append(renew, revoke);
  d.append(head, what, use, b);
  return d;
}
// The form's inputs, by name; built once, so what the operator types survives the poll.
const capInputs = {};
// The lifetime the form asks for (hours, at most 24): also what Renew renews for.
function capacityTtl() {
  const h = Number((capInputs.hours && capInputs.hours.value) || 8);
  return Math.round(Math.min(24, Math.max(0.1, h)) * 3600);
}
function renderCapacityForm() {
  const box = document.getElementById("capacity-form");
  if (!box || box.dataset.built) return;
  box.dataset.built = "1";
  const field = (name, label, placeholder, type) => {
    const l = el("label", "field"); const i = el("input"); i.placeholder = placeholder; if (type) i.type = type;
    capInputs[name] = i; l.append(el("span", "meta", label), i); return l;
  };
  const go = el("button", "approve", "Grant (sign with passkey)");
  go.onclick = () => {
    const v = k => capInputs[k].value;
    signed({ action: "capacity_grant", principal: v("principal"), plans: v("plans"), regions: v("regions"),
      max_hourly_usd: v("hourly"), max_daily_usd: v("daily"), nodes: Number(v("nodes") || 0), ttl_secs: capacityTtl() });
  };
  const b = el("div", "buttons"); b.append(go);
  box.append(el("div", "note", "Issue a capacity grant: what a principal may lease with `wicket node create` without asking each time."),
    field("principal", "To", "unix/alex, passkey/laptop or spiffe://…"),
    field("plans", "Plans", "vc2-1c-2gb, vc2-2c-4gb"), field("regions", "Regions", "lhr"),
    field("hourly", "Most per hour, all its nodes ($)", "0.05"), field("daily", "Most a day ($)", "1.00"),
    field("nodes", "Nodes at once", "2", "number"), field("hours", "Hours (at most 24)", "8", "number"), b);
  capInputs.hours.value = "8";
}

// A running agent can have its identity revoked, signed. An ACP agent's session opens on its own
// page, where prompts are sent (#198).
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
  // An ACP run's live session (#327): its own page, opened with a passkey there.
  if (x.acp && x.status === "running" && !x.revoked) {
    const a = el("a", "mono session", "session");
    a.href = "/session?run=" + encodeURIComponent(x.id);
    left.append(document.createTextNode(" · "), a);
  }
  const auth = el("button", "link", "authority");
  auth.onclick = () => showAuthority(x.id);
  left.append(document.createTextNode(" · "), auth);
  if (x.status === "running" && x.has_identity && !x.revoked) {
    const acts = el("span", "acts");
    const rev = el("button", "deny", "Revoke…");
    rev.onclick = () => openRunForm("revoke", x.id);
    acts.append(rev); d.append(acts);
  }
  return d;
}

// The revoke form: an in-page form (no browser dialogs), kept outside the runs list
// so the 2-second refresh doesn't wipe what the operator is typing.
function openRunForm(kind, run) {
  const f = document.getElementById("runform"), text = document.getElementById("runform-text");
  f.dataset.kind = kind; f.dataset.run = run;
  f.className = "card " + kind;
  document.getElementById("runform-title").textContent =
    "Revoke " + run + "'s identity: its box is stopped and its requests can't be approved. Reason:";
  const go = document.getElementById("runform-go");
  go.textContent = "Revoke";
  go.className = "deny";
  text.value = "revoked by the operator";
  f.hidden = false; text.focus();
}
function closeRunForm() { const f = document.getElementById("runform"); f.hidden = true; document.getElementById("runform-text").value = ""; }
function submitRunForm(ev) {
  ev.preventDefault();
  const f = document.getElementById("runform"), text = document.getElementById("runform-text").value;
  signed({ action: "revoke", run: f.dataset.run, reason: text });
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

// ---- notifications (Web Push) ----
// The service worker (/sw.js) shows what the server pushes; a tap on a notification opens the console
// at "#pending/<id>" or, if it is open, tells it which request to show. Permission is asked only from
// the button's click (iOS home-screen apps allow nothing else). Registering a device and showing the
// request on it widen what it receives, so each is signed with the passkey (a stolen session cookie
// can't add a receiver); removing a device or hiding the request need only the session. Each
// device's notifications show only how many requests are waiting unless it opts in to the request
// itself (lock screens show them). If the browser replaces this device's subscription (the service
// worker's pushsubscriptionchange), the page offers a signed re-registration the next time it is open.
const pushSupported = () => typeof navigator !== "undefined" && "serviceWorker" in navigator &&
  typeof window !== "undefined" && "PushManager" in window && "Notification" in window;
function deviceLabel() {
  const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "device";
  const br = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "";
  return br ? os + " · " + br : os;
}
async function pushInfo() {
  const r = await fetch("/api/push");
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}
// This browser's current subscription, if it has one.
async function currentSub() {
  if (!pushSupported()) return null;
  const reg = await navigator.serviceWorker.getRegistration("/");
  return reg ? reg.pushManager.getSubscription() : null;
}
async function subId(sub) {
  if (!sub || !crypto.subtle) return "";
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sub.endpoint)));
  return Array.from(h.slice(0, 8), b => b.toString(16).padStart(2, "0")).join("");
}
async function enablePush() {
  // First, while the click still counts as the user's gesture.
  const perm = await Notification.requestPermission();
  if (perm !== "granted") { toast(perm === "denied" ? "Notifications are blocked for this site in the browser's settings." : "Notifications not allowed."); return; }
  try {
    const reg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    await navigator.serviceWorker.ready;
    const info = await pushInfo();
    let sub = await reg.pushManager.getSubscription();
    const key = sub && sub.options && sub.options.applicationServerKey ? b2a(sub.options.applicationServerKey) : null;
    if (sub && key && key !== info.public_key) { await sub.unsubscribe(); sub = null; }
    if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: a2b(info.public_key) });
    registerSub(sub);
  } catch (e) { toastError(e, "Notifications"); renderPush(); }
}
// Registers this browser's subscription with the server: a signed action.
function registerSub(sub) {
  const j = sub.toJSON();
  signed({ action: "push_subscribe", endpoint: j.endpoint, p256dh: j.keys.p256dh, auth: j.keys.auth, label: deviceLabel(), details: false }, renderPush);
}
async function removeDevice(id, mine) {
  try {
    await post("/api/push/remove", { id });
    if (mine) { const sub = await currentSub(); if (sub) await sub.unsubscribe(); }
    toast("Device removed");
  } catch (e) { toastError(e, "Notifications"); }
  renderPush();
}
async function setDetails(id, details) {
  // Showing more is signed; showing less needs only the session.
  if (details) { signed({ action: "push_details", id, details: true }, renderPush); return; }
  try { toast((await post("/api/push/details", { id, details: false })).ok); } catch (e) { toastError(e, "Notifications"); }
  renderPush();
}
// Renders can overlap (a toggle, a worker's message): only the latest one writes the box.
let pushGen = 0;
async function renderPush() {
  const box = document.getElementById("push");
  if (!box) return;
  const gen = ++pushGen;
  let info;
  try { info = await pushInfo(); } catch (e) { if (gen === pushGen) box.replaceChildren(el("div", "note", "Notifications: " + e.message)); return; }
  const sub = await currentSub().catch(() => null);
  const mine = await subId(sub);
  if (gen !== pushGen) return;
  box.replaceChildren();
  const b = el("div", "buttons");
  if (!pushSupported()) {
    box.append(el("div", "note", "This browser can't receive notifications here. On an iPhone or iPad, add the console to the home screen (Share → Add to Home Screen) and open it from there."));
  } else if (sub && mine && !info.devices.some(d => d.id === mine)) {
    // The browser holds a subscription the console doesn't know: it replaced the old one
    // (pushsubscriptionchange), or this device was removed elsewhere. Registering it is signed.
    box.append(el("div", "note", "This device's notification subscription changed, so the console can't reach it. Sign to register it again."));
    const go = el("button", "approve", "Re-register this device"); go.onclick = () => registerSub(sub); b.append(go); box.append(b);
  } else if (!info.devices.some(d => d.id === mine)) {
    const go = el("button", "approve", "Enable notifications"); go.onclick = enablePush; b.append(go); box.append(b);
  }
  for (const d of info.devices) {
    const row = el("div", "row push-dev");
    row.append(el("span", "", strip(d.label) + (d.id === mine ? " (this device)" : "")),
      el("span", "meta", strip(d.service) + " · " + (d.last_success ? "last delivered " + ago(Math.floor(Date.now() / 1000), d.last_success) : "nothing delivered yet")));
    const lab = el("label", "details"); const cb = el("input"); cb.type = "checkbox"; cb.checked = !!d.details;
    cb.onchange = () => setDetails(d.id, cb.checked);
    lab.append(cb, document.createTextNode("Show the agent and what it asks for"));
    const rm = el("button", "deny", "Remove"); rm.onclick = () => removeDevice(d.id, d.id === mine);
    row.append(lab, rm);
    box.append(row);
  }
  if (!info.devices.length) box.append(el("div", "empty", "No device gets notifications yet."));
  box.append(el("div", "note", "A notification says how many requests are waiting (lock screens show it); tick a device to also show the agent and what it asks for. At most one per device every " + (info.min_interval_secs || 30) + " s."));
}
// The service worker saw the subscription change: show the notifications box (and its re-register button).
function openNotifications() {
  const box = document.getElementById("push");
  if (box && box.scrollIntoView) box.scrollIntoView();
  renderPush();
}
// Opened from a notification: scroll to the pending list and mark the request (if still waiting).
let openId = "";
function openPending(id) {
  openId = id || "";
  const box = document.getElementById("pending");
  if (box && box.scrollIntoView) box.scrollIntoView();
  for (const [k, c] of cards) c.node.className = "card req" + (k === openId ? " opened" : "");
}
function fromHash() {
  const h = (typeof location !== "undefined" && location.hash) || "";
  const m = /^#pending(?:\/([A-Za-z0-9_-]{1,64}))?$/.exec(h);
  if (m) openPending(m[1]);
  if (h === "#notifications") openNotifications();
}

// Signed out, the server answers /api/me with 401 and tells the page nothing else: the page offers
// passkey sign-in (and says where enrolment links come from) whatever the server's state.
async function boot() {
  const r = await fetch("/api/me");
  const me = r.ok ? await r.json() : { who: { state: "none" } };
  const auth = document.getElementById("auth"), con = document.getElementById("console");
  auth.replaceChildren();
  if (me.who.state === "operator") { auth.hidden = true; con.hidden = false; await refresh(); fromHash(); renderPush(); return; }
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
  if (g.agent) out.push(kvRow("agent", g.agent.name + " · " + g.agent.harness + " · max_turns " + (g.agent.max_turns ?? "default") + " · children " + g.agent.max_children + (g.agent.remote ? " · Remote Control session " + g.agent.remote : "")));
  if (g.program) out.push(kvRow("program", g.program.name + ": " + g.program.command.join(" ")));
  out.push(kvRow("image", g.image.Ok || ("refused: " + g.image.Err), g.image.Ok ? "mono" : "blocked"));
  out.push(kvRow("isolation", g.isolation + " · unlisted hosts " + JSON.stringify(g.unlisted_hosts)));
  for (const r of g.reach) out.push(kvRow("reach", r.host + " " + (r.methods || []).join(",") + " " + (r.paths || ["/**"]).join(" ") + (r.allow_dangerous ? " · DANGEROUS allowed" : "")));
  for (const h of g.hosts) out.push(kvRow(h.mode, h.host + (h.mode === "spliced" ? " (every method and path; not inspected)" : " (" + h.why + ")"), h.mode === "spliced" ? "pend" : "mono"));
  for (const f of g.forbid) out.push(kvRow("forbid", f.host + " " + (f.paths || ["everything"]).join(" "), "blocked"));
  for (const i of g.inject) out.push(kvRow("inject", "secret " + i.secret + " → " + i.host + " " + i.header + (i.secret_set ? "" : " · NOT SET in the vault") + (i.bound_to_host ? "" : " · not bound to this host") + (i.optional ? " · optional" : ""), i.secret_set && i.bound_to_host ? "mono" : "pend"));
  if (g.llm) out.push(kvRow("model", g.llm.provider + " via " + g.llm.upstream + " · secret " + g.llm.secret + (g.llm.secret_set ? "" : " (NOT SET)") + " · " + g.llm.max_requests + " requests, " + g.llm.max_output_tokens + " output tokens" + (g.llm.max_input_tokens != null ? ", " + g.llm.max_input_tokens + " input tokens" : "") + (g.llm.models ? " · models: " + (g.llm.models.length ? g.llm.models.join(", ") : "none") : "")));
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

// ---- secrets ----
// The vault by name: the server sends no value, nor anything derived from one. Storing or replacing a
// value, changing a secret's hosts and deleting it are each signed with the passkey. A value is typed
// into a password field, which is cleared as soon as it is submitted; it goes to the server only in the
// signed action's finish, over HTTPS, while begin (and so the passkey) signs its salted sha256.
// References (a file on the host, like a harness's login) are listed and can be rebound, but are made
// on the host.
const hexOf = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, "0")).join("");
async function saltedDigest(value) {
  const salt = new Uint8Array(16); crypto.getRandomValues(salt);
  const v = new TextEncoder().encode(value);
  const buf = new Uint8Array(salt.length + v.length); buf.set(salt); buf.set(v, salt.length);
  const d = await crypto.subtle.digest("SHA-256", buf);
  buf.fill(0); v.fill(0);
  return { value_salt: hexOf(salt), value_sha256: hexOf(d) };
}
const utc = t => new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC";
function secretUse(u) {
  const where = "zone " + u.zone + " (" + u.root + "/" + u.manifest + "): ";
  return strip(u.use === "llm" ? where + "model credential" + (u.provider ? " (" + u.provider + ")" : "")
    : where + "inject \u2192 " + u.host + " \u00b7 header " + u.header + " \u00b7 format " + u.format + (u.optional ? " \u00b7 optional" : ""));
}
let secretsKey = "";
function renderSecrets(s) {
  const box = document.getElementById("secrets");
  if (!box) return;
  const v = s.secrets || { secrets: [], missing: [] };
  // Rebuilt only when it changes, so a button doesn't move under a tap.
  const key = JSON.stringify(v);
  if (key === secretsKey) return;
  secretsKey = key;
  box.replaceChildren();
  for (const x of v.secrets || []) {
    const d = el("div", "secret");
    const head = el("div", "row");
    head.append(el("span", "mono", strip(x.name)), el("span", "risk " + (x.kind === "reference" ? "r2" : "r0"), x.kind === "reference" ? "reference" : "value"));
    d.append(head);
    d.append(el("div", "meta", (x.hosts || []).length ? "sent only to " + x.hosts.map(strip).join(", ") : "bound to no host: sent nowhere"));
    if (x.reference) d.append(el("div", "meta", "refers to " + strip(x.reference.file) + (x.reference.pointer ? "#" + strip(x.reference.pointer) : "") + ", read at each use"));
    d.append(el("div", "meta", x.set_at ? "last set " + utc(x.set_at) : "last set: unknown"));
    for (const u of x.used_by || []) d.append(el("div", "meta", secretUse(u)));
    if (!(x.used_by || []).length) d.append(el("div", "meta", "no listed manifest uses it"));
    if ((x.runs || []).length) d.append(el("div", "meta", "running now: " + x.runs.map(r => strip(r.run)).join(", ")));
    const b = el("div", "buttons");
    if (x.kind !== "reference") { const set = el("button", "", "Replace value\u2026"); set.onclick = () => openSecret("set", x); b.append(set); }
    const h = el("button", "", "Hosts\u2026"); h.onclick = () => openSecret("hosts", x);
    const rm = el("button", "deny", "Delete\u2026"); rm.onclick = () => openSecret("delete", x);
    b.append(h, rm); d.append(b); box.append(d);
  }
  for (const m of v.missing || []) {
    const d = el("div", "secret");
    const head = el("div", "row");
    head.append(el("span", "mono", strip(m.name)), el("span", "risk r3", "not set"));
    d.append(head);
    for (const u of m.used_by || []) d.append(el("div", "meta", secretUse(u)));
    const b = el("div", "buttons"); const set = el("button", "approve", "Set\u2026");
    set.onclick = () => openSecret("set", { name: m.name, hosts: (m.used_by || []).filter(u => u.host).map(u => u.host), missing: true });
    b.append(set); d.append(b); box.append(d);
  }
  if (!(v.secrets || []).length && !(v.missing || []).length) box.append(el("div", "empty", "No secrets in the vault."));
  const b = el("div", "buttons"); const add = el("button", "", "New secret\u2026"); add.onclick = () => openSecret("set", null);
  b.append(add); box.append(b);
  box.append(el("div", "note", "Values are never shown, here or anywhere. " + strip(v.link_cli_only ||
    "References (a file on the host, like a harness login) are made on the host: wicket secret link.")));
}
let secretMode = null;
function secretInput(id, label, value, password) {
  const l = el("label", "", label); l.htmlFor = id;
  const i = el("input", "text"); i.id = id; i.type = password ? "password" : "text"; i.value = value || "";
  i.autocomplete = "off"; i.spellcheck = false;
  if (i.setAttribute) { i.setAttribute("autocomplete", "off"); i.setAttribute("autocapitalize", "none"); i.setAttribute("autocorrect", "off"); }
  return [l, i];
}
function openSecret(mode, x) {
  const f = document.getElementById("secret-edit"), body = document.getElementById("secret-edit-body"), go = document.getElementById("secret-edit-go");
  const title = document.getElementById("secret-edit-title");
  closeSecret();
  secretMode = { mode, name: x ? x.name : "", x, inputs: {} };
  const inputs = secretMode.inputs;
  const parts = [];
  const hosts = x && x.hosts ? x.hosts.join(", ") : "";
  if (mode === "set") {
    const replacing = x && !x.missing;
    title.textContent = replacing ? "Replace the value of " + strip(x.name) : "Store a secret";
    const [nl, ni] = secretInput("secret-name", "Name (letters, digits, - and _)", x ? x.name : "");
    if (x) ni.readOnly = true;
    inputs.name = ni;
    const [vl, vi] = secretInput("secret-value", "Value (not shown, and never shown again)", "", true);
    const [hl, hi] = secretInput("secret-hosts", "Hosts it may be sent to (comma-separated; *.example.com for every host under it)", hosts);
    hi.placeholder = replacing ? "empty: keep its hosts" : "api.example.com";
    inputs.value = vi; inputs.hosts = hi;
    parts.push(nl, ni, vl, vi, hl, hi, el("div", "note", "The value goes to the server only when you sign, over HTTPS; your passkey signs its salted hash, never the value. " +
      "A secret is sent only to the hosts it is bound to; a new one with none is sent nowhere. Running boxes use a new value from their next request."));
    go.textContent = replacing ? "Sign and replace" : "Sign and store"; go.className = "approve";
  } else if (mode === "hosts") {
    title.textContent = "Hosts for " + strip(x.name);
    const [hl, hi] = secretInput("secret-hosts", "Hosts it may be sent to (comma-separated; *.example.com for every host under it)", hosts);
    inputs.hosts = hi;
    parts.push(hl, hi, el("div", "note", "A secret is sent only to these hosts, whatever a manifest asks (as wicket secret hosts). This replaces its list."));
    go.textContent = "Sign: set hosts"; go.className = "approve";
  } else {
    title.textContent = "Delete " + (x.kind === "reference" ? "the reference " : "secret ") + strip(x.name) + "?";
    const zones = x.zones || [], runs = (x.runs || []).map(r => r.run);
    parts.push(el("div", "warn", zones.length ? "Used by zone " + zones.map(strip).join(", ") + ": their boxes are refused it from their next request." : "No listed manifest uses it."));
    if (runs.length) parts.push(el("div", "warn", "Running now: " + runs.map(strip).join(", ") + "."));
    if (x.kind === "reference") parts.push(el("div", "note", "Only the reference is removed; the file it names stays on the host."));
    go.textContent = "Delete\u2026 (sign next)"; go.className = "deny";
  }
  body.replaceChildren(...parts);
  f.hidden = false;
  if (f.scrollIntoView) f.scrollIntoView({ block: "nearest" });
  const first = parts.find(p => p.tagName === "input" && !p.readOnly); if (first) first.focus();
}
function closeSecret() {
  if (secretMode && secretMode.inputs.value) secretMode.inputs.value.value = "";
  const f = document.getElementById("secret-edit"); if (f) f.hidden = true;
  const body = document.getElementById("secret-edit-body"); if (body) body.replaceChildren();
  secretMode = null;
}
async function submitSecret(ev) {
  ev.preventDefault();
  const m = secretMode;
  if (!m) return;
  const hosts = (m.inputs.hosts ? m.inputs.hosts.value : "").split(",").map(h => h.trim()).filter(Boolean);
  if (m.mode === "set") {
    const vi = m.inputs.value;
    let value = vi.value;
    vi.value = ""; // no echo after submit
    const name = m.inputs.name.value.trim();
    closeSecret();
    if (!name || !value.trim()) { value = ""; toast("A name and a value are needed."); return; }
    let d;
    try { d = await saltedDigest(value); } catch (e) { value = ""; toast("This browser can't hash the value here (the console needs HTTPS)."); return; }
    signed({ action: "set_secret", name, hosts, ...d }, () => { value = ""; }, () => ({ value }));
    return;
  }
  closeSecret();
  if (m.mode === "hosts") signed({ action: "secret_hosts", name: m.name, hosts });
  else signed({ action: "delete_secret", name: m.name });
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
    renderRows("health", ((s.health || {}).nodes) || [], healthRow, "No node has reported its health yet.");
    if (s.health && s.health.control_disk_pct > 85) document.getElementById("health").prepend(el("div", "blocked", "! the control host's disk is " + s.health.control_disk_pct + "% full"));
    renderRows("placed", s.placed || [], placedRow, "No placed nodes.");
    renderRows("capacity", s.capacity || [], capacityRow, "No capacity grants: every `wicket node create` waits for a decision.");
    renderCapacityForm();
    renderStart(s);
    renderManifests(s);
    renderSecrets(s);
    renderRows("decided", s.decided, x => { const d = el("div", "row"); d.append(el("span", "mono", strip(x.id + " " + x.method + " " + x.host + x.path)), el("span", x.status === "granted" ? "ok" : "blocked", ({ granted: "approved", denied: "denied" })[x.status] || x.status)); return d; }, "No decisions yet.");
    renderRows("audit", s.audit.slice().reverse(), line, "No activity yet.");
    renderOperator(s);
    renderPolicy();
  } catch (e) { /* keep polling */ }
}
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("runform").addEventListener("submit", submitRunForm);
  document.getElementById("runform-cancel").addEventListener("click", closeRunForm);
  document.getElementById("confirm-cancel").addEventListener("click", closeConfirm);
  document.getElementById("secret-edit").addEventListener("submit", submitSecret);
  document.getElementById("secret-edit-cancel").addEventListener("click", closeSecret);
  document.getElementById("mfedit-close").addEventListener("click", () => { document.getElementById("mfedit").hidden = true; });
  document.getElementById("detail-close").addEventListener("click", () => { document.getElementById("detail").hidden = true; });
  if (typeof navigator !== "undefined" && navigator.serviceWorker) navigator.serviceWorker.addEventListener("message", e => {
    if (e.data && typeof e.data.open === "string") openPending(e.data.open);
    if (e.data && e.data.resubscribe === true) openNotifications();
  });
  if (typeof window !== "undefined" && window.addEventListener) window.addEventListener("hashchange", fromHash);
  boot();
  setInterval(() => { if (!document.getElementById("console").hidden) refresh(); }, 2000);
});

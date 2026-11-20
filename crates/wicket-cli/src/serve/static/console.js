"use strict";
// The console's script, served as a static file under a strict CSP (no inline script or style, no
// eval). Every string from the ledger is untrusted (agents influence paths and reasons): set as textContent only.
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = String(text); return e; };
// The same set as wicket_core::text::is_unsafe: C0, DEL, C1, bidi, zero-width, line separators (#128).
const strip = s => String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, " ");
// One time format (#645): how far off, for the near past and future ("in 8 h", "2 h ago"), with the
// local wall-clock time ("19:20", "Wed 19:20", "21 Nov 19:20") and the exact UTC value as a tooltip.
// Counted from the server's clock (`skewSecs`, from each poll), so a phone's wrong clock doesn't matter.
let skewSecs = 0;
// The last state polled: the authority view reads the standing rules and runs from it.
let lastState = null;
const nowSecs = () => Date.now() / 1000 + skewSecs;
const plural = (n, one, many) => n + " " + (n === 1 ? one : (many || one + "s"));
function rel(t, now) {
  const d = t - (now === undefined ? nowSecs() : now), a = Math.abs(d);
  if (a < 5) return "just now";
  const v = a < 90 ? Math.round(a) + " s" : a < 5400 ? Math.round(a / 60) + " min" : a < 172800 ? Math.round(a / 3600) + " h" : plural(Math.round(a / 86400), "day");
  return d > 0 ? "in " + v : v + " ago";
}
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function clock(t, now) {
  const d = new Date(t * 1000), n = new Date((now === undefined ? nowSecs() : now) * 1000);
  const hm = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  if (d.toDateString() === n.toDateString()) return hm;
  if (Math.abs(d - n) < 6 * 86400000) return DAYS[d.getDay()] + " " + hm;
  return d.getDate() + " " + MONTHS[d.getMonth()] + (d.getFullYear() !== n.getFullYear() ? " " + d.getFullYear() : "") + " " + hm;
}
const iso = t => new Date(t * 1000).toISOString().replace(/\.\d+Z$/, "Z");
// "19:20 (in 8 h)", or a dash for no time.
const at = (t, now) => t ? clock(t, now) + " (" + rel(t, now) + ")" : "\u2014";
// The same as an element, its exact time in `title` and `datetime`.
function timeEl(t, text) {
  const e = el("time", "", text === undefined ? at(t) : text);
  if (t) { e.title = iso(t); if (e.setAttribute) e.setAttribute("datetime", iso(t)); }
  return e;
}
const ago = (now, t) => rel(t, now);
// A relative time that stays true in a row kept across polls: refreshRel() rewrites every one.
const relEls = new Set();
function relEl(t, prefix, now) {
  const e = timeEl(t, (prefix || "") + rel(t, now));
  e.dataset.rel = String(t); e.dataset.prefix = prefix || "";
  relEls.add(e);
  return e;
}
function refreshRel() {
  for (const e of relEls) {
    if (e.isConnected === false) { relEls.delete(e); continue; }
    const text = e.dataset.prefix + rel(Number(e.dataset.rel));
    if (e.textContent !== text) e.textContent = text;
  }
}
const riskClass = r => ({ R0Read: "r0", R1ReadScoped: "r1", R2WriteReversible: "r2", R3ExternalOrIrreversible: "r3", R4ExecOrPrivilege: "r4" })[r] || "r4";
// What a risk class means to whoever decides, with its code (docs/reference/risk-classes.md, #574).
// Risk as what could happen (docs/explanation/console-design.md); the class's code only under Details.
const riskWords = r => ({ R0Read: "Only reads", R1ReadScoped: "Only reads", R2WriteReversible: "Changes data that can be put back", R3ExternalOrIrreversible: "Others will see it, or it can't be undone", R4ExecOrPrivilege: "Pushes code, deploys, or gains privileges" })[r] || strip(r);
// The signing sheet's words, unchanged until the sheet's own change is reviewed (#715 review):
// describe() stays byte for byte what main shows.
const riskLabel = r => ({ R0Read: "R0 \u00b7 read", R1ReadScoped: "R1 \u00b7 read (scoped)", R2WriteReversible: "R2 \u00b7 changes data", R3ExternalOrIrreversible: "R3 \u00b7 visible to others, or can't be undone", R4ExecOrPrivilege: "R4 \u00b7 push, deploy or privilege" })[r] || r;
const riskCode = r => ({ R0Read: "R0", R1ReadScoped: "R1", R2WriteReversible: "R2", R3ExternalOrIrreversible: "R3", R4ExecOrPrivilege: "R4" })[r] || strip(r);
// A lifetime as the card and the sheet both say it: whole hours as hours, else minutes.
// Money as people write it (#639): "$0.05", "$1.00", and more places only where a value needs them
// ("$0.014"). The server sends "$0.0500"; anything that isn't a dollar amount is shown as sent.
function money(v) {
  const m = /^\$(\d+)(?:\.(\d+))?$/.exec(String(v ?? "").trim());
  if (!m) return strip(v);
  const frac = (m[2] || "").replace(/0+$/, "").padEnd(2, "0");
  return "$" + m[1] + "." + frac;
}
const microUsd = u => money("$" + (Number(u || 0) / 1e6).toFixed(6));
// A principal by its short name (#639): an operator as unix/alex or passkey/laptop, an agent by its
// name and zone; its full identity in the element's title where there is one.
function principalName(p) {
  const x = String(p || "");
  const op = /\/op\/((?:unix|passkey)\/[^/]+)$/.exec(x);
  if (op) return strip(op[1]);
  const ag = /\/z\/([^/]+)\/a\/([^/]+)$/.exec(x);
  if (ag) return strip(ag[2]) + " (zone " + strip(ag[1]) + ")";
  return strip(x);
}
// A principal as an element (#707 review): the short name as a button that shows the full identity
// under it on a tap (a phone has no hover), and as its title.
function principalEl(p) {
  const w = el("span", "principal");
  const full = strip(p), short = principalName(p);
  if (short === full) { w.append(el("span", "run-name", full)); return w; }
  const b = el("button", "idname", short);
  b.type = "button"; b.title = full;
  if (b.setAttribute) b.setAttribute("aria-expanded", "false");
  const line = el("div", "idline", full); line.hidden = true;
  b.onclick = () => { line.hidden = !line.hidden; if (b.setAttribute) b.setAttribute("aria-expanded", String(!line.hidden)); layoutAt = performance.now(); };
  w.append(b, line);
  return w;
}
// Server text with RFC 3339 UTC times in it (a node's health, a refusal's reason) in the rows' local
// time; the original stays in the element's title (#707 review).
const UTC_TIME = /\b\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d+)?)?Z\b/g;
const localTimes = text => strip(text).replace(UTC_TIME, m => { const t = Date.parse(m) / 1000; return isNaN(t) ? m : clock(t); });
function serverText(tag, cls, text) { const e = el(tag, cls, localTimes(text)); if (UTC_TIME.test(String(text))) e.title = strip(text); UTC_TIME.lastIndex = 0; return e; }
// A sentence with `commands` in backticks as code spans (#648): the rest stays text.
// A command to run on the host, with a Copy button (#715 review): the console's own controls come
// first, and a command is the secondary way, so it is small, but one tap copies it whole.
function copyButton(cmd) {
  const b = el("button", "link copy", "Copy");
  b.type = "button";
  if (b.setAttribute) b.setAttribute("aria-label", "Copy " + cmd);
  b.onclick = async () => {
    try { await navigator.clipboard.writeText(cmd); toast("Copied: " + cmd); }
    catch { toast("Couldn't copy here; select the command instead.", true); }
  };
  return b;
}
// `copy`: the commands in `text` that are instructions to run, each given a Copy button (#715
// review); a command only mentioned gets none.
function codeText(tag, cls, text, copy = []) {
  const e = el(tag, cls);
  String(text).split("`").forEach((part, i) => {
    if (!part) return;
    if (i % 2 === 0) { e.append(document.createTextNode(part)); return; }
    e.append(el("code", "", part));
    if (copy.includes(part)) e.append(copyButton(part));
  });
  return e;
}
const span = secs => { const s = Math.round(secs || 0); return s >= 3600 && s % 3600 === 0 ? (s / 3600) + (s === 3600 ? " hour" : " hours") : Math.round(s / 60) + " min"; };

// What happened, at the foot of the page (#574): long enough to read (3 to 8 s by length), and an
// error in its own style, kept until tapped.
let toastTimer;
function toast(t, error, sticky) {
  const m = document.getElementById("msg");
  m.textContent = (t === undefined || t === null || t === "") ? "Done." : String(t);
  m.className = error ? "error" : "";
  m.setAttribute("role", error ? "alert" : "status");
  m.hidden = false;
  m.onclick = () => { m.hidden = true; };
  clearTimeout(toastTimer);
  if (!error && !sticky) toastTimer = setTimeout(() => { m.hidden = true; }, Math.min(8000, Math.max(3000, 40 * m.textContent.length)));
}
// An error, said plainly: a passkey sheet the operator closed is no failure of wicket's.
function toastError(e, what, passkey) {
  const name = e && e.name, msg = (e && e.message) || String(e);
  // Only around a passkey call does NotAllowedError mean the sheet was closed; elsewhere (push
  // subscription, say) it means a permission was refused, and says so as the browser does.
  if (passkey && (name === "NotAllowedError" || name === "AbortError")) return toast("Passkey cancelled. Nothing was signed.", true);
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
  } catch (e) { toastError(e, "Passkey", true); }
}
async function signIn() {
  try { const { publicKey } = await post("/api/login/begin"); const j = await post("/api/login/finish", await assertWith(publicKey)); toast(j.ok); boot(); }
  catch (e) { toastError(e, "Sign-in", true); }
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
    // Who it is for, from the signed fields: the agent's name with its zone (the same name in two
    // zones mustn't read the same), its full id with the ids; who in the box asked, as reported.
    const agent = a.agent ? String(a.agent).split("/a/").pop() : "";
    const lines = [verb + how + ": " + what + (a.prefix ? "\u2026 (every path under it)" : "") + (a.scope === "zone" ? " \u00b7 for any run in zone " + s(a.zone) : ""),
      "Risk: " + riskLabel(a.risk)];
    lines.push((agent ? "For " + s(agent) : "For run " + s(a.run)) + " (zone " + s(a.zone) + ")" +
      ((a.requested_by || []).length ? " \u00b7 asked by " + a.requested_by.map(s).join(", ") + " (as reported)" : ""));
    lines.push("Request " + s(a.request) + " \u00b7 run " + s(a.run) + (a.agent ? " \u00b7 agent " + s(a.agent) : "") + (a.effect_sha256 ? " \u00b7 effect " + s(a.effect_sha256).slice(0, 16) : ""));
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
  if (a.action === "standing_approve" || a.action === "standing_renew") {
    const days = a.ttl_secs ? "for " + Math.round(a.ttl_secs / 86400) + " days" : "until revoked";
    if (a.action === "standing_renew") return "Renew standing reach " + s(a.standing) + " (" + ruleText(a.rule) + ") " + (a.ttl_secs ? days + " from now" : days);
    const to = a.for === "zone" ? "every agent of zone " + s(a.zone) : s(a.principal) + " (each later run of it)";
    return "Approve standing reach " + s(a.standing) + (a.narrowed ? " narrowed to its evidence" : "") + ": " + ruleText(a.rule) +
      " \u00b7 for " + to + " \u00b7 " + days + (a.effect_sha256 ? " \u00b7 effect " + s(a.effect_sha256).slice(0, 16) : "");
  }
  if (a.action === "standing_deny") return "Deny standing reach " + s(a.standing) + ": " + ruleText(a.rule);
  if (a.action === "release_fence") return "Release run " + s(a.run) + "'s fence on node " + s(a.node) + " (" + s(a.node_status) +
    (a.node_seen_ms ? ", last reported " + whenMs(a.node_seen_ms) : ", never reported") + "), fenced " +
    (a.fenced_until_ms ? "until " + whenMs(a.fenced_until_ms) : "until its node confirms the box stopped") +
    ": its agent can be woken while its box may still be running there \u00b7 " + s(a.why) + " \u00b7 reason: " + s(a.reason) +
    (a.effect_sha256 ? " \u00b7 effect " + s(a.effect_sha256).slice(0, 16) : "");
  // #711: a link for another device of the operator's, as the same passkey operator.
  if (a.action === "enrol_link") return "Make a one-time link that enrols another device as " + s(a.name) + " (" + s(a.enrols_as) + ", the same operator and authority)\n" +
    "It works once, for " + Math.round((a.ttl_secs || 0) / 60) + " minutes, and is shown only now. Open it on the new device.";
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
// How long the server keeps a begun action's challenge (`CHALLENGE_TTL` in serve/mod.rs).
const CHALLENGE_MS = 120000;
const EXPIRY_MARGIN_MS = 5000;
let expiryTimer = null, sheetToken = 0;
async function signed(body, after, extra) {
  if (ceremony) return;
  ceremony = true;
  afterConfirm = after || null;
  // Something shows between the tap and the sheet (#574, item 6), and stays until it opens: on a
  // slow link the operator otherwise taps again, or thinks the tap failed.
  toast("Preparing\u2026", false, true);
  await openSheet(body, extra);
}
// Begins the action and fills the sheet with what the server returned: once from a tap, and again
// from "Ask again" inside the open sheet, so a second tap never lands on the page beneath.
async function openSheet(body, extra) {
  const go = document.getElementById("confirm-go");
  const state = document.getElementById("confirm-state");
  // Each sheet has a token; closing it (Cancel, say, while "Ask again" prepares) bumps it, and the
  // begin that comes back afterwards is dropped rather than reopening a closed sheet.
  const sheet = ++sheetToken;
  let begin;
  try { begin = await post("/api/action/begin", body); }
  catch (e) { if (sheet === sheetToken) { toastError(e); closeConfirm(); } return; }
  if (sheet !== sheetToken) return;
  // An error that stays sits above the sheet (#597): it goes when the sheet opens.
  document.getElementById("msg").hidden = true;
  // The decision (describe's first line) in an element of its own, styled strongly; the rest, the
  // target among it, in full ink. The text, newline included, is describe's exactly (#698 review).
  const said = describe(begin.action), cut = said.indexOf("\n");
  const lead = el("div", "lead", cut < 0 ? said : said.slice(0, cut));
  document.getElementById("confirm-what").replaceChildren(lead, ...(cut < 0 ? [] : [document.createTextNode("\n"), el("div", "rest", said.slice(cut + 1))]));
  announce("");
  renderBlast(document.getElementById("confirm-blast"), begin.action.blast);
  renderUpdate(document.getElementById("confirm-update"), begin.action.update);
  state.textContent = "";
  delete go.dataset.waiting;
  const deny = begin.action.decision === "deny" || ["revoke", "delete_secret", "standing_deny", "release_fence"].includes(begin.action.action);
  go.textContent = deny ? "Sign: " + ({ revoke: "revoke", delete_secret: "delete", release_fence: "release" }[begin.action.action] || "deny") : "Sign with passkey";
  go.className = deny ? "deny" : "approve";
  // Not tappable at once: a second tap aimed at the card mustn't land on it.
  go.disabled = true; setTimeout(() => { if (sheet === sheetToken) go.disabled = false; }, SETTLE_MS);
  // The challenge expires on the server's clock. The time it has left, counted from its arrival on
  // the wall clock (a phone that sleeps still counts it), a few seconds early for the signature's
  // trip back; the phone's own clock being out doesn't matter.
  const deadline = Date.now() + (begin.expires_in_ms || CHALLENGE_MS) - EXPIRY_MARGIN_MS;
  clearInterval(expiryTimer);
  const tick = () => {
    if (go.dataset.waiting) return;
    const left = Math.max(0, deadline - Date.now());
    if (left > 0) { state.textContent = "Expires in " + Math.floor(left / 60000) + ":" + String(Math.floor(left / 1000) % 60).padStart(2, "0"); return; }
    clearInterval(expiryTimer);
    state.textContent = "This expired before it was signed. Nothing was signed.";
    announce(state.textContent);
    go.textContent = "Ask again"; go.className = "approve"; go.disabled = false;
    go.onclick = () => { go.disabled = true; state.textContent = "Preparing\u2026"; openSheet(body, extra); };
  };
  tick();
  expiryTimer = setInterval(tick, 1000);
  go.onclick = async () => {
    go.disabled = true;
    go.dataset.waiting = "1";
    clearInterval(expiryTimer);
    state.textContent = "Waiting for your passkey\u2026";
    announce(state.textContent);
    try { const j = await post("/api/action/finish", { ...(await assertWith(begin.publicKey)), ...(extra ? extra() : {}) }); toast(j.ok); if (j.link) showEnrolLink(j); }
    catch (e) { toastError(e, null, true); }
    closeConfirm();
  };
  document.getElementById("confirm").hidden = false;
  go.focus();
}
// What a screen reader is told about the sheet: state changes only, not the countdown's every second.
function announce(t) { const a = document.getElementById("confirm-announce"); if (a) a.textContent = t; }
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
  sheetToken++;
  pollGen++;
  clearInterval(expiryTimer);
  delete document.getElementById("confirm-go").dataset.waiting;
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
// `more`, if given, takes the on-behalf-of chain: on a request card it sits under Details.
function renderAgent(c, id, more) {
  const w = el("div", "agent");
  if (id.verified) {
    // The agent by name; its full identity behind a tap (#574, item 5).
    // A real button: focusable, and it says whether the identity is shown.
    const name = el("button", "idname", strip(id.agent));
    name.type = "button";
    const idline = el("div", "idline", strip(id.id));
    idline.hidden = true;
    name.title = "Show its identity";
    name.setAttribute("aria-expanded", "false");
    name.onclick = () => {
      idline.hidden = !idline.hidden;
      name.setAttribute("aria-expanded", String(!idline.hidden));
      // The line moves the buttons below it: a tap meant for where they were is ignored a moment.
      layoutAt = performance.now();
    };
    w.append(el("span", "ok", "✓ "), name, document.createTextNode(" · zone " + strip(id.zone)));
    (more || w).append(el("div", "chain", "On behalf of: " + (id.acting_for || []).map(strip).join(" → ")));
    w.append(idline);
    c.append(w); return true;
  }
  if ((id.error || "").startsWith("no identity was issued")) {
    w.append(el("div", "", "Program run (no agent identity)")); c.append(w); return true;
  }
  w.append(el("div", "bad", "Agent identity NOT verified: " + strip(id.error || "unknown") + ". Approval is disabled."));
  c.append(w); return false;
}

// Which call in the box asked, as the agent's event stream reports it (#574, item 5): helpful, not
// proof. Labelled apart from "On behalf of" above, and always with the note that anything in the
// box could use the grant.
function renderWho(list, part) {
  const w = el("div", "who");
  // What stays on the card (#709 review): whether more than one agent asked, and that anything in
  // the box could use the grant, are about how far a grant reaches, not detail.
  if (part === "warnings") {
    if (list.length > 1) w.append(el("div", "warn", "Asked by more than one agent: one grant would serve all of them."));
    w.append(el("div", "note", (list.length ? "As the agent reports it, not proven: anything" : "Anything") + " in this box could use the grant."));
    return w;
  }
  const line = r => strip(r.agent) + " \u2014 " + strip(r.tool) + ": " + strip(r.call).slice(0, 120);
  if (!list.length) w.append(el("div", "", "Asked by (in the box): unknown (no agent event stream)"));
  for (const a of list) {
    const rs = a.requesters || [];
    // One asker with no call in flight is said by the note alone; beside others it is listed, so
    // "more than one agent" counts what is shown.
    if (a.basis === "none" || !rs.length) { if (list.length > 1) w.append(el("div", "", "Asked by (in the box): unknown — no tool call was in flight")); continue; }
    if (a.basis === "ambiguous") { w.append(el("div", "", "Asked by (in the box): one of " + rs.length + " concurrent calls:")); for (const r of rs) w.append(el("div", "cand", "\u2022 " + line(r))); }
    else w.append(el("div", "", "Asked by (in the box): " + line(r0(rs))));
  }
  if (part !== "list") {
    if (list.length > 1) w.append(el("div", "warn", "Asked by more than one agent: one grant would serve all of them."));
    // Always: whoever asked, the grant is the box's.
    w.append(el("div", "note", (list.length ? "As the agent reports it, not proven: anything" : "Anything") + " in this box could use the grant."));
  }
  return w;
}
const r0 = rs => rs[0];

// What a request asks for, in words (#621): an HTTP request as its method and URL; wicket's own kinds
// (on wicket.internal) as a sentence, with the raw op on a small line under it. A capacity lease's
// sentence is built from its terms as the server sends them (`lease`), never parsed out of the
// reason, which quotes agent-chosen text (#709 review). The region the agent asked for is its own
// value (`asked`), shown quoted.
// A long id in a sentence: its head and tail (the whole op is on the raw line under Details).
const shortText = id => id.length > 18 ? id.slice(0, 10) + "\u2026" + id.slice(-6) : id;
function asks(p) {
  const raw = strip(p.method + " " + p.host + p.path);
  if (p.host !== "wicket.internal") return { what: raw + (p.scope_prefix ? "\u2026  (every path under it)" : ""), raw: "", said: [["Why", strip(p.reason)]], wicket: null, mixed: null, internal: false };
  const seg = String(p.path || "").split("/").filter(Boolean).map(strip);
  // Three kinds of text, kept apart (#715 review): `what`, wicket's sentence from fields it checked;
  // `said`, what the agent chose (quoted, as its words); `wicket`, a reason wicket wrote whole (a
  // spawn's limits, a link's policy). A reason that mixes wicket's words with the agent's is never
  // shown as wicket's: when its parts aren't sent apart, it is `mixed`, shown under Details as such.
  let what = raw, said = [], wicket = null, mixed = null;
  if (p.method === "CAPACITY") {
    const x = p.lease;
    if (x) {
      what = "Lease a node: " + plural(Number(x.vcpus) || 0, "vCPU", "vCPUs") + ", " + (Number(x.memory_mib) || 0) + " MiB, " + strip(x.isolation || "default") + " isolation, for " +
        span(Number(x.duration_secs) || 0) + " on " + strip(x.provider) + ", at most " + money(x.hourly_cap_usd) + "/h, " + money(x.reserved_usd) + " reserved";
      if (x.region) said.push(["Region", strip(x.region)]);
      if (x.reason) said.push(["Why", strip(x.reason)]);
    } else { what = "Lease a node (" + seg.slice(1).join("/") + "); its terms arrive with the next refresh"; mixed = strip(p.reason); }
  } else if (p.method === "SPAWN" && seg[0] === "zones") {
    // wicket writes the reason as "start <kind> …"; only its two kinds are read from it, nothing else.
    const k = /^start (agent|program) /.exec(String(p.reason || ""));
    what = "Start " + (k ? "a new " + k[1] : "a new agent or program") + (seg[2] ? " named " + seg[2] : "") + " in zone " + seg[1];
    wicket = strip(p.reason);
  } else if (p.method === "LINK" && seg[0] === "links") {
    // The path is /links/<from run>/<to run>/<port>: the port is on the second box, the one linked to.
    const nm = id => { const n = runName(id); return n === id ? shortText(n) : n; };
    what = "Let " + nm(seg[1]) + "'s box reach port " + (seg[3] || "?") + " on " + nm(seg[2]) + "'s box";
    wicket = strip(p.reason);
  } else if (p.method === "UPDATE" && seg[0] === "self") {
    what = "Install wicket build " + String(seg[1] || "").slice(0, 12) + "\u2026";
    const c = p.claims;
    if (c) {
      if (c.commit) said.push(["Commit", strip(c.commit)]);
      if (c.reason) said.push(["Why", strip(c.reason)]);
    } else mixed = strip(p.reason);
  } else mixed = strip(p.reason);
  return { what, raw, said, wicket, mixed, internal: true };
}

// Pending cards are kept by request id: a card whose content hasn't changed is the same element
// from one poll to the next, so its buttons don't move or get replaced under the cursor. When the
// cards do move, `layoutAt` is set and taps are ignored for a moment.
const cards = new Map();
// A long id shortened in the middle, its head and tail kept (#574 review): what is copied is the
// whole id, and the whole id is its title.
// Inline text (so a copy is one line), shortened in the middle; a tap or click shows it whole, to
// read or select and copy on a phone (#709 review).
function idEl(id) {
  id = strip(id);
  if (id.length <= 18) { const e = el("span", "id-short mono", id); e.title = id; return e; }
  const short = id.slice(0, 10) + "\u2026" + id.slice(-6);
  const b = el("button", "id-short link", short);
  b.type = "button"; b.title = id;
  if (b.setAttribute) { b.setAttribute("aria-label", id + " (tap to show it whole)"); b.setAttribute("aria-expanded", "false"); }
  b.onclick = () => {
    const whole = b.textContent === short;
    b.textContent = whole ? id : short;
    if (b.setAttribute) b.setAttribute("aria-expanded", String(whole));
    layoutAt = performance.now();
  };
  return b;
}
// A URL broken only after its slashes and dots, so it wraps at a segment, not mid-word.
function wrapped(cls, text) {
  const e = el("div", cls);
  for (const part of String(text).split(/(?<=[/.?&])/)) { e.append(document.createTextNode(part)); e.append(el("wbr")); }
  return e;
}
function fillMeta(meta, p) { meta.replaceChildren(document.createTextNode(p.id + " \u00b7 zone " + strip(p.zone) + " \u00b7 run "), idEl(p.run)); }
// What a request wants to do, as a verb (docs/explanation/console-design.md): from its method, or
// git's service for a push or a fetch.
function verb(p) {
  // git's own words only for the methods git uses (#715 review): a DELETE to a git path is a delete.
  const m = String(p.method).toUpperCase();
  if ((m === "GET" || m === "POST") && /git-receive-pack$|service=git-receive-pack/.test(p.path || "")) return "push code to";
  if ((m === "GET" || m === "POST") && /git-upload-pack$|service=git-upload-pack/.test(p.path || "")) return "fetch code from";
  return ({ GET: "read", HEAD: "read", OPTIONS: "read", POST: "send data to", PUT: "change", PATCH: "change", DELETE: "delete" })[String(p.method).toUpperCase()] || strip(p.method);
}
// Methods as the verbs a person would use: [GET, HEAD, POST] is "read and send data to".
function verbsOf(methods) {
  const v = [];
  for (const m of methods && methods.length ? methods : ["GET"]) { const w = verb({ method: m, path: "" }); if (!v.includes(w)) v.push(w); }
  return v.length > 1 ? v.slice(0, -1).join(", ") + " and " + v[v.length - 1] : v[0];
}
// The "Where" of a request: its host, its path quieter and wrapped at its slashes.
function where(p) {
  const d = el("div", "where");
  d.append(el("span", "host", strip(p.host)));
  if (p.path && p.path !== "/") d.append(wrapped("path", strip(p.path) + (p.scope_prefix ? "\u2026" : "")));
  if (p.scope_prefix) d.append(el("div", "meta", "and every page under it"));
  return d;
}
// A labelled field of a card: its label and its value (text or an element).
function field(dl, label, value, cls) {
  const dt = el("dt", "", label), dd = el("dd", cls || "");
  if (typeof value === "string") dd.textContent = value; else dd.append(value);
  dl.append(dt, dd);
  return dd;
}
// Who asks: the agent and its zone, verified (#574, item 5), or said plainly when it isn't.
function whoAsks(id) {
  const w = el("span", "who-ask");
  if (id.verified) {
    // The agent by name; its full identity behind a tap: a real button, focusable, saying whether it is shown.
    const name = el("button", "idname", strip(id.agent));
    name.type = "button";
    const idline = el("div", "idline", strip(id.id));
    idline.hidden = true;
    name.title = "Show its identity";
    name.setAttribute("aria-expanded", "false");
    name.onclick = () => {
      idline.hidden = !idline.hidden;
      name.setAttribute("aria-expanded", String(!idline.hidden));
      layoutAt = performance.now(); // the line moves the buttons below it
    };
    w.append(el("span", "ok", "\u2713 "), name, document.createTextNode(" \u00b7 zone " + strip(id.zone)), idline);
    return [w, true];
  }
  if ((id.error || "").startsWith("no identity was issued")) { w.append(document.createTextNode("a program (it has no agent identity)")); return [w, true]; }
  w.append(el("span", "bad", "We can't confirm which agent this is (" + strip(id.error || "unknown") + "). Only Don't allow is offered."));
  return [w, false];
}
function fillMeta(meta, p) { meta.replaceChildren(document.createTextNode(p.id + " \u00b7 zone " + strip(p.zone) + " \u00b7 run "), idEl(p.run)); }
function pendingCard(s, p) {
  const key = JSON.stringify([p.risk, p.method, p.host, p.path, p.scope_prefix, p.reason, p.identity, p.attribution, p.zone, p.run, p.lease, p.claims, p.once_terms]);
  const had = cards.get(p.id);
  if (had && had.key === key) { had.age.textContent = rel(p.created_at, s.now); return had.node; }
  // Labelled fields (docs/explanation/console-design.md): who, wants to, where, why, risk; then the
  // choices; the rest (on whose behalf, who in the box asked, the exact request, the ids) under Details.
  const c = el("div", "card req"); c.dataset.id = p.id;
  const tone = riskClass(p.risk);
  const head = el("div", "req-head");
  const age = timeEl(p.created_at, rel(p.created_at, s.now)); age.className = "age";
  head.append(el("span", "risk " + tone, riskWords(p.risk)), age);
  c.append(head);
  const a = asks(p);
  const dl = el("dl", "fields");
  const [who, idOk] = whoAsks(p.identity || {});
  field(dl, "Who", who);
  // The verb, and always the exact method beside it (#715 review): a verb alone could mislead.
  if (a.internal) field(dl, "Wants to", a.what.charAt(0).toLowerCase() + a.what.slice(1), "said");
  else { field(dl, "Wants to", verb(p) + " (" + strip(p.method) + ")", "said"); field(dl, "Where", where(p)); }
  // What the agent chose, quoted and labelled as its words (#709, #715 review); text wicket wrote
  // whole, labelled as wicket's.
  for (const [label, text] of a.said) field(dl, label + (label === "Why" ? "" : ", as the agent says"), "\u201c" + text + "\u201d", label === "Why" ? "why" : "asked");
  if (a.wicket) field(dl, "wicket says", a.wicket, "why");
  c.append(dl);
  // How far a grant reaches stays on the card (#709 review); who in the box asked is detail.
  c.append(renderWho(p.attribution || [], "warnings"));
  const more = el("details", "more req-more");
  more.append(el("summary", "", "Details"));
  const id = p.identity || {};
  if (id.verified) more.append(el("div", "chain", "On behalf of: " + (id.acting_for || []).map(strip).join(" \u2192 ")));
  more.append(el("div", "mono raw", strip(p.method + " " + p.host + p.path) + " \u00b7 risk class " + riskCode(p.risk)));
  if (a.mixed) more.append(el("div", "meta", "The request's text, with the agent's words in it: \u201c" + a.mixed + "\u201d"));
  more.append(renderWho(p.attribution || [], "list"));
  const meta = el("div", "meta");
  fillMeta(meta, p);
  more.append(meta);
  const b = el("div", "buttons ladder");
  // The first button's words are the server's terms for it (`once_terms`): a git push is granted
  // as a window whatever is picked, and the card mustn't say otherwise.
  const ot = p.once_terms || { uses: 1, ttl_secs: 600 };
  const window_ = ot.uses !== 1;
  const onceLabel = window_ ? "Allow for " + span(ot.ttl_secs) + " (any number of uses)" : a.internal ? "Allow" : "Allow once (expires in " + span(ot.ttl_secs) + ")";
  const once = el("button", "approve", onceLabel); once.onclick = () => act("approve", { id: p.id, uses: 1, ttl_secs: 600 });
  const hour = el("button", "", "Allow for 1 hour (any number of uses)"); hour.onclick = () => act("approve", { id: p.id, unlimited: true, ttl_secs: 3600 });
  const deny = el("button", "deny apart", "Don't allow"); deny.onclick = () => act("deny", { id: p.id });
  if (!idOk) { once.disabled = true; hour.disabled = true; }
  // Only the steps the server grants: a push is one window, R3 and R4 one use, wicket's own kinds one
  // decision (#597 re-review, #621). A push to a host that isn't github.com can be R2, but it is still
  // granted as the window: no hour button, which would promise what the grant doesn't give.
  if (!idOk) b.append(deny);
  else if (a.internal) b.append(once, deny);
  else if (window_ || p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible") {
    b.append(once, deny);
    more.append(el("div", "note", window_ ? "A push is allowed as one window: any number of requests for " + span(ot.ttl_secs) + ", for its ref discovery and upload." :
      "This kind is allowed one request at a time."));
  } else b.append(once, hour, deny);
  c.append(b, more);
  cards.set(p.id, { key, node: c, meta, age });
  return c;
}

// How many decisions wait (#650): in the tab's title, the heading, the section nav and, where the
// browser has one, the installed app's badge; and how many health alerts, beside Health in the nav.
let shownCount = -1;
function renderCounts(waiting, alerts) {
  // Each count with its link's accessible name: "Waiting, 10 items" (#698 review).
  const set = (id, v) => {
    const e = document.getElementById(id);
    if (!e) return;
    e.textContent = v ? String(v) : ""; e.hidden = !v;
    const a = e.parentNode;
    if (a && a.setAttribute && a.dataset) { if (v) a.setAttribute("aria-label", a.dataset.label + ", " + plural(v, a.dataset.noun || "item")); else a.removeAttribute("aria-label"); }
  };
  set("nav-waiting", waiting);
  set("nav-health", alerts);
  const h = document.getElementById("waiting-h");
  if (h) h.textContent = waiting ? "Needs you (" + waiting + ")" : "Needs you";
  document.title = waiting ? "(" + waiting + ") wicket" : "wicket";
  if (waiting === shownCount) return;
  shownCount = waiting;
  try {
    if (typeof navigator !== "undefined" && navigator.setAppBadge) (waiting ? navigator.setAppBadge(waiting) : navigator.clearAppBadge()).catch(() => {});
  } catch (e) { /* no badge here */ }
}

function renderPending(s) {
  pendingLoaded = true;
  const box = document.getElementById("pending");
  const live = new Set(s.pending.map(p => p.id));
  for (const id of [...cards.keys()]) if (!live.has(id)) cards.delete(id);
  const nodes = s.pending.length ? s.pending.map(p => pendingCard(s, p)) : [el("div", "empty", "Nothing is waiting for you.")];
  const same = nodes.length === box.children.length && nodes.every((n, i) => n === box.children[i]);
  if (same) return;
  const empty = !s.pending.length && box.children.length === 1 && box.children[0].className === "empty";
  if (empty) return;
  box.replaceChildren(...nodes);
  layoutAt = performance.now();
  if (openId) for (const [k, c] of cards) c.node.className = "card req" + (k === openId ? " opened" : "");
}

// Rows kept across polls (#574): each by its id and content, rebuilt only when it changed, and the
// list replaced only when something did. Then the layout moved: taps are ignored for a moment, as
// on the pending cards (`settled`), so a tap can't land on a row that just moved under it.
const keyed = new Map();
function renderKeyed(id, rows, f, emptyText) {
  const box = document.getElementById(id);
  const had = keyed.get(id) || new Map(), now = new Map();
  const nodes = rows.map(r => {
    const key = JSON.stringify(r), old = had.get(r.id);
    const node = old && old.key === key ? old.node : f(r);
    now.set(r.id, { key, node });
    return node;
  });
  keyed.set(id, now);
  if (!rows.length) {
    if (!(box.children.length === 1 && box.children[0].className === "empty")) box.replaceChildren(codeText("div", "empty", emptyText));
    return;
  }
  if (nodes.length === box.children.length && nodes.every((n, i) => n === box.children[i])) return;
  box.replaceChildren(...nodes);
  layoutAt = performance.now();
}
// A signed action from a row's button, once the layout has settled.
const signedSettled = body => {
  if (!settled()) { toast("The list just changed: check the row and tap again."); return; }
  signed(body);
};

function renderRows(id, rows, f, emptyText) {
  const box = document.getElementById(id); box.replaceChildren();
  if (!rows.length) { box.append(codeText("div", "empty", emptyText)); return; }
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

// One record of activity as a sentence (#646): its local time, a tag for its kind, then what
// happened. Every kind wicket writes that an operator acts on has words; anything else is its kind
// and run, so nothing is dropped.
const num = n => Number(n || 0).toLocaleString("en-US");
// Who did it: an operator by their passkey's name ("passkey:phone" is "phone"), signed or not.
const byName = x => strip(String(x || "").replace(/^passkey:/, ""));
// Who decided, from the decider's label (#715 review): never "you", since another operator, a parent
// agent (`agent:<run>`) or a standing capacity grant (`capacity-grant:<id>`) may have.
function decider(label) {
  const s = String(label || "");
  if (s.startsWith("agent:")) {
    // An agent run names itself by its agent; a program run, which has none, by its run id.
    const run = s.slice(6), n = runName(run);
    return (n === "a program" ? "run " + shortText(strip(run)) : n) + " (a parent agent)";
  }
  if (s.startsWith("capacity-grant:")) return "capacity grant " + strip(s.slice(15));
  return s ? byName(s) : "?";
}
const by = b => b.by ? " by " + decider(b.by) + (b.signed ? ", signed with a passkey" : "") : "";
function logLine(op, tag, tone, text, extra) {
  const d = el("div", "logline");
  d.dataset.cat = /^(decision|standing|grant|capacity|lease)/.test(op.kind) ? "decisions" : /^(run|identity|session|operator\.message)/.test(op.kind) || (op.body || {}).kind === "llm" || (op.body || {}).kind === "box" ? "agents" : /^node/.test(op.kind) ? "servers" : "other";
  const t = el("span", "text", text);
  d.append(op.ts ? timeEl(op.ts, clock(op.ts)) : el("span"), el("span", "tag " + (tone || ""), tag), t);
  if (extra) t.append(document.createTextNode(" "), extra);
  return d;
}
// An agent run by its agent's name where the latest list knows it; its id otherwise.
function runName(id) {
  const x = ((lastState && lastState.runs) || []).find(r => r.id === id);
  return x ? (x.agent ? strip(x.agent) : "a program") : strip(id);
}
function line(op) {
  const b = op.body || {};
  const r = op.run ? runName(op.run) : "";
  const eg = egressOf(op);
  if (eg) {
    const [x, where] = eg;
    const outcome = String(x.outcome || "?");
    const tone = outcome === "allow" || outcome === "spliced" ? "ok" : outcome === "pending" ? "pend" : "blocked";
    let why = null;
    if (op.run) {
      why = el("button", "link", "why?");
      why.onclick = () => { const box = why.parentNode.parentNode.nextSibling; if (box && box.className === "explained") { box.hidden = !box.hidden; return; }
        const nb = el("div", "explained"); why.parentNode.parentNode.after ? why.parentNode.parentNode.after(nb) : null; showExplain(op.seq, nb); };
    }
    const said = ({ allow: "allowed", spliced: "allowed", pending: "waiting", forbidden: "blocked", denied: "blocked", deny: "blocked" })[outcome] || outcome;
    const ln = logLine(op, said, tone, (r ? r + ": " : "") + verb(x) + " " + strip(x.host + x.path + where), why);
    ln.dataset.cat = outcome === "allow" || outcome === "spliced" ? "allowed" : "blocked";
    return ln;
  }
  switch (op.kind === "op" ? "op." + b.kind : op.kind) {
    case "op.llm": return logLine(op, "model", "", strip(b.model || "?") + " request #" + num(b.requests) + " \u2192 " + strip(b.status) +
      " \u00b7 " + num(b.input_tokens) + " in / " + num(b.output_tokens) + " out tokens" + (r ? " \u00b7 " + r : ""));
    case "op.box": return logLine(op, "box", "pend", strip(b.what) + ": " + strip(b.detail) + (r ? " \u00b7 " + r : ""));
    case "decision": return logLine(op, b.decision === "approve" ? "allowed" : "refused", b.decision === "approve" ? "ok" : "blocked", strip(b.request) + by(b));
    case "decision.refused": return logLine(op, "refused", "blocked", "a decision (" + strip(b.decision) + ") on " + strip(b.target) + " was refused" +
      (b.by ? " for " + strip(b.by) : "") + ": " + strip(b.why));
    case "grant.revoked": return logLine(op, "revoked", "", "grant " + strip(b.grant) + " revoked" + by(b));
    case "standing.revoked": return logLine(op, "revoked", "", "standing reach " + strip(b.standing) + (b.rule ? " (" + ruleText(b.rule) + ")" : "") + " revoked" + by(b));
    case "capacity.requested": return logLine(op, "capacity", "pend", "capacity asked for" + (b.principal ? " by " + principalName(b.principal) : "") +
      (b.ask ? ": " + strip(b.ask) : "") + (b.lifetime_secs ? " for " + span(b.lifetime_secs) : "") + (b.request ? " (" + strip(b.request) + ")" : ""));
    case "lease.requested": return logLine(op, "lease", "pend", "lease " + strip(b.lease) + " asked for" + (b.spec && b.spec.plan ? ": " + strip(b.spec.plan) + " in " + strip(b.spec.region) : "") +
      (b.hourly_cap_usd_micros ? ", at most " + microUsd(b.hourly_cap_usd_micros) + "/h" : "") + (b.duration_secs ? " for " + span(b.duration_secs) : "") +
      (b.request ? " (" + strip(b.request) + ")" : "") + (r ? " \u00b7 " + r : ""));
    case "operator.passkey_added": return logLine(op, "passkey", "", "passkey " + strip(b.name) + " added via " + strip(b.via));
    case "run.start": return logLine(op, "start", "", r + " started: agent " + strip(b.agent) + " in zone " + strip(b.zone));
    // operator.message is from before `wicket say` was removed (#198); prompts are session.prompt.
    case "operator.message": case "session.prompt": return logLine(op, "message", "", "a message of " + plural(b.chars || 0, "character") + " to " + r + by(b) + (b.via ? " in the " + strip(b.via) : ""));
    case "run.fence_released": return logLine(op, "released", "blocked", r + " released from server " + strip(b.node) + by(b) + ", though its box may still be running there: " + strip(b.why));
    case "run.fence_release_failed": return logLine(op, "still held", "blocked", r + " is still held: its release from server " + strip(b.node) + " couldn't be made: " + strip(b.error));
    case "identity.revoked": return logLine(op, "stopped", "blocked", r + " stopped" + by(b) + ": " + strip(b.reason));
    case "run.console_start": return logLine(op, "started", "", r + " started from " + strip(b.manifest) + " by " + byName(b.by) + ", signed with a passkey");
    case "run.exit_cause": return logLine(op, "failed", "blocked", r + " failed (exit status " + strip(b.code) + "): " + strip(b.cause));
    case "run.end": return logLine(op, "finished", b.cause ? "blocked" : "", r + " " + (b.status === "exited" ? "finished" : strip(b.status)) + " after " + plural(b.model_requests || 0, "model call"));
  }
  if (op.kind === "node.audit") {
    let inner = "";
    try { inner = String((JSON.parse(b.body) || {}).kind || ""); } catch (e) { /* not JSON */ }
    return logLine(op, "node", "", "node " + strip(b.node) + ": " + (inner ? strip(inner) : "a record") + (r ? " \u00b7 " + r : ""));
  }
  return logLine(op, "record", "", strip(op.kind) + (r ? " \u00b7 " + r : ""));
}

// A node's latest health report (#377): disk, memory, what went wrong, and what is alerted.
function healthRow(n) {
  // The row (name, summary) and its alerts under it, each a line of its own (#574, B7): inside the
  // flex row they were squeezed into side columns.
  const w = el("div", "hrow");
  const d = el("div", "row");
  d.append(el("span", "mono", strip(n.node)));
  d.append(serverText("span", (n.alerts || []).length ? "blocked" : "", n.summary + " · reported " + whenMs(n.received_ms)));
  w.append(d);
  for (const a of n.alerts || []) w.append(serverText("div", "blocked", "! " + a));
  return w;
}

// The state store's sync and the audit export's progress (#635), as `wicket state check` and
// `wicket audit export --status` compute them: a row for the ledger's stream, one per audit sink,
// each with its last error under it. A span in seconds, short.
const secs = s => { s = Math.max(0, Math.round(s || 0)); return s < 120 ? s + " s" : s < 7200 ? Math.floor(s / 60) + " min" : s < 172800 ? Math.floor(s / 3600) + " h" : Math.floor(s / 86400) + " d"; };
function stateStoreRows(p, nowMs) {
  const out = [];
  const row = (name, cls, text, err) => {
    const w = el("div", "hrow");
    const d = el("div", "row");
    d.append(el("span", "mono", name));
    d.append(codeText("span", cls, text));
    w.append(d);
    if (err) w.append(el("div", "blocked", "! " + err));
    return w;
  };
  // What is alerted (and pushed, if notifications are on) first, so a sink past its threshold
  // doesn't look like one a few records behind; then whether these rows are current.
  for (const a of p.alerts || []) out.push(serverText("div", "blocked", "! " + a));
  if (p.not_read_yet) out.push(el("div", "pend", "! not read yet: the console hasn't managed a first read of the state store"));
  else if (p.stale) out.push(el("div", "pend", "! not checked for " + secs((nowMs - (p.read_ms || 0)) / 1000) + ": these rows may be out of date"));
  const st = p.stream;
  if (st) {
    let text = strip(st.endpoint) + " (" + strip(st.bucket) + ") \u00b7 ledger " + strip(st.state);
    if (st.last_sync_ms) text += " \u00b7 last sync " + secs((nowMs - st.last_sync_ms) / 1000) + " ago";
    else if (st.behind_secs !== null && st.behind_secs !== undefined) text += " \u00b7 no sync yet in " + secs(st.behind_secs);
    const cls = st.state === "streaming" ? "" : st.state === "starting" ? "pend" : "blocked";
    // An error is shown while the stream isn't streaming, or if it came after the last sync: an
    // old one, recovered from, isn't news.
    const live = st.error && (st.state !== "streaming" || (st.error_ms || 0) > (st.last_sync_ms || 0));
    const err = live ? "last error" + (st.error_ms ? " " + secs((nowMs - st.error_ms) / 1000) + " ago" : "") + ": " + strip(st.error) : null;
    out.push(row("Record backup", cls, text, err));
  }
  for (const a of p.audit || []) {
    let text = a.behind ? a.behind + " record" + (a.behind === 1 ? "" : "s") + " behind (oldest " + secs(a.behind_secs) + ")" : "caught up";
    // A jsonl sink to stdout is fed only by `wicket audit export` in the foreground: behind is expected.
    if (a.manual) text += " (manual: fed only by `wicket audit export`)";
    text += " at " + a.seq + " of " + a.head + " \u00b7 last checkpoint " + (a.checkpoint_at ? secs(nowMs / 1000 - a.checkpoint_at) + " ago" : "never");
    out.push(row("Activity export to " + strip(a.sink), a.error ? "blocked" : a.behind && !a.manual ? "pend" : "", text, a.error ? "last error: " + strip(a.error) : null));
  }
  // An error already alerted on (the config alert quotes it) isn't said twice.
  for (const e of p.errors || []) if (!(p.alerts || []).some(a => a.startsWith(e))) out.push(serverText("div", "blocked", "! " + e));
  return out;
}

// A fenced run (#690): its box may still be running on a node that is revoked or no longer enrolled,
// so its agent isn't woken. Released (signed, with a reason) from a form in its own row: kept across
// polls while the row is unchanged, so what is typed survives, and it can only release this run.
function fencedRow(x) {
  const f = x.fence || {};
  const d = el("div", "lease");
  const head = el("div", "run-head");
  head.append(el("span", "run-name mono", strip(x.id)));
  const until = el("span", "meta");
  if (f.fenced_until_ms) until.append(document.createTextNode("fenced until "), timeEl(f.fenced_until_ms / 1000));
  else until.append(document.createTextNode("fenced until its node confirms the box stopped"));
  head.append(until);
  const node = el("div", "meta");
  node.append(document.createTextNode("node " + strip(f.node) + " (" + strip(f.node_status) + ")"));
  if (f.node_seen_ms) node.append(document.createTextNode(" \u00b7 last reported "), timeEl(f.node_seen_ms / 1000));
  else node.append(document.createTextNode(" \u00b7 never reported"));
  const form = el("div", "stack");
  form.hidden = true;
  const label = el("label", "meta", "Release " + strip(x.id) + "'s fence: its agent can be woken and the run ended, while its box may still be running on node " +
    strip(f.node) + ". Only if that node will never run it again. Say why (it goes in the activity log):");
  const text = el("textarea");
  const go = el("button", "deny", "Release");
  go.onclick = () => {
    if (!text.value.trim()) { toast("Say why: the reason goes in the activity log."); return; }
    signed({ action: "release_fence", run: x.id, reason: text.value }, () => { form.hidden = true; text.value = ""; });
  };
  const cancel = el("button", "", "Cancel");
  cancel.onclick = () => { form.hidden = true; text.value = ""; };
  const fb = el("div", "buttons"); fb.append(go, cancel);
  form.append(label, text, fb);
  const open = el("button", "deny", "Release\u2026");
  open.onclick = () => { form.hidden = false; text.focus && text.focus(); };
  const acts = el("div", "buttons"); acts.append(open);
  d.append(head, node, el("div", "meta", strip(f.why)), acts, form);
  return d;
}

// A node from `wicket node create` (#294): past its lease it is released by the reconciler, unless
// a run still holds it, which is a warning until renewals exist (#56).
function placedRow(p) {
  // The name and when its lease ends; the UUID quiet on a line of its own (#649).
  const d = el("div", "lease");
  const head = el("div", "run-head");
  head.append(el("span", "run-name mono", strip(p.name)));
  if (!p.past_lease) { const e = el("span", "meta"); e.append(document.createTextNode("lease ends "), timeEl(p.lease_until)); head.append(e); }
  d.append(head, el("div", "meta mono quiet", strip(p.id)));
  if (p.past_lease && p.held_by) {
    const w = el("div", "callout warn");
    w.append(document.createTextNode("Lease ended "), timeEl(p.lease_until), document.createTextNode("; still billing: run " + strip(p.held_by) + " holds it. Release it on the host:"));
    w.append(el("code", "block", "wicket node release " + strip(p.id)), copyButton("wicket node release " + strip(p.id)));
    d.append(w);
  } else if (p.past_lease) {
    const w = el("div", "meta");
    w.append(document.createTextNode("Lease ended "), timeEl(p.lease_until), document.createTextNode("; released at the reconciler's next pass."));
    d.append(w);
  }
  return d;
}

// Standing capacity grants (#256): a principal's `wicket node create` within one is approved at once
// and audited against it; beyond every one, it waits here as a request. Issuing and renewing a grant
// widen what may be spent, so each is signed with the passkey; revoking one only narrows, so it needs
// only the session.
function capacityRow(g) {
  const t = g.terms || {}, u = g.used || {}, left = g.left || {};
  const d = el("div", "row cap");
  const head = el("div", "run-head");
  const who = principalEl(g.principal);
  head.append(who, el("span", "mono quiet", strip(g.id)));
  const nodes = n => plural(Number(n) || 0, "node");
  const what = el("div", "meta", "Allows: " + nodes(t.nodes) + " at once of " + (t.plans || []).map(strip).join(" or ") + " in " + (t.regions || []).map(strip).join(", ") +
    ", up to " + money(t.hourly_usd) + "/h and " + money(t.daily_usd) + " a day");
  const used = el("div", "meta", "Used today: " + nodes(u.nodes) + ", " + money(u.hourly_usd) + "/h, " + money(u.daily_usd));
  const rest = el("div", "meta", "Left today: " + nodes(left.nodes) + ", " + money(left.hourly_usd) + "/h, " + money(left.daily_usd));
  const ends = el("div", "meta");
  ends.append(document.createTextNode("Ends "), timeEl(g.expires_at), document.createTextNode(" \u00b7 granted by " + strip(g.decided_by)));
  const b = el("div", "buttons");
  const renew = el("button", "approve", "Renew");
  renew.onclick = () => signed({ action: "capacity_renew", id: g.id, ttl_secs: capacityTtl() });
  const revoke = revokeButton(b, "Revoke capacity grant " + strip(g.id) + "? Nothing more is approved under it, from now.", async () => {
    try { toast((await post("/api/capacity/revoke", { id: g.id })).ok); } catch (e) { toastError(e); }
    refresh();
  });
  b.append(renew, revoke);
  d.append(head, what, used, rest, ends, b);
  return d;
}
// Revoke on a capacity grant or a standing rule (#640): unsigned, since it only narrows, but asked in
// the page first, and set apart from Renew. The question replaces the row's buttons until answered.
function revokeButton(box, question, go) {
  const revoke = el("button", "deny apart", "Revoke\u2026");
  revoke.onclick = () => {
    if (!settled()) { toast("The list just changed: check the row and tap again."); return; }
    const keep = [...box.children];
    const q = el("div", "callout warn ask", question);
    const yes = el("button", "deny", "Revoke");
    const no = el("button", "", "Cancel");
    // The question moved the row: a second tap of a double tap mustn't land on its Revoke.
    yes.onclick = async () => { if (!settled()) return; yes.disabled = true; await go(); };
    no.onclick = () => { box.replaceChildren(...keep); };
    box.replaceChildren(q, yes, no);
    layoutAt = performance.now();
  };
  return revoke;
}

// Standing reach (#572). A rule as a manifest would carry it.
function ruleText(r) {
  r = r || {};
  return "{ host: " + strip(r.host) + ", methods: [" + (r.methods || []).map(strip).join(", ") + "], paths: [" +
    (r.paths || []).map(p => "'" + strip(p) + "'").join(", ") + "]" + (r.allow_dangerous ? ", allow_dangerous: true" : "") + " }";
}
// An agent's ask: the rule, who asked and why, the ledger's evidence, and what it allows beyond it.
// Approved once (signed): as asked or narrowed to the evidence, for the agent or its zone, 30 days.
function standingAskRow(a) {
  // An agent's ask to be always allowed something (#572): the same card as a request, with its
  // evidence, and the Always choices narrowest first.
  const d = el("div", "card req always");
  const e = a.evidence || {};
  const r = a.rule || {};
  const agent = String(a.principal || "").split("/a/").pop();
  const head = el("div", "req-head");
  // The pill says only what the rule says (#715 review): dangerous requests included or not, and its
  // methods. Whether a POST changes data depends on the API, so it isn't guessed here.
  head.append(el("span", "risk " + (r.allow_dangerous ? "r4" : ""),
    (r.allow_dangerous ? "Includes requests that can't be undone: " : "") + (r.methods || []).map(strip).join(", ")),
    timeEl(a.created_at, rel(a.created_at)));
  head.children[head.children.length - 1].className = "age";
  d.append(head);
  const dl = el("dl", "fields");
  const who = el("span"); who.append(el("strong", "", strip(agent)), document.createTextNode(" \u00b7 zone " + strip(a.zone))); who.title = strip(a.principal);
  field(dl, "Who", who);
  field(dl, "Wants to", "always be allowed to " + verbsOf(r.methods), "said");
  const w = el("div", "where"); w.append(el("span", "host", strip(r.host)), el("div", "path", (r.paths || []).map(strip).join("  ")));
  field(dl, "Where", w);
  field(dl, "Why", "\u201c" + strip(a.reason) + "\u201d", "why");
  field(dl, "So far", plural(e.requests || 0, "request") + " like this in " + plural(e.days || 0, "day") + "; allowed " + (e.granted || 0) +
    (e.denied ? ", refused " + e.denied : "") + (e.undecided ? ", " + e.undecided + " not decided" : ""));
  d.append(dl);
  for (const x of (a.beyond || [])) d.append(el("div", "callout warn", "Wider than what it used: " + strip(x)));
  const b = el("div", "buttons ladder");
  // The narrowest choice first, and the default; the widest (a whole zone) marked as such.
  const narrow = el("button", a.narrowed ? "approve" : "", a.narrowed ? "Always: only what it used" : "Always: only what it used (nothing to narrow to)");
  narrow.onclick = () => signedSettled({ action: "standing_approve", id: a.id, for: "agent", narrow: true });
  narrow.disabled = !a.narrowed;
  const asAsked = el("button", a.narrowed ? "" : "approve", "Always: as asked");
  asAsked.onclick = () => signedSettled({ action: "standing_approve", id: a.id, for: "agent" });
  const zone = el("button", "deny", "Always, for every agent in zone " + strip(a.zone));
  zone.onclick = () => signedSettled({ action: "standing_approve", id: a.id, for: "zone" });
  const deny = el("button", "deny apart", "Don't allow");
  deny.onclick = () => signedSettled({ action: "standing_deny", id: a.id });
  b.append(narrow, asAsked, zone, deny);
  d.append(b, el("div", "meta", "\u201cAlways\u201d lasts 30 days, and you can remove it in Settings."));
  const more = el("details", "more req-more");
  more.append(el("summary", "", "Details"));
  if (a.narrowed) more.append(el("div", "meta", "Only what it used: methods " + (a.narrowed.methods || []).map(strip).join(", ") + ", paths " + (a.narrowed.paths || []).map(strip).join(", ")));
  more.append(el("div", "meta", "Methods: " + (r.methods || []).map(strip).join(", ") + (r.allow_dangerous ? " \u00b7 dangerous requests too (R3, R4)" : "")));
  more.append(el("div", "meta", "Paths: " + (r.paths || []).map(strip).join(", ")));
  more.append(el("div", "meta", "Asked by " + strip(agent) + " (zone " + strip(a.zone) + ") \u00b7 for its later runs with this zone definition" +
    (a.zone_digest ? " (" + strip(a.zone_digest).slice(0, 12) + "\u2026)" : "")));
  more.append(el("div", "meta", "Evidence: " + e.granted + " granted of " + e.requests + " blocked request(s) it covers in the last 14 days (" +
    e.denied + " denied, " + e.undecided + " undecided), in " + e.runs + " run(s) on " + e.days + " day(s)" +
    ((e.ops || []).length >= 10 ? ", the 10 most asked:" : (e.ops || []).length ? ":" : "")));
  for (const o of (e.ops || [])) more.append(el("div", "meta mono", o.count + " \u00d7 " + strip(o.method) + " " + strip(o.path) + " (" + o.granted + " granted)"));
  if (e.own_asks) more.append(el("div", "meta", "and " + e.own_asks + " ask(s) ahead of its own, not counted as evidence"));
  more.append(el("div", "meta", "standing reach " + strip(a.id) + " \u00b7 asked " + when(a.created_at)));
  d.append(more);
  return d;
}
// An approved rule: who it is for, when it lapses; renewed (signed, 30 days) or revoked (session).
function standingRuleRow(r) {
  const d = el("div", "row cap");
  const head = el("div");
  const rr = r.rule || {};
  const to = r.for === "zone" ? "every agent in zone " + strip(r.zone) : principalName(r.principal);
  head.append(r.for === "zone" ? el("span", "run-name", to) : principalEl(r.principal), el("span", "", " may " + verbsOf(rr.methods) + " "), el("span", "mono", strip(rr.host)));
  // On the row, not only in its title (#715 review): this rule allows requests that can't be undone.
  if (rr.allow_dangerous) head.append(document.createTextNode(" "), el("span", "risk r4", "including requests that can't be undone"));
  head.title = "standing reach " + strip(r.id) + ": " + ruleText(r.rule);
  const until = r.expires_at ? (r.live ? "ends " + when(r.expires_at) : "lapsed " + when(r.expires_at)) : "until revoked";
  const b = el("div", "buttons");
  const renew = el("button", "approve", "Renew (30 days)");
  renew.onclick = () => signedSettled({ action: "standing_renew", id: r.id });
  renew.disabled = !r.live;
  const revoke = revokeButton(b, "Revoke standing reach " + strip(r.id) + "? Runs it allows lose it at once.", async () => {
    try { toast((await post("/api/standing/revoke", { id: r.id })).ok); } catch (e) { toastError(e); }
    refresh();
  });
  b.append(renew, revoke);
  d.append(head, el("div", "meta", (rr.paths || []).map(strip).join("  ") + " \u00b7 " + until + " \u00b7 allowed by " + strip(r.decided_by)), b);
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
  box.append(codeText("div", "note", "Issue a capacity grant: what a principal may lease with `wicket node create` without asking each time."),
    field("principal", "To", "unix/alex, passkey/laptop or spiffe://…"),
    field("plans", "Plans", "vc2-1c-2gb, vc2-2c-4gb"), field("regions", "Regions", "lhr"),
    field("hourly", "Most per hour, all its nodes ($)", "0.05"), field("daily", "Most a day ($)", "1.00"),
    field("nodes", "Nodes at once", "2", "number"), field("hours", "Hours (at most 24)", "8", "number"), b);
  capInputs.hours.value = "8";
}

// A run: who, where, its state and times, its pages; an ACP agent's session opens on its own page,
// where prompts are sent (#198).
function renderRun(s, x, page) {
  // The agent first, its zone and state; the run id quieter under it (#641). A program run has no agent.
  const d = el("div", "row run");
  const left = el("div");
  const head = el("div", "run-head");
  const name = x.agent ? strip(x.agent) : "program run";
  if (page) head.append(el("h2", "run-name", name));
  else { const a = el("a", "run-name", name); a.href = "#agent/" + encodeURIComponent(x.id); head.append(a); }
  head.append(el("span", "meta", " \u00b7 zone " + strip(x.zone)));
  const status = x.revoked ? "revoked" : String(x.status || "");
  const tone = ({ running: "good", revoked: "bad", failed: "bad", hibernated: "info" })[status] || "";
  const waiting = x.waiting !== undefined ? x.waiting : ((s && s.pending) || []).some(p => p.run === x.id);
  head.append(el("span", "pill " + (waiting ? "warn" : tone), waiting ? "waiting for you" : ({ running: "working", exited: "finished", revoked: "stopped", hibernated: "asleep" })[status] || strip(status)));
  left.append(head);
  const meta = el("div", "meta");
  meta.append(relEl(x.started_at, "started ", s.now));
  if (x.ended_at) meta.append(document.createTextNode(" \u00b7 "), relEl(x.ended_at, "ended ", s.now));
  meta.append(document.createTextNode(" \u00b7 "), idEl(x.id));
  left.append(meta);
  const links = el("div", "links");
  // An ACP run's live session (#327): its own page, opened with a passkey there.
  if (x.acp && x.status === "running" && !x.revoked) {
    const a = el("a", "session", "Live session");
    a.href = "/session?run=" + encodeURIComponent(x.id);
    links.append(a);
  }
  // A remote session (#169): where the owner drives it, in the vendor's app.
  if (x.remote_url && x.remote_url.startsWith("https://")) {
    const a = el("a", "session", "Remote Control session \u2197");
    a.href = x.remote_url; a.target = "_blank"; a.rel = "noopener noreferrer";
    links.append(a);
  }
  if (!page) { const auth = el("a", "", "What it can reach \u203a"); auth.href = "#agent/" + encodeURIComponent(x.id); links.append(auth); }
  left.append(links);
  d.append(left);
  // A running agent can have its identity revoked, signed.
  if (page && x.status === "running" && x.has_identity && !x.revoked) {
    const acts = el("span", "acts");
    const rev = el("button", "deny", "Stop agent\u2026");
    rev.onclick = () => openRunForm("revoke", x.id);
    acts.append(rev); d.append(acts);
  }
  return d;
}

// An agent's page: its name, state and links, what it can reach (the authority view, #651), and what
// it did. Stop is the signed revoke, from here only.
function openAgent(run) {
  // A Stop form left open for another agent goes (#715 review): its submit would revoke that one.
  if (agentRun !== run) closeRunForm();
  agentRun = run;
  show("agent");
  renderAgentHead();
  showAuthority(run);
  renderAgentLog();
  if (typeof window !== "undefined" && window.scrollTo) window.scrollTo(0, 0);
}
function renderAgentHead() {
  const box = document.getElementById("agent-head");
  if (!box || view !== "agent") return;
  const x = ((lastState && lastState.runs) || []).find(r => r.id === agentRun);
  if (!x) { box.replaceChildren(el("h2", "", "Agent"), el("p", "note", "This agent run isn't in the latest list (only the 15 most recent are).")); return; }
  const key = JSON.stringify(x);
  if (box.dataset.key === key) return;
  box.dataset.key = key;
  const row = renderRun(lastState, x, true);
  box.replaceChildren(row);
}
function renderAgentLog() {
  const box = document.getElementById("agent-log");
  if (!box || view !== "agent") return;
  const mine = ((lastState && lastState.audit) || []).filter(op => op.run === agentRun).slice().reverse();
  // Rebuilt only when its records changed, so a line (and its "why?") stays put across polls.
  const key = agentRun + ":" + mine.map(op => op.seq).join(",");
  if (box.dataset.key === key) return;
  box.dataset.key = key;
  box.replaceChildren(...(mine.length ? mine.map(line) : [el("div", "empty", "Nothing recorded for it in the latest activity.")]));
}

// The revoke form: an in-page form (no browser dialogs), kept outside the runs list
// so the 2-second refresh doesn't wipe what the operator is typing.
function openRunForm(kind, run) {
  const f = document.getElementById("runform"), text = document.getElementById("runform-text");
  f.dataset.kind = kind; f.dataset.run = run;
  f.className = "card " + kind;
  // Named in the question, with its run, so the operator sees which agent they stop (#715 review).
  document.getElementById("runform-title").textContent =
    "Stop " + runName(run) + " (run " + strip(run) + ")? Its identity is revoked: its box stops and nothing it asks can be allowed. Say why (it goes in the activity log):";
  const go = document.getElementById("runform-go");
  go.textContent = "Stop agent";
  go.className = "deny";
  text.value = "revoked by the operator";
  f.hidden = false; text.focus();
}
function closeRunForm() {
  const f = document.getElementById("runform");
  if (!f) return;
  f.hidden = true; f.dataset.run = ""; document.getElementById("runform-text").value = "";
}
function submitRunForm(ev) {
  ev.preventDefault();
  const f = document.getElementById("runform"), text = document.getElementById("runform-text").value;
  // Only the agent whose page is open (#715 review): a form for another run is refused, not sent.
  if (!f.dataset.run || view !== "agent" || f.dataset.run !== agentRun) { closeRunForm(); toast("That form was for another agent; nothing was stopped. Open Stop agent… again.", true); return; }
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

// #711: the enrolment link a signed enrol_link returned, shown in the passkeys card until it expires
// (it lives only in this page: reloading drops it).
let enrolLink = null;
function showEnrolLink(j) { enrolLink = { link: String(j.link), until: Date.now() + (Number(j.expires_in_secs) || 0) * 1000 }; }
function renderOperator(s) {
  const box = document.getElementById("operator"); box.replaceChildren();
  for (const k of s.passkeys) { const d = el("div", "row"); d.append(el("span", "", "passkey: " + strip(k.name)), el("span", "mono", String(k.id).slice(0, 16) + "…")); box.append(d); }
  const b = el("div", "buttons");
  const out = el("button", "", "Sign out"); out.onclick = async () => { try { await post("/api/logout"); } catch (e) { /* signed out anyway */ } boot(); };
  const add = el("button", "", "Add a device"); add.onclick = () => signed({ action: "enrol_link" });
  b.append(add, out); box.append(b);
  if (enrolLink && enrolLink.until > Date.now()) {
    const d = el("div", "callout");
    d.append(el("div", "", "Open this on the new device (once, until " + new Date(enrolLink.until).toLocaleTimeString() + "):"),
      el("code", "block", enrolLink.link), copyButton(enrolLink.link));
    box.append(d);
  } else enrolLink = null;
  box.append(codeText("div", "note", "Adding a device makes a one-time link, signed with your passkey; the new device is you, with your authority. Or on the host: `wicket operator enrol-link`.", ["wicket operator enrol-link"]));
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
// The card itself is scrolled to, clear of the sticky header (#644); a request no longer waiting
// (decided on another device, or expired) is said to be, with where to look.
let pendingLoaded = false;
function openPending(id) {
  openId = id || "";
  for (const [k, c] of cards) c.node.className = "card req" + (k === openId ? " opened" : "");
  const card = openId && cards.get(openId);
  const target = card ? card.node : document.getElementById("waiting") || document.getElementById("pending");
  if (target && target.scrollIntoView) target.scrollIntoView({ block: "start" });
  if (openId && !card && pendingLoaded) {
    toast(strip(openId) + " is no longer waiting: it was decided or expired. Activity has what became of it.", false, true);
    openId = "";
  }
}
// Four views and an agent's page, by the address's hash, so the back button and a notification's
// link work: #inbox (the default), #agents, #agent/<run>, #activity, #settings. A notification's
// #pending/<id> opens the Inbox at that card; #health the Inbox's problems; #notifications Settings.
let view = "inbox", agentRun = "";
function show(v) {
  // Leaving the agent's page closes its Stop form (#715 review).
  if (v !== "agent") closeRunForm();
  view = v;
  for (const n of ["inbox", "agents", "agent", "activity", "settings"]) {
    const e = document.getElementById("view-" + n);
    if (e) e.hidden = n !== v;
  }
  const nav = document.getElementById("nav");
  if (nav && nav.querySelectorAll) for (const a of nav.querySelectorAll("a")) {
    const here = a.dataset.view === v || (v === "agent" && a.dataset.view === "agents");
    if (here) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
}
function fromHash() {
  const h = (typeof location !== "undefined" && location.hash) || "";
  const m = /^#pending(?:\/([A-Za-z0-9_-]{1,64}))?$/.exec(h);
  const ag = /^#agent\/([A-Za-z0-9_-]{1,80})$/.exec(h);
  if (m) { show("inbox"); openPending(m[1]); }
  else if (ag) openAgent(ag[1]);
  else if (h === "#notifications") { show("settings"); openNotifications(); }
  else if (h === "#health") { show("inbox"); openHealth(); }
  else if (["#agents", "#activity", "#settings"].includes(h)) { show(h.slice(1)); if (typeof window !== "undefined" && window.scrollTo) window.scrollTo(0, 0); }
  else show("inbox");
}
// A node-health notification opens the nodes' health, not the pending list (#574, B5).
function openHealth() {
  const box = document.getElementById("problems");
  if (box && box.scrollIntoView) box.scrollIntoView();
}

// Signed out, the server answers /api/me with 401 and tells the page nothing else: the page offers
// passkey sign-in (and says where enrolment links come from) whatever the server's state.
async function boot() {
  // Signed out is what the server says (401, 403, or who: none); a server that can't answer now (a
  // restart's 502, a network error) is retried, not shown as a sign-in (#574).
  let r;
  try { r = await fetch("/api/me"); } catch (e) { r = null; }
  if (!r || (!r.ok && r.status !== 401 && r.status !== 403)) {
    showStale(r ? "HTTP " + r.status : "no answer");
    setTimeout(boot, 5000);
    return;
  }
  showStale(null);
  const me = r.ok ? await r.json() : { who: { state: "none" } };
  const auth = document.getElementById("auth"), con = document.getElementById("console");
  auth.replaceChildren();
  const nav = document.getElementById("nav");
  if (me.who.state === "operator") { sessionEnded = false; auth.hidden = true; con.hidden = false; if (nav) nav.hidden = false; await refresh(); fromHash(); renderPush(); return; }
  if (sessionEnded) auth.append(el("div", "callout warn", "Your console session ended. Sign in again."));
  con.hidden = true; auth.hidden = false;
  if (nav) nav.hidden = true;
  document.getElementById("tenant").textContent = "";
  if (me.who.state === "bootstrap") {
    auth.append(el("div", "", "Enrol this device's passkey. It signs you in, and you will sign every approval with it."));
    const name = el("input", "text"); name.id = "pkname"; name.value = "my phone"; name.maxLength = 40;
    const b = el("div", "buttons"); const go = el("button", "approve", "Create passkey"); go.onclick = registerPasskey; b.append(go);
    auth.append(name, b);
  } else {
    auth.append(el("div", "", "Sign in to approve or deny what your agents are waiting on, start runs and steer them."));
    const b = el("div", "buttons"); const go = el("button", "approve", "Sign in with passkey"); go.onclick = signIn; b.append(go); auth.append(b);
    auth.append(codeText("div", "note", "No passkey yet? Open a one-time enrolment link from the host (`wicket serve` prints one at first start; `wicket operator enrol-link` makes another).", ["wicket operator enrol-link"]));
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
const when = t => at(t);
const whenMs = ms => ms ? at(ms / 1000) : "\u2014";

// A run's authority (#651): what it can reach first (its zone's rules, its live grants, the standing
// rules that apply to it, each with when it ends), then what its node holds, and the token's
// internals (blocks, every grant, the zone's Cedar) folded under Details. Every string is text.
const methodsText = m => (m || []).map(strip).join(", ") || "GET, HEAD";
const pathsText = p => (p || ["/**"]).map(strip).join(" ");
function reachLine(text, end, note) {
  const d = el("div", "reach");
  d.append(el("div", "mono", text));
  const m = el("div", "meta");
  if (end !== undefined) m.append(end);
  if (note) m.append(document.createTextNode((end !== undefined ? " \u00b7 " : "") + note));
  if (m.children.length || m.textContent) d.append(m);
  return d;
}
async function showAuthority(run) {
  const body = openDetail("Permissions");
  try {
    const a = await getJson("/api/runs/" + encodeURIComponent(run) + "/authority");
    const t = a.token || {};
    const out = [];
    const now = nowSecs();
    // What it can reach.
    out.push(el("h4", "", "Can reach"));
    const reach = [];
    for (const r of t.reach || []) reach.push(reachLine(verbsOf(r.methods) + " " + strip(r.host) + "  " + pathsText(r.paths), undefined,
      "from its zone's rules" + (r.allow_dangerous ? "; including requests that can't be undone" : "") +
      ((r.decode_slash || []).length ? "; reads an encoded slash (%2F) as / in path part " + r.decode_slash.map(Number).join(", ") : "")));
    for (const g of (t.grants || []).filter(g => !g.revoked && (!g.expires_at || g.expires_at > now))) {
      const end = el("span"); end.append(document.createTextNode("allowed by " + decider(g.approved_by) + "; ends "), timeEl(g.expires_at));
      // All that the grant reaches (#715 review): a standing grant is a rule on the host (its methods,
      // path globs and allow_dangerous); a prefix grant covers every path under its path.
      const sr = g.standing;
      const what = sr ? verbsOf(sr.methods) + " " + strip(g.host) + "  " + pathsText(sr.paths)
        : verb(g) + " " + strip(g.host + g.path) + (g.prefix ? " and every path under it" : "");
      reach.push(reachLine(what, end,
        (g.uses == null ? "any number of times" : plural(g.uses, "more time", "more times")) +
        (sr && sr.allow_dangerous ? " \u00b7 including requests that can't be undone" : "") +
        (g.reached_node === false ? " \u00b7 not yet on its server" : "")));
    }
    const st = (lastState && lastState.standing && lastState.standing.rules) || [];
    const row = ((lastState && lastState.runs) || []).find(x => x.id === run) || {};
    for (const r of st.filter(r => r.live && (r.for === "zone" ? r.zone === t.zone : row.agent && String(r.principal || "").endsWith("/z/" + row.zone + "/a/" + row.agent)))) {
      const end = el("span"); end.append(document.createTextNode("always allowed, "), r.expires_at ? timeEl(r.expires_at, "ends " + at(r.expires_at)) : document.createTextNode("until removed"));
      reach.push(reachLine(verbsOf(r.rule.methods) + " " + strip(r.rule.host) + "  " + pathsText(r.rule.paths), end, (r.for === "zone" ? "for every agent in its zone" : "for this agent") +
        (r.rule.allow_dangerous ? "; including requests that can't be undone" : "") + " \u00b7 allowed by " + decider(r.decided_by)));
    }
    // What its zone forbids beats everything above, a grant included.
    for (const f of t.forbid || []) reach.push(reachLine("never " + strip(f.host) + "  " + pathsText(f.paths), undefined, "forbidden by its zone's rules, even if you allow it"));
    if (!t.held) reach.push(el("div", "note", "No token now: " + strip(t.why)));
    else if (!reach.length) reach.push(el("div", "empty", "Nothing: everything it asks for waits for you."));
    out.push(...reach);
    // The run, and what its node holds for it.
    out.push(el("h4", "", "Where it runs"));
    if (a.revoked) out.push(el("div", "callout warn", "Stopped by " + strip(a.revoked.by) + ": " + strip(a.revoked.reason)));
    out.push(kv("server", strip(a.node)));
    if (a.deadline) out.push(kv("its permissions end", whenMs(a.deadline.until_ms) + (a.deadline.stopped ? " (stopped)" : "")));
    if (a.holdings) {
      out.push(kv("keys it can use", a.holdings.secrets.length ? a.holdings.secrets.map(strip).join(", ") : "none"));
      const sl = a.holdings.slice;
      out.push(kv("model budget left on its server", sl ? num(sl.requests) + " requests, " + num(sl.output_tokens) + " output tokens" + (sl.input_tokens != null ? ", " + num(sl.input_tokens) + " input tokens" : "") : "none"));
    }
    out.push(kv("organisation rules", (a.policy.version ? strip(a.policy.version) + (a.policy.current ? " (current)" : " (not the installed " + strip(a.policy.installed || "none") + ")") : "none")));
    if (t.held) {
      const det = el("details", "more");
      det.append(el("summary", "", "Technical details: its token, grants and zone policy"));
      det.append(kv("status", strip(a.status) + (a.feed ? " \u00b7 node feed epoch " + strip(a.feed.epoch) : "")));
      det.append(kv("token", "box " + strip(t.box_path) + " \u00b7 epoch " + strip(t.epoch) + " \u00b7 zone " + strip(t.zone) + " \u00b7 minted by " + strip(t.issued_by) +
        (t.loads === true ? " \u00b7 loads" : " \u00b7 does NOT load: " + strip((t.loads || {}).error || ""))));
      for (const b of t.blocks || []) {
        const h = el("div", "row");
        h.append(el("span", b.revoked ? "blocked" : "ok", "block " + b.index + " \u00b7 " + strip(b.kind) + (b.revoked ? " \u00b7 REVOKED" : "")),
          el("span", "meta", "revocation " + strip(b.revocation_fingerprint) + (b.signed_by ? " \u00b7 signed by " + strip(b.signed_by) : "")));
        det.append(h, el("pre", "src", b.source));
      }
      for (const g of t.grants || []) {
        det.append(kv(g.id, g.method + " " + g.host + g.path + " \u00b7 " + (g.uses == null ? "unlimited uses" : g.uses + " uses (counted on the node)") +
          " \u00b7 ends " + when(g.expires_at) + " \u00b7 approved by " + (g.approved_by || "?") + " at " + when(g.approved_at) +
          (g.revoked ? " \u00b7 revoked" : "") + (g.reached_node === false ? " \u00b7 not yet on its node" : "")));
      }
      if (t.zone_cedar) det.append(el("div", "meta", "zone policy (Cedar, generated from the manifest)"), el("pre", "src", t.zone_cedar));
      out.push(det);
    }
    body.replaceChildren(...out);
  } catch (e) { body.replaceChildren(el("div", "blocked", strip(e.message))); }
}

async function showExplain(seq, into) {
  const body = into || openDetail("decision #" + seq);
  if (into) { into.hidden = false; into.replaceChildren(el("div", "meta", "loading\u2026")); }
  try {
    const x = await getJson("/api/explain/" + encodeURIComponent(seq));
    const r = x.recorded, n = x.against_token_now;
    const out = [
      kv("request", r.method + " " + r.host + r.path + " (" + (r.risk || "?") + ")"),
      kv("recorded", String(r.outcome) + " on " + r.decided_on + " at " + when(r.at) + ": " + localTimes(r.detail)),
      kv("run", x.run + " · policy " + (x.policy || "none")),
    ];
    if (n.available) {
      out.push(kv("token now", n.decision), el("pre", "src", n.why), kv("zone says", n.zone_says));
      out.push(el("div", "note", "Against the run's token as its node's feed holds it now: grants and policy may have changed since it was decided."));
    } else out.push(el("div", "note", "Can't evaluate it now: " + localTimes(n.why)));
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

// A box's limits as words (#651): "memory 2GiB · 2 CPUs · timeout 1h", the rest after.
function limitsText(l) {
  if (!l || typeof l !== "object") return strip(l);
  const parts = [];
  if (l.memory) parts.push("memory " + strip(l.memory));
  if (l.cpus) parts.push(plural(l.cpus, "CPU"));
  if (l.timeout) parts.push("timeout " + strip(l.timeout));
  if (l.authority) parts.push("authority " + strip(l.authority));
  if (l.pids) parts.push(num(l.pids) + " processes");
  if (l.output) parts.push("output " + strip(l.output) + (l.on_output_full ? " (then " + strip(l.on_output_full) + ")" : ""));
  return parts.join(" \u00b7 ") || JSON.stringify(l);
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
  out.push(kvRow("limits", limitsText(g.limits)));
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
const utc = t => at(t);
function secretUse(u) {
  const where = "Used by " + u.manifest + " (zone " + u.zone + ")";
  return strip(u.use === "llm" ? where + " as the model key" + (u.provider ? " (" + u.provider + ")" : "")
    : where + ": sent to " + u.host + " in its " + u.header + " header" + (u.format ? ", as " + u.format : "") + (u.optional ? " (optional)" : ""));
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
    head.append(el("span", "mono", strip(x.name)), el("span", "risk " + (x.kind === "reference" ? "r2" : "r0"), x.kind === "reference" ? "read from a file on the host" : "stored"));
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
    head.append(el("span", "mono", strip(m.name)), el("span", "risk r3", "needed, not set"));
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

// A decided request: its outcome as a pill, what it was for, and when it was asked (#645).
function decidedRow(x) {
  const d = el("div", "decided");
  const head = el("div", "run-head");
  head.append(el("span", "pill " + (({ granted: "good", denied: "bad" })[x.status] || ""), ({ granted: "allowed", denied: "refused" })[x.status] || strip(x.status)),
    el("span", "", runName(x.run) + ": " + verb(x) + " "), wrapped("mono inline", strip(x.host + x.path)));
  const meta = el("div", "meta");
  meta.append(document.createTextNode(strip(x.id) + " \u00b7 zone " + strip(x.zone) + " \u00b7 asked "), timeEl(x.created_at, rel(x.created_at)));
  d.append(head, meta);
  return d;
}

// The activity log's filters: everything, or one kind of line (docs/explanation/console-design.md).
let logFilter = "all";
function renderFilters() {
  const box = document.getElementById("filters");
  if (!box || box.dataset.built) return;
  box.dataset.built = "1";
  for (const [k, label] of [["all", "Everything"], ["blocked", "Blocked"], ["decisions", "Decisions"], ["agents", "Agents"], ["servers", "Servers"]]) {
    const b = el("button", "chip", label); b.type = "button"; b.setAttribute("aria-pressed", String(k === logFilter));
    b.onclick = () => { logFilter = k; for (const c of box.children) c.setAttribute("aria-pressed", String(c === b)); applyFilter(); };
    box.append(b);
  }
}
function applyFilter() {
  const box = document.getElementById("audit");
  if (!box) return;
  for (const n of box.children) if (n.dataset && n.dataset.cat) n.hidden = logFilter !== "all" && n.dataset.cat !== logFilter;
}

// The Inbox's first line: how things are, each part a link to where it is (#574 redesign).
function renderStatus(s) {
  const box = document.getElementById("status");
  if (!box) return;
  const runs = s.runs || [];
  const working = runs.filter(r => r.status === "running" && !r.revoked).length;
  const waiting = (s.pending || []).length + (((s.standing || {}).asks) || []).length;
  const problems = problemList(s).length;
  const part = (n, one, many, href, cls) => { const a = el("a", cls || "", plural(n, one, many)); a.href = href; return a; };
  const parts = [part(working, "agent working", "agents working", "#agents")];
  if (waiting) parts.push(part(waiting, "request waiting for you", "requests waiting for you", "#inbox", "warn"));
  parts.push(problems ? part(problems, "problem", "problems", "#health", "bad") : el("span", "ok", "no problems"));
  box.replaceChildren();
  parts.forEach((x, i) => { if (i) box.append(document.createTextNode(" \u00b7 ")); box.append(x); });
}
// What is wrong, in plain words, each with where to act: health alerts, the record backup, servers
// still billing past their rental, keys a task setup needs that aren't set.
function problemList(s) {
  const out = [];
  const h = s.health || {};
  for (const n of h.nodes || []) for (const a of n.alerts || []) out.push(["bad", "Server " + strip(a), "#settings"]);
  if (h.control_disk_pct > 85) out.push(["bad", "The control host's disk is " + h.control_disk_pct + "% full", "#settings"]);
  const st = h.state_store;
  if (st) {
    for (const a of st.alerts || []) out.push(["warn", "Record backup: " + strip(a), "#settings"]);
    if (st.stream && st.stream.state !== "streaming" && st.stream.state !== "starting") out.push(["bad", "The record backup isn't running (" + strip(st.stream.state) + ")", "#settings"]);
  }
  for (const p of s.placed || []) if (p.past_lease && p.held_by) out.push(["warn", "Rented server " + strip(p.name) + " is still billing after its rental ended", "#settings"]);
  for (const m of ((s.secrets || {}).missing) || []) out.push(["warn", "Key " + strip(m.name) + " isn't set, and a task setup needs it", "#settings"]);
  return out;
}
let problemsKey = "";
function renderProblems(s) {
  const box = document.getElementById("problems");
  if (!box) return;
  const list = problemList(s);
  const key = JSON.stringify(list);
  if (key === problemsKey) return;
  problemsKey = key;
  if (!list.length) { box.replaceChildren(el("div", "empty", "Nothing is wrong.")); return; }
  box.replaceChildren(...list.map(([tone, text, href]) => { const a = el("a", "problem " + tone, text); a.href = href; return a; }));
}

// When the console last heard from wicket, and a line saying so while it can't (#574): what is on
// the page is as of then, and the poll goes on.
let lastHeard = 0;
// A poll answered 401 or 403 after the page was signed in: the sign-in card says why it is back (#618).
let sessionEnded = false;
function showStale(why) {
  const b = document.getElementById("stale");
  if (!b) return;
  if (!why) { b.hidden = true; return; }
  b.hidden = false;
  const since = lastHeard ? " since " + new Date(lastHeard).toISOString().slice(11, 19) + "Z; what is shown is as of then" : "";
  b.textContent = "Can't reach wicket (" + why + ")" + since + ". Retrying.";
}

// One poll at a time (#574, B9), each bounded: a hung fetch is a stale page, said so, not a frozen
// one. An answer from before a decision is dropped (`pollGen` moves when the sheet closes), and a
// poll asked for while one is in flight runs once it ends (review of #598).
let polling = false, pollAgain = false, pollGen = 0;
const POLL_TIMEOUT_MS = 10000;
async function refresh() {
  if (ceremony) return;
  if (polling) { pollAgain = true; return; }
  polling = true;
  try { await refreshOnce(); } finally { polling = false; }
  if (pollAgain) { pollAgain = false; refresh(); }
}
async function refreshOnce() {
  const gen = pollGen;
  let r;
  const opts = typeof AbortSignal !== "undefined" && AbortSignal.timeout ? { signal: AbortSignal.timeout(POLL_TIMEOUT_MS) } : undefined;
  try { r = await fetch("/api/state", opts); } catch (e) { showStale(e && e.name === "TimeoutError" ? "no answer in 10 s" : "no answer"); return; }
  if (gen !== pollGen) return;
  // Only the server saying the session is gone signs the page out; anything else is a moment's
  // trouble, said as such, and the poll carries on.
  if (r.status === 401 || r.status === 403) { sessionEnded = true; boot(); return; }
  if (!r.ok) { showStale("HTTP " + r.status); return; }
  lastHeard = Date.now();
  showStale(null);
  try {
    const s = await r.json();
    if (ceremony || gen !== pollGen) return; // a sheet opened, or a decision was made, while this poll was in flight
    if (typeof s.now === "number") skewSecs = s.now - Date.now() / 1000;
    lastState = s;
    document.getElementById("tenant").textContent = "tenant " + s.tenant;
    renderPending(s);
    renderStatus(s);
    renderProblems(s);
    // Kept across polls, as the pending cards are (#715 review): a row is rebuilt only when its run, or
    // whether it waits for you, changed.
    renderKeyed("runs", s.runs.map(x => ({ ...x, waiting: s.pending.some(p => p.run === x.id) })), x => renderRun(s, x), "No runs yet.");
    renderRows("health", ((s.health || {}).nodes) || [], healthRow, "No node has reported its health yet.");
    if (s.health && s.health.control_disk_pct > 85) document.getElementById("health").prepend(el("div", "blocked", "! the control host's disk is " + s.health.control_disk_pct + "% full"));
    if (s.health && s.health.state_store) document.getElementById("health").prepend(...stateStoreRows(s.health.state_store, s.now * 1000));
    renderRows("placed", s.placed || [], placedRow, "No leased nodes.");
    renderKeyed("fenced", s.fenced || [], fencedRow, "None: no agent's box is held on a node that is revoked or no longer enrolled. An enrolled node's boxes are released by the node, or by revoking it first.");
    renderKeyed("capacity", s.capacity || [], capacityRow, "No capacity grants: every `wicket node create` waits for a decision.");
    renderCapacityForm();
    const st = s.standing || {};
    // Standing asks wait with the requests, under a heading of their own, shown only when there are some.
    const ptr = document.getElementById("standing-pointer");
    const n = (st.asks || []).length;
    if (ptr) { ptr.textContent = n ? "Asking to be always allowed (" + n + ")" : ""; ptr.hidden = !n; }
    renderCounts(s.pending.length + n, problemList(s).length);
    renderKeyed("standing-asks", st.asks || [], standingAskRow, "No agent is asking for standing reach.");
    renderKeyed("standing-rules", st.rules || [], standingRuleRow, "No standing rules: each request waits for a decision.");
    renderStart(s);
    renderManifests(s);
    renderSecrets(s);
    renderRows("decided", s.decided, decidedRow, "No decisions yet.");
    renderRows("audit", s.audit.slice().reverse(), line, "No activity yet.");
    renderFilters(); applyFilter();
    refreshRel();
    renderAgentHead(); renderAgentLog();
    const ar = document.getElementById("audit-retention");
    if (ar) ar.textContent = s.audit_retention ? strip(s.audit_retention.line) : "";
    renderOperator(s);
    renderPolicy();
  } catch (e) { /* keep polling */ }
}
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("runform").addEventListener("submit", submitRunForm);
  const so = document.getElementById("start-open");
  if (so) so.addEventListener("click", () => { const c = document.getElementById("start-card"); c.hidden = !c.hidden; so.setAttribute("aria-expanded", String(!c.hidden)); });
  document.getElementById("runform-cancel").addEventListener("click", closeRunForm);
  document.getElementById("confirm-cancel").addEventListener("click", closeConfirm);
  document.getElementById("secret-edit").addEventListener("submit", submitSecret);
  document.getElementById("secret-edit-cancel").addEventListener("click", closeSecret);
  document.getElementById("mfedit-close").addEventListener("click", () => { document.getElementById("mfedit").hidden = true; });
  document.getElementById("detail-close").addEventListener("click", () => { document.getElementById("detail").hidden = true; });
  if (typeof navigator !== "undefined" && navigator.serviceWorker) navigator.serviceWorker.addEventListener("message", e => {
    if (e.data && typeof e.data.open === "string") openPending(e.data.open);
    if (e.data && e.data.health === true) openHealth();
    if (e.data && e.data.resubscribe === true) openNotifications();
  });
  if (typeof window !== "undefined" && window.addEventListener) window.addEventListener("hashchange", fromHash);
  boot();
  setInterval(() => { if (!document.getElementById("console").hidden) refresh(); }, 2000);
});

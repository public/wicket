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

// The Inbox is drawn by inbox.js, with lit-html (#574): the request cards, the status line and the
// problems. These hand it the state; before the module has loaded (or where it can't run, as in the
// fake DOM of console_ui.js) they draw nothing.
function renderPending(s) {
  pendingLoaded = true;
  inbox("renderPending", s);
}
// A failure drawing the Inbox is logged (the browser tests fail on it) and doesn't stop the rest of
// the page from being drawn.
// What each view module draws: if it didn't load (a failed fetch, an old browser), each of these says
// so, rather than look empty (no requests waiting, no agents).
const VIEW_BOXES = { wicketInbox: ["pending", "standing-asks"], wicketAgents: ["runs", "start", "agent-head", "agent-log"], wicketActivity: ["audit", "decided"],
  wicketSettings: ["standing-rules", "capacity", "capacity-form", "health", "placed", "fenced", "secrets", "manifests", "policy", "operator"] };
// Sign out (settings.js's button calls it too): the one-time enrolment link and any open question go
// with the session (#711), and the page asks to sign in again.
async function signOut() {
  enrolLink = null;
  if (globalThis.wicketSettings) globalThis.wicketSettings.reset();
  try { await post("/api/logout"); } catch (e) { /* signed out anyway */ }
  boot();
}
const UNLOADED = "This can't be shown: part of this page didn't load. Reload the page; if it stays, check the browser's console.";
function drawn(mod, f, ...args) {
  if (!globalThis[mod]) {
    for (const id of VIEW_BOXES[mod] || []) {
      const box = document.getElementById(id);
      if (!box || (box.textContent || "").startsWith("This can't be shown")) continue;
      box.replaceChildren(el("div", "blocked", UNLOADED));
      // Signing out is a security control: it mustn't need a module to have loaded.
      if (id === "operator") { const out = el("button", "", "Sign out"); out.onclick = signOut; const b = el("div", "buttons"); b.append(out); box.append(b); }
    }
    return;
  }
  // A failure, then or later (showAuthority is async), is logged (the browser tests fail on it) and
  // doesn't stop the rest of the page from being drawn.
  try {
    const r = globalThis[mod][f](...args);
    if (r && typeof r.catch === "function") r.catch(e => console.error(mod + "." + f + " failed:", e));
  } catch (e) { console.error(mod + "." + f + " failed:", e); }
}
const inbox = (f, s) => drawn("wicketInbox", f, s);
// The cards moved: taps are ignored for a moment (`settled`), so one can't land on a card that just
// moved under it. inbox.js calls it.
function layoutMoved() { layoutAt = performance.now(); }

// A signed action from a row's button, once the layout has settled (the views' rows use it).
const signedSettled = body => {
  if (!settled()) { toast("The list just changed: check the row and tap again."); return; }
  signed(body);
};

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
// A line as data (activity.js draws it): which filter shows it, its tag and tone, its words, and
// whether it has a "why?" (a decision on a run's request, which can be explained).
function logLine(op, tag, tone, text) {
  const cat = /^(decision|standing|grant|capacity|lease)/.test(op.kind) ? "decisions" : /^(run|identity|session|operator\.message)/.test(op.kind) || (op.body || {}).kind === "llm" || (op.body || {}).kind === "box" ? "agents" : /^node/.test(op.kind) ? "servers" : "other";
  return { cat, tag, tone: tone || "", text, why: false };
}
// An agent run by its agent's name where the latest list knows it; its id otherwise.
function runName(id) {
  const x = ((lastState && lastState.runs) || []).find(r => r.id === id);
  return x ? (x.agent ? strip(x.agent) : "a program") : strip(id);
}
function sentence(op) {
  const b = op.body || {};
  const r = op.run ? runName(op.run) : "";
  const eg = egressOf(op);
  if (eg) {
    const [x, where] = eg;
    const outcome = String(x.outcome || "?");
    const tone = outcome === "allow" || outcome === "spliced" ? "ok" : outcome === "pending" ? "pend" : "blocked";
    const said = ({ allow: "allowed", spliced: "allowed", pending: "waiting", forbidden: "blocked", denied: "blocked", deny: "blocked" })[outcome] || outcome;
    const ln = logLine(op, said, tone, (r ? r + ": " : "") + verb(x) + " " + strip(x.host + x.path + where));
    ln.cat = outcome === "allow" || outcome === "spliced" ? "allowed" : "blocked";
    ln.why = !!op.run;
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

// Standing reach (#572). A rule as a manifest would carry it.
function ruleText(r) {
  r = r || {};
  return "{ host: " + strip(r.host) + ", methods: [" + (r.methods || []).map(strip).join(", ") + "], paths: [" +
    (r.paths || []).map(p => "'" + strip(p) + "'").join(", ") + "]" + (r.allow_dangerous ? ", allow_dangerous: true" : "") + " }";
}
// An agent's page: its name, state and links, what it can reach (the authority view, #651), and what
// it did. Stop is the signed revoke, from here only.
function openAgent(run) {
  // A Stop form left open for another agent goes (#715 review): its submit would revoke that one.
  if (agentRun !== run) closeRunForm();
  agentRun = run;
  show("agent");
  drawn("wicketAgents", "renderAgentHead", lastState, run);
  drawn("wicketAgents", "showAuthority", run);
  drawn("wicketAgents", "renderAgentLog", lastState, run);
  if (typeof window !== "undefined" && window.scrollTo) window.scrollTo(0, 0);
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

// #711: the enrolment link a signed enrol_link returned, shown in the passkeys card until it expires
// (it lives only in this page: reloading drops it).
let enrolLink = null;
function showEnrolLink(j) { enrolLink = { link: String(j.link), until: Date.now() + (Number(j.expires_in_secs) || 0) * 1000 }; }
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
// The service worker's URL as Trusted Types require it (#739): registering one is a script-URL sink,
// so the URL comes from a policy of wicket's own that makes "/sw.js" and nothing else. Made once
// (a policy name can be created only once); without Trusted Types, the plain string.
let swPolicy = null;
function swUrl() {
  const tt = typeof window !== "undefined" && window.trustedTypes;
  if (!tt) return "/sw.js";
  swPolicy = swPolicy || tt.createPolicy("wicket-sw", { createScriptURL: u => { if (u !== "/sw.js") throw new TypeError("wicket-sw makes only /sw.js"); return u; } });
  return swPolicy.createScriptURL("/sw.js");
}
async function enablePush() {
  // First, while the click still counts as the user's gesture.
  const perm = await Notification.requestPermission();
  if (perm !== "granted") { toast(perm === "denied" ? "Notifications are blocked for this site in the browser's settings." : "Notifications not allowed."); return; }
  try {
    const reg = await navigator.serviceWorker.register(swUrl(), { scope: "/" });
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
  const card = globalThis.wicketInbox ? globalThis.wicketInbox.setOpen(openId, lastState) : null;
  const target = card || document.getElementById("waiting") || document.getElementById("pending");
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
  // An unused enrolment link enrols a device as the operator who made it, so it never outlives
  // their session in this tab: whoever signs in next starts without it (#711).
  enrolLink = null;
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

const whenMs = ms => ms ? at(ms / 1000) : "\u2014";


// ---- manifests (#172): view, check as you type, save and restore as signed actions ----
async function fetchJson(path) {
  const r = await fetch(path);
  const j = await r.json().catch(() => ({ error: "unreadable answer" }));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const kvRow = (k, v, cls) => { const d = el("div", "row"); d.append(el("span", "meta", k), el("span", cls || "mono", strip(v))); return d; };

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

// The Inbox's first line: how things are, each part a link to where it is (#574 redesign).
function renderStatus(s) {
  inbox("renderStatus", s);
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
function renderProblems(s) {
  inbox("renderProblems", s);
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
  if (r.status === 401 || r.status === 403) { sessionEnded = true; if (globalThis.wicketSettings) globalThis.wicketSettings.reset(); boot(); return; }
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
    drawn("wicketAgents", "renderRuns", s);
    drawn("wicketSettings", "renderSettings", s);
    const st = s.standing || {};
    // Standing asks wait with the requests, under a heading of their own, shown only when there are some.
    const ptr = document.getElementById("standing-pointer");
    const n = (st.asks || []).length;
    if (ptr) { ptr.textContent = n ? "Asking to be always allowed (" + n + ")" : ""; ptr.hidden = !n; }
    renderCounts(s.pending.length + n, problemList(s).length);
    inbox("renderStandingAsks", s);
    drawn("wicketAgents", "renderStart", s);
    drawn("wicketActivity", "renderActivity", s);
    refreshRel();
    if (view === "agent") { drawn("wicketAgents", "renderAgentHead", s, agentRun); drawn("wicketAgents", "renderAgentLog", s, agentRun); }
    const ar = document.getElementById("audit-retention");
    if (ar) ar.textContent = s.audit_retention ? strip(s.audit_retention.line) : "";
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

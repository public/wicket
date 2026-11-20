// Settings (docs/explanation/console-design.md), drawn with lit-html (#574, the port's step 4b): the
// rules agents are always allowed, spending limits (capacity grants) and the form that adds one, the
// servers' health with the record backup and the activity export, and the rented servers. Every
// string from the API goes in as a template value, which lit-html sets as text, never as HTML.
//
// As the other views, it uses console.js's helpers by their bare names (strip, signed, post, …);
// every signed action is console.js's.
import { html, nothing } from "lit-html";
import { repeat } from "lit-html/directives/repeat.js";
import { draw, time, code, copyButton, serverText, serverLine, keeper } from "./ui.js";

const g = globalThis;

// ---- Revoke, asked first (#640) ----

// Revoke on a capacity grant or a standing rule: unsigned, since it only narrows, but asked in the
// page first, and set apart from Renew. The question replaces the row's buttons until answered.
const asking = new Set();
let last = null;
const again = () => { if (last) renderSettings(last); };
function revokeButtons(key, question, others, go) {
  if (!asking.has(key)) {
    const ask = () => {
      if (!settled()) { toast("The list just changed: check the row and tap again."); return; }
      asking.add(key); again(); layoutMoved();
    };
    return html`<div class="buttons">${others}<button class="deny apart" @click=${ask}>Revoke…</button></div>`;
  }
  // The question moved the row: a second tap of a double tap mustn't land on its Revoke.
  const yes = async e => { if (!settled()) return; e.target.disabled = true; await go(); asking.delete(key); again(); };
  return html`<div class="buttons"><div class="callout warn ask">${question}</div><button class="deny" @click=${yes}>Revoke</button><button @click=${() => { asking.delete(key); again(); }}>Cancel</button></div>`;
}

// Rows kept across polls by their id: when one changes or the order does, the layout moved, and
// taps wait a moment (console.js's `settled`), as on the request cards.
const lastKeys = new Map();
function keyed(id, rows, row, empty) {
  const box = document.getElementById(id);
  if (!box) return;
  draw(rows.length ? repeat(rows, r => r.id, row) : html`<div class="empty">${code(empty)}</div>`, box);
  const key = JSON.stringify(rows);
  if (lastKeys.has(id) && lastKeys.get(id) !== key) layoutMoved();
  lastKeys.set(id, key);
}

// ---- spending limits (#256) ----

// A principal's `wicket node create` within a grant is approved at once and audited against it;
// beyond every one, it waits as a request. Issuing and renewing a grant widen what may be spent, so
// each is signed with the passkey; revoking one only narrows, so it needs only the session.
const principals = keeper();
const principal = (scope, p) => principals.get(scope + "\u0000" + p, () => principalEl(p));

// The lifetime the form asks for (hours, at most 24): also what Renew renews for.
function capacityTtl() {
  const i = document.querySelector('#capacity-form input[name="hours"]');
  const h = Number((i && i.value) || 8);
  return Math.round(Math.min(24, Math.max(0.1, h)) * 3600);
}

function capacityRow(gr) {
  const t = gr.terms || {}, u = gr.used || {}, left = gr.left || {};
  const nodes = n => plural(Number(n) || 0, "node");
  const revoke = async () => { try { toast((await post("/api/capacity/revoke", { id: gr.id })).ok); } catch (e) { toastError(e); } refresh(); };
  return html`<div class="row cap"><div class="run-head">${principal("cap:" + gr.id, gr.principal)}<span class="mono quiet">${strip(gr.id)}</span></div><div class="meta">${"Allows: " + nodes(t.nodes) + " at once of " + (t.plans || []).map(strip).join(" or ") + " in " + (t.regions || []).map(strip).join(", ") +
    ", up to " + money(t.hourly_usd) + "/h and " + money(t.daily_usd) + " a day"}</div><div class="meta">${"Used today: " + nodes(u.nodes) + ", " + money(u.hourly_usd) + "/h, " + money(u.daily_usd)}</div><div class="meta">${"Left today: " + nodes(left.nodes) + ", " + money(left.hourly_usd) + "/h, " + money(left.daily_usd)}</div><div class="meta">Ends ${time(gr.expires_at)}${" · granted by " + strip(gr.decided_by)}</div>${revokeButtons("cap:" + gr.id, "Revoke capacity grant " + strip(gr.id) + "? Nothing more is approved under it, from now.",
    html`<button class="approve" @click=${() => signed({ action: "capacity_renew", id: gr.id, ttl_secs: capacityTtl() })}>Renew</button>`, revoke)}</div>`;
}

// The form: built once (lit-html keeps its inputs), so what the operator types survives the poll.
const FIELDS = [["principal", "To", "unix/alex, passkey/laptop or spiffe://…"], ["plans", "Plans", "vc2-1c-2gb, vc2-2c-4gb"], ["regions", "Regions", "lhr"],
  ["hourly", "Most per hour, all its nodes ($)", "0.05"], ["daily", "Most a day ($)", "1.00"], ["nodes", "Nodes at once", "2", "number"], ["hours", "Hours (at most 24)", "8", "number"]];
function capacityForm() {
  const grant = e => {
    const v = k => e.target.closest("#capacity-form").querySelector(`input[name="${k}"]`).value;
    signed({ action: "capacity_grant", principal: v("principal"), plans: v("plans"), regions: v("regions"),
      max_hourly_usd: v("hourly"), max_daily_usd: v("daily"), nodes: Number(v("nodes") || 0), ttl_secs: capacityTtl() });
  };
  return html`<div class="note">${code("Issue a capacity grant: what a principal may lease with `wicket node create` without asking each time.")}</div>${FIELDS.map(([name, label, placeholder, type]) =>
    html`<label class="field"><span class="meta">${label}</span><input name=${name} placeholder=${placeholder} type=${type || "text"} value=${name === "hours" ? "8" : ""}></label>`)}<div class="buttons"><button class="approve" @click=${grant}>Grant (sign with passkey)</button></div>`;
}

// ---- always allowed (#572) ----

// An approved rule: who it is for, when it lapses; renewed (signed, 30 days) or revoked (session).
function standingRuleRow(r) {
  const rr = r.rule || {};
  const to = r.for === "zone" ? html`<span class="run-name">${"every agent in zone " + strip(r.zone)}</span>` : principal("rule:" + r.id, r.principal);
  const until = r.expires_at ? (r.live ? "ends " + at(r.expires_at) : "lapsed " + at(r.expires_at)) : "until revoked";
  const revoke = async () => { try { toast((await post("/api/standing/revoke", { id: r.id })).ok); } catch (e) { toastError(e); } refresh(); };
  // On the row, not only in its title (#715 review): a rule that allows requests that can't be undone.
  return html`<div class="row cap"><div title=${"standing reach " + strip(r.id) + ": " + ruleText(r.rule)}>${to}<span>${" may " + verbsOf(rr.methods) + " "}</span><span class="mono">${strip(rr.host)}</span>${rr.allow_dangerous ? html` <span class="risk r4">including requests that can't be undone</span>` : nothing}</div><div class="meta">${(rr.paths || []).map(strip).join("  ") + " · " + until + " · allowed by " + strip(r.decided_by)}</div>${revokeButtons("rule:" + r.id, "Revoke standing reach " + strip(r.id) + "? Runs it allows lose it at once.",
    html`<button class="approve" ?disabled=${!r.live} @click=${() => signedSettled({ action: "standing_renew", id: r.id })}>Renew (30 days)</button>`, revoke)}</div>`;
}

// ---- servers ----

// A node's latest health report (#377): the row (name, summary), and its alerts under it, each a
// line of its own (#574, B7).
const healthRow = n => html`<div class="hrow"><div class="row"><span class="mono">${strip(n.node)}</span>${serverText((n.alerts || []).length ? "blocked" : "", n.summary + " · reported " + whenMs(n.received_ms))}</div>${(n.alerts || []).map(a => serverLine("blocked", "! " + a))}</div>`;

// The state store's sync and the audit export's progress (#635), as `wicket state check` and
// `wicket audit export --status` compute them: a row for the ledger's stream, one per audit sink,
// each with its last error under it. A span in seconds, short.
const secs = s => { s = Math.max(0, Math.round(s || 0)); return s < 120 ? s + " s" : s < 7200 ? Math.floor(s / 60) + " min" : s < 172800 ? Math.floor(s / 3600) + " h" : Math.floor(s / 86400) + " d"; };
function stateStoreRows(p, nowMs) {
  const row = (name, cls, text, err) => html`<div class="hrow"><div class="row"><span class="mono">${name}</span><span class=${cls}>${code(text)}</span></div>${err ? html`<div class="blocked">${"! " + err}</div>` : nothing}</div>`;
  const out = [];
  // What is alerted (and pushed, if notifications are on) first, so a sink past its threshold
  // doesn't look like one a few records behind; then whether these rows are current.
  for (const a of p.alerts || []) out.push(serverLine("blocked", "! " + a));
  if (p.not_read_yet) out.push(html`<div class="pend">! not read yet: the console hasn't managed a first read of the state store</div>`);
  else if (p.stale) out.push(html`<div class="pend">${"! not checked for " + secs((nowMs - (p.read_ms || 0)) / 1000) + ": these rows may be out of date"}</div>`);
  const st = p.stream;
  if (st) {
    let text = strip(st.endpoint) + " (" + strip(st.bucket) + ") · ledger " + strip(st.state);
    if (st.last_sync_ms) text += " · last sync " + secs((nowMs - st.last_sync_ms) / 1000) + " ago";
    else if (st.behind_secs !== null && st.behind_secs !== undefined) text += " · no sync yet in " + secs(st.behind_secs);
    const cls = st.state === "streaming" ? "" : st.state === "starting" ? "pend" : "blocked";
    // An error is shown while the stream isn't streaming, or if it came after the last sync: an
    // old one, recovered from, isn't news.
    const live = st.error && (st.state !== "streaming" || (st.error_ms || 0) > (st.last_sync_ms || 0));
    out.push(row("Record backup", cls, text, live ? "last error" + (st.error_ms ? " " + secs((nowMs - st.error_ms) / 1000) + " ago" : "") + ": " + strip(st.error) : null));
  }
  for (const a of p.audit || []) {
    let text = a.behind ? a.behind + " record" + (a.behind === 1 ? "" : "s") + " behind (oldest " + secs(a.behind_secs) + ")" : "caught up";
    // A jsonl sink to stdout is fed only by `wicket audit export` in the foreground: behind is expected.
    if (a.manual) text += " (manual: fed only by `wicket audit export`)";
    text += " at " + a.seq + " of " + a.head + " · last checkpoint " + (a.checkpoint_at ? secs(nowMs / 1000 - a.checkpoint_at) + " ago" : "never");
    out.push(row("Activity export to " + strip(a.sink), a.error ? "blocked" : a.behind && !a.manual ? "pend" : "", text, a.error ? "last error: " + strip(a.error) : null));
  }
  // An error already alerted on (the config alert quotes it) isn't said twice.
  for (const e of p.errors || []) if (!(p.alerts || []).some(a => a.startsWith(e))) out.push(serverLine("blocked", "! " + e));
  return out;
}

// The record backup and the export first, then the control host's disk, then each node.
function healthView(s) {
  const h = s.health || {}, nodes = h.nodes || [];
  return html`${h.state_store ? stateStoreRows(h.state_store, s.now * 1000) : nothing}${h.control_disk_pct > 85 ? html`<div class="blocked">${"! the control host's disk is " + h.control_disk_pct + "% full"}</div>` : nothing}${nodes.length ? nodes.map(healthRow) : html`<div class="empty">No node has reported its health yet.</div>`}`;
}

// A node from `wicket node create` (#294): past its lease it is released by the reconciler, unless
// a run still holds it, which is a warning until renewals exist (#56). The name and when its lease
// ends; the UUID quiet on a line of its own (#649).
function placedRow(p) {
  const cmd = "wicket node release " + strip(p.id);
  const after = p.past_lease && p.held_by
    ? html`<div class="callout warn">Lease ended ${time(p.lease_until)}${"; still billing: run " + strip(p.held_by) + " holds it. Release it on the host:"}<code class="block">${cmd}</code>${copyButton(cmd)}</div>`
    : p.past_lease ? html`<div class="meta">Lease ended ${time(p.lease_until)}; released at the reconciler's next pass.</div>` : nothing;
  return html`<div class="lease"><div class="run-head"><span class="run-name mono">${strip(p.name)}</span>${p.past_lease ? nothing : html`<span class="meta">lease ends ${time(p.lease_until)}</span>`}</div><div class="meta mono quiet">${strip(p.id)}</div>${after}</div>`;
}

// ---- the view ----

let formDrawn = false;
function renderSettings(s) {
  last = s;
  const st = s.standing || {};
  keyed("standing-rules", st.rules || [], standingRuleRow, "No standing rules: each request waits for a decision.");
  keyed("capacity", s.capacity || [], capacityRow, "No capacity grants: every `wicket node create` waits for a decision.");
  principals.done();
  const form = document.getElementById("capacity-form");
  if (form && !formDrawn) { draw(capacityForm(), form); formDrawn = true; }
  const health = document.getElementById("health");
  if (health) draw(healthView(s), health);
  const placed = document.getElementById("placed");
  if (placed) draw((s.placed || []).length ? s.placed.map(placedRow) : html`<div class="empty">No leased nodes.</div>`, placed);
}

g.wicketSettings = { renderSettings };

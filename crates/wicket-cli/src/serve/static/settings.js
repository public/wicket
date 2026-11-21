// Settings (docs/explanation/console-design.md), drawn with lit-html (#574, the port's step 4b): the
// rules agents are always allowed, spending limits (capacity grants) and the form that adds one, the
// servers' health with the record backup and the activity export, and the rented servers. Every
// string from the API goes in as a template value, which lit-html sets as text, never as HTML.
//
// As the other views, it uses console.js's helpers by their bare names (strip, signed, post, …);
// every signed action is console.js's.
import { html, nothing } from "lit-html";
import { repeat } from "lit-html/directives/repeat.js";
import { draw, time, kv, code, copyButton, serverText, serverLine, keeper } from "./ui.js";

const g = globalThis;

// ---- Revoke, asked first (#640) ----

// Revoke on a capacity grant or a standing rule: unsigned, since it only narrows, but asked in the
// page first, and set apart from Renew. The question replaces the row's buttons until answered.
// Each row's question, by key: "ask" (shown), "sending" (Revoke tapped), "sent" (done: shown, still
// disabled, until the next poll draws the row as it is now). A failed revoke asks again.
const asking = new Map();
let last = null;
// Drawn again for a change on the page, not a poll: what was sent waits for the poll.
const again = () => { if (last) renderSettings(last, false); };
function revokeButtons(key, question, others, go) {
  const state = asking.get(key);
  if (!state) {
    const ask = () => {
      if (!settled()) { toast("The list just changed: check the row and tap again."); return; }
      asking.set(key, "ask"); again(); layoutMoved();
    };
    return html`<div class="buttons">${others}<button class="deny apart" @click=${ask}>Revoke…</button></div>`;
  }
  // The question moved the row: a second tap of a double tap mustn't land on its Revoke.
  const yes = async () => {
    if (!settled() || asking.get(key) !== "ask") return;
    asking.set(key, "sending"); again();
    asking.set(key, (await go()) ? "sent" : "ask"); again();
  };
  return html`<div class="buttons"><div class="callout warn ask">${question}</div><button class="deny" ?disabled=${state !== "ask"} @click=${yes}>Revoke</button><button ?disabled=${state !== "ask"} @click=${() => { asking.delete(key); again(); }}>Cancel</button></div>`;
}
// Whether a revoke went through (its toast says so either way); a poll is asked for.
const revoked = async (path, id) => {
  try { toast((await post(path, { id })).ok); refresh(); return true; } catch (e) { toastError(e); return false; }
};

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
  const revoke = () => revoked("/api/capacity/revoke", gr.id);
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
  const revoke = () => revoked("/api/standing/revoke", r.id);
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

// ---- agents held on lost servers (#690) ----

// A fenced run: its box may still be running on a node that is revoked or no longer enrolled, so its
// agent isn't woken. Released (signed, with a reason) from a form in its own row: the row is kept
// across polls, so what is typed survives, and it can only release this run.
const releasing = new Set();
function fencedRow(x) {
  const f = x.fence || {};
  const open = releasing.has(x.id);
  const close = e => { const t = e.target.closest(".lease").querySelector("textarea"); if (t) t.value = ""; releasing.delete(x.id); again(); };
  const go = e => {
    const text = e.target.closest(".lease").querySelector("textarea");
    if (!text.value.trim()) { toast("Say why: the reason goes in the activity log."); return; }
    signed({ action: "release_fence", run: x.id, reason: text.value }, () => { text.value = ""; releasing.delete(x.id); again(); });
  };
  const ask = e => { releasing.add(x.id); again(); e.target.closest(".lease").querySelector("textarea").focus(); };
  return html`<div class="lease"><div class="run-head"><span class="run-name mono">${strip(x.id)}</span><span class="meta">${f.fenced_until_ms ? html`fenced until ${time(f.fenced_until_ms / 1000)}` : "fenced until its node confirms the box stopped"}</span></div><div class="meta">${"node " + strip(f.node) + " (" + strip(f.node_status) + ")"}${f.node_seen_ms ? html` · last reported ${time(f.node_seen_ms / 1000)}` : " · never reported"}</div><div class="meta">${strip(f.why)}</div><div class="buttons"><button class="deny" @click=${ask}>Release…</button></div><div class="stack" ?hidden=${!open}><label class="meta">${"Release " + strip(x.id) + "'s fence: its agent can be woken and the run ended, while its box may still be running on node " +
    strip(f.node) + ". Only if that node will never run it again. Say why (it goes in the activity log):"}</label><textarea></textarea><div class="buttons"><button class="deny" @click=${go}>Release</button><button @click=${close}>Cancel</button></div></div></div>`;
}

// ---- keys and passwords, task setups, organisation rules, passkeys ----

// The vault by name (console.js's secrets section says how a value is handled): the server sends no
// value, nor anything derived from one. Each button opens console.js's form, which signs.
function secretUse(u) {
  const where = "Used by " + u.manifest + " (zone " + u.zone + ")";
  return strip(u.use === "llm" ? where + " as the model key" + (u.provider ? " (" + u.provider + ")" : "")
    : where + ": sent to " + u.host + " in its " + u.header + " header" + (u.format ? ", as " + u.format : "") + (u.optional ? " (optional)" : ""));
}
function secretsView(v) {
  const uses = list => (list || []).map(u => html`<div class="meta">${secretUse(u)}</div>`);
  const stored = x => html`<div class="secret"><div class="row"><span class="mono">${strip(x.name)}</span><span class="risk ${x.kind === "reference" ? "r2" : "r0"}">${x.kind === "reference" ? "read from a file on the host" : "stored"}</span></div><div class="meta">${(x.hosts || []).length ? "sent only to " + x.hosts.map(strip).join(", ") : "bound to no host: sent nowhere"}</div>${x.reference ? html`<div class="meta">${"refers to " + strip(x.reference.file) + (x.reference.pointer ? "#" + strip(x.reference.pointer) : "") + ", read at each use"}</div>` : nothing}<div class="meta">${x.set_at ? "last set " + at(x.set_at) : "last set: unknown"}</div>${uses(x.used_by)}${(x.used_by || []).length ? nothing : html`<div class="meta">no listed manifest uses it</div>`}${(x.runs || []).length ? html`<div class="meta">${"running now: " + x.runs.map(r => strip(r.run)).join(", ")}</div>` : nothing}<div class="buttons">${x.kind !== "reference" ? html`<button @click=${() => openSecret("set", x)}>Replace value…</button>` : nothing}<button @click=${() => openSecret("hosts", x)}>Hosts…</button><button class="deny" @click=${() => openSecret("delete", x)}>Delete…</button></div></div>`;
  const missing = m => html`<div class="secret"><div class="row"><span class="mono">${strip(m.name)}</span><span class="risk r3">needed, not set</span></div>${uses(m.used_by)}<div class="buttons"><button class="approve" @click=${() => openSecret("set", { name: m.name, hosts: (m.used_by || []).filter(u => u.host).map(u => u.host), missing: true })}>Set…</button></div></div>`;
  const none = !(v.secrets || []).length && !(v.missing || []).length;
  return html`${repeat(v.secrets || [], x => x.name, stored)}${repeat(v.missing || [], m => m.name, missing)}${none ? html`<div class="empty">No secrets in the vault.</div>` : nothing}<div class="buttons"><button @click=${() => openSecret("set", null)}>New secret…</button></div><div class="note">${"Values are never shown, here or anywhere. " + strip(v.link_cli_only ||
    "References (a file on the host, like a harness login) are made on the host: wicket secret link.")}</div>`;
}

// The task setups (#172) the server lists; each opens in console.js's editor.
const manifestsView = ms => html`${repeat(ms, m => m.root + "/" + m.name, m => html`<div class="row"><span class=${m.valid ? "mono" : "blocked mono"}>${strip(m.root + "/" + m.name) + (m.valid ? "" : " · invalid")}</span><button class="link" @click=${() => openManifest(m.root, m.name)}>${m.root === "manifests" ? "view / edit" : "view"}</button></div>`)}<button class="link" @click=${() => openManifest("manifests", null)}>new manifest</button>`;

// The organisation's rules (#173): fetched at most every 30 s, as they change rarely.
let policyAt = 0;
async function renderPolicy() {
  if (policyAt && performance.now() - policyAt < 30000) return;
  policyAt = performance.now();
  const box = document.getElementById("policy");
  if (!box) return;
  try {
    const p = await getJson("/api/policy");
    draw(html`${!p.installed ? html`<div class="note">No org policy applied: tokens carry their zone's policy only (wicket policy apply).</div>`
      : html`${kv("applied", p.installed + (p.current.matches_applied === false ? " · org.cedar was changed by hand: every mint is refused until it is applied" : ""))}<pre class="src">${p.current.cedar || ""}</pre>`}${p.versions.map(v => {
      const a = v.applied.length ? v.applied[v.applied.length - 1] : null;
      return kv("version " + v.version + (v.current ? " (current)" : ""), a ? "applied " + at(a.at) + " by " + a.by : "kept");
    })}${p.runs.map(r => kv(r.run, "zone " + r.zone + " · policy " + (r.policy || "none") + " · " + r.status))}`, box);
  } catch (e) { draw(html`<div class="blocked">${strip(e.message)}</div>`, box); }
}

// Your passkeys; adding a device (#711: a signed enrol_link, whose one-time link console.js keeps in
// `enrolLink` and shows here until it expires); and signing out (console.js's signOut, which forgets
// the link and this module's open questions).
function operatorView(s) {
  const link = enrolLink && enrolLink.until > Date.now() ? enrolLink : null;
  if (!link) enrolLink = null;
  return html`${(s.passkeys || []).map(k => html`<div class="row"><span>${"passkey: " + strip(k.name)}</span><span class="mono">${String(k.id).slice(0, 16) + "…"}</span></div>`)}<div class="buttons"><button @click=${() => signed({ action: "enrol_link" })}>Add a device</button><button @click=${signOut}>Sign out</button></div>${link
    ? html`<div class="callout"><div>${"Open this on the new device (once, until " + new Date(link.until).toLocaleTimeString() + "):"}</div><code class="block">${link.link}</code>${copyButton(link.link)}</div>` : nothing}<div class="note">${code("Adding a device makes a one-time link, signed with your passkey; the new device is you, with your authority. Or on the host: `wicket operator enrol-link`.", ["wicket operator enrol-link"])}</div>`;
}

// ---- the view ----

// The capacity form's element, once drawn: drawn again only if the page's element is a new one.
const formsDrawn = new WeakSet();
function renderSettings(s, poll = true) {
  last = s;
  // A question or a release form for a row that is gone goes with it; a poll ends a sent revoke's wait.
  const live = new Set([...(s.capacity || []).map(g => "cap:" + g.id), ...(((s.standing || {}).rules) || []).map(r => "rule:" + r.id)]);
  for (const [k, v] of [...asking]) if (!live.has(k) || (poll && v === "sent")) asking.delete(k);
  const fenced = new Set((s.fenced || []).map(x => x.id));
  for (const id of [...releasing]) if (!fenced.has(id)) releasing.delete(id);
  const st = s.standing || {};
  keyed("standing-rules", st.rules || [], standingRuleRow, "No standing rules: each request waits for a decision.");
  keyed("fenced", s.fenced || [], fencedRow, "None: no agent's box is held on a node that is revoked or no longer enrolled. An enrolled node's boxes are released by the node, or by revoking it first.");
  keyed("capacity", s.capacity || [], capacityRow, "No capacity grants: every `wicket node create` waits for a decision.");
  principals.done();
  const form = document.getElementById("capacity-form");
  if (form && !formsDrawn.has(form)) { draw(capacityForm(), form); formsDrawn.add(form); }
  const health = document.getElementById("health");
  if (health) draw(healthView(s), health);
  const placed = document.getElementById("placed");
  if (placed) draw((s.placed || []).length ? s.placed.map(placedRow) : html`<div class="empty">No leased nodes.</div>`, placed);
  const secrets = document.getElementById("secrets");
  if (secrets) draw(secretsView(s.secrets || { secrets: [], missing: [] }), secrets);
  const manifests = document.getElementById("manifests");
  if (manifests) draw(manifestsView(s.manifests || []), manifests);
  const operator = document.getElementById("operator");
  if (operator) draw(operatorView(s), operator);
  renderPolicy();
}

// Signed out: no question or form left open for the next sign-in.
function reset() { asking.clear(); releasing.clear(); last = null; }

g.wicketSettings = { renderSettings, reset };

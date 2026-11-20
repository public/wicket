// The Activity view (docs/explanation/console-design.md), drawn with lit-html (#574, the port's step
// 4): the log of what happened, its filters, and the recent decisions; and a line of the log, which
// an agent's page (agents.js) draws too. Every string from the API goes in as a template value, which
// lit-html sets as text, never as HTML.
//
// What a record says is console.js's `sentence(op)` (tested under node, serve/tests/console_ui.js);
// this draws it. As inbox.js, it uses console.js's helpers by their bare names.
import { html, nothing } from "lit-html";
import { repeat } from "lit-html/directives/repeat.js";
import { draw, time, kv, wrapped } from "./ui.js";

const g = globalThis;

// ---- a line, and its "why?" (#173) ----

// What a decision's "why?" holds, by the record's seq: open or not, and what the server explained
// (null while it is asked). Kept across polls, so an opened explanation stays open.
const explained = new Map();
// Whoever draws lines redraws them when an explanation opens or arrives: the log and the agent page.
const redraws = new Set();
const redraw = () => { for (const f of redraws) f(); };

async function explain(seq) {
  const e = explained.get(seq);
  if (e) { e.open = !e.open; redraw(); return; }
  const now = { open: true, view: html`<div class="meta">loading…</div>` };
  explained.set(seq, now);
  redraw();
  try {
    const x = await getJson("/api/explain/" + encodeURIComponent(seq));
    now.view = explainView(x);
  } catch (err) { now.view = html`<div class="blocked">${strip(err.message)}</div>`; }
  redraw();
}

// A decision explained: what was recorded, then the run's token as its node holds it now.
function explainView(x) {
  const r = x.recorded, n = x.against_token_now;
  return html`${kv("request", r.method + " " + r.host + r.path + " (" + (r.risk || "?") + ")")}${kv("recorded", String(r.outcome) + " on " + r.decided_on + " at " + at(r.at) + ": " + localTimes(r.detail))}${kv("run", x.run + " · policy " + (x.policy || "none"))}${n.available
    ? html`${kv("token now", n.decision)}<pre class="src">${n.why}</pre>${kv("zone says", n.zone_says)}<div class="note">Against the run's token as its node's feed holds it now: grants and policy may have changed since it was decided.</div>`
    : html`<div class="note">${"Can't evaluate it now: " + localTimes(n.why)}</div>`}`;
}

// One record (#646): its local time, a tag for its kind, then what happened; a decision on a run's
// request has a "why?" that opens its explanation under it. `hidden` is the filter's.
function lineView(op, hidden) {
  const l = sentence(op);
  const e = l.why ? explained.get(op.seq) : null;
  const why = l.why ? html` <button class="link" aria-expanded=${e && e.open ? "true" : "false"} @click=${() => explain(op.seq)}>why?</button>` : nothing;
  return html`<div class="logline" data-cat=${l.cat} ?hidden=${hidden}>${op.ts ? time(op.ts, clock(op.ts)) : html`<span></span>`}<span class="tag ${l.tone}">${l.tag}</span><span class="text">${l.text}${why}</span></div>${e && e.open && !hidden ? html`<div class="explained">${e.view}</div>` : nothing}`;
}

// ---- the view ----

// The log's filters: everything, or one kind of line.
const FILTERS = [["all", "Everything"], ["blocked", "Blocked"], ["decisions", "Decisions"], ["agents", "Agents"], ["servers", "Servers"]];
let filter = "all";
let last = null;

// A recent decision on a request: allowed or refused, by whom, for what.
function decidedView(x) {
  const pill = "pill " + (({ granted: "good", denied: "bad" })[x.status] || "");
  return html`<div class="decided"><div class="run-head"><span class=${pill}>${({ granted: "allowed", denied: "refused" })[x.status] || strip(x.status)}</span><span>${runName(x.run) + ": " + verb(x) + " "}</span>${wrapped("mono inline", strip(x.host + x.path))}</div><div class="meta">${strip(x.id) + " · zone " + strip(x.zone) + " · asked "}${time(x.created_at, rel(x.created_at))}</div></div>`;
}

function renderActivity(s) {
  last = s;
  const f = document.getElementById("filters");
  if (f) draw(FILTERS.map(([k, label]) => html`<button type="button" class="chip" aria-pressed=${k === filter ? "true" : "false"} @click=${() => { filter = k; renderActivity(last); }}>${label}</button>`), f);
  const box = document.getElementById("audit");
  if (box) {
    const ops = (s.audit || []).slice().reverse();
    const seqs = new Set(ops.map(op => op.seq));
    for (const k of [...explained.keys()]) if (!seqs.has(k)) explained.delete(k);
    const shown = op => { const c = sentence(op).cat; return filter === "all" || c === filter; };
    draw(ops.length ? repeat(ops, op => op.seq, op => lineView(op, !shown(op))) : html`<div class="empty">No activity yet.</div>`, box);
  }
  const d = document.getElementById("decided");
  if (d) draw((s.decided || []).length ? (s.decided || []).map(decidedView) : html`<div class="empty">No decisions yet.</div>`, d);
}
redraws.add(() => { if (last) renderActivity(last); });

g.wicketActivity = { renderActivity, lineView, redraws };

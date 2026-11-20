// The Agents view and an agent's page (docs/explanation/console-design.md), drawn with lit-html
// (#574, the port's step 3): the list of runs, Start an agent, and an agent's page (its head, what it
// can reach, what it did). Every string from the API goes in as a template value, which lit-html
// sets as text, never as HTML.
//
// As inbox.js, it uses console.js's helpers by their bare names (strip, rel, idEl, signed, …), and
// console.js calls window.wicketAgents's functions where it drew these itself. The Stop form is
// console.html's own and stays console.js's, as does every signed action.
import { html, render, nothing } from "lit-html";
import { repeat } from "lit-html/directives/repeat.js";

const g = globalThis;

// lit-html renders after what a container already holds: the first time, it is emptied.
const owned = new WeakSet();
function draw(value, box) {
  if (!owned.has(box)) { box.replaceChildren(); owned.add(box); }
  render(value, box);
}

const time = (t, text) => html`<time title=${t ? iso(t) : nothing} datetime=${t ? iso(t) : nothing}>${text === undefined ? at(t) : text}</time>`;

// ---- a run, in the list and as the head of its page ----

// Elements from console.js's helpers (the relative times, which refreshRel keeps true between polls;
// the run id, which a tap shows whole) are made once per run and place, and kept while the run's
// times are the same, so a poll leaves a tapped id open.
const runMemo = new Map();
function runEls(s, x, page) {
  const id = (page ? "page:" : "list:") + x.id, key = JSON.stringify([x.started_at, x.ended_at]);
  let m = runMemo.get(id);
  if (!m || m.key !== key) {
    m = { key, started: relEl(x.started_at, "started ", s.now), ended: x.ended_at ? relEl(x.ended_at, "ended ", s.now) : null, id: idEl(x.id) };
    runMemo.set(id, m);
  }
  return m;
}

const STATE_WORDS = { running: "working", exited: "finished", revoked: "stopped", hibernated: "asleep" };
const STATE_TONE = { running: "good", revoked: "bad", failed: "bad", hibernated: "info" };

// A run: who, where, its state and times, its pages; an ACP agent's session opens on its own page,
// where prompts are sent (#198). The agent first, its zone and state; the run id quieter under it
// (#641). A program run has no agent.
function runRow(s, x, page) {
  const name = x.agent ? strip(x.agent) : "program run";
  const status = x.revoked ? "revoked" : String(x.status || "");
  const waiting = x.waiting !== undefined ? x.waiting : ((s && s.pending) || []).some(p => p.run === x.id);
  const m = runEls(s, x, page);
  const agentHref = "#agent/" + encodeURIComponent(x.id);
  // An ACP run's live session (#327): its own page, opened with a passkey there.
  const live = x.acp && x.status === "running" && !x.revoked
    ? html`<a class="session" href=${"/session?run=" + encodeURIComponent(x.id)}>Live session</a>` : nothing;
  // A remote session (#169): where the owner drives it, in the vendor's app.
  const remote = x.remote_url && x.remote_url.startsWith("https://")
    ? html`<a class="session" href=${x.remote_url} target="_blank" rel="noopener noreferrer">Remote Control session ↗</a>` : nothing;
  // A running agent can have its identity revoked, signed: from its page only.
  const stop = page && x.status === "running" && x.has_identity && !x.revoked
    ? html`<span class="acts"><button class="deny" @click=${() => openRunForm("revoke", x.id)}>Stop agent…</button></span>` : nothing;
  return html`<div class="row run"><div><div class="run-head">${page ? html`<h2 class="run-name">${name}</h2>` : html`<a class="run-name" href=${agentHref}>${name}</a>`}<span class="meta"> · zone ${strip(x.zone)}</span><span class="pill ${waiting ? "warn" : STATE_TONE[status] || ""}">${waiting ? "waiting for you" : STATE_WORDS[status] || strip(status)}</span></div><div class="meta">${m.started}${m.ended ? html` · ${m.ended}` : nothing} · ${m.id}</div><div class="links">${live}${remote}${page ? nothing : html`<a href=${agentHref}>What it can reach ›</a>`}</div></div>${stop}</div>`;
}

// The list: a row per run, kept across polls by its id. When a row or the order changes, the layout
// moved, and taps wait a moment (console.js's `settled`), as on the request cards.
let lastRuns = null;
function renderRuns(s) {
  const box = document.getElementById("runs");
  if (!box) return;
  const runs = (s.runs || []).map(x => ({ ...x, waiting: (s.pending || []).some(p => p.run === x.id) }));
  const live = new Set(runs.map(x => "list:" + x.id));
  for (const k of [...runMemo.keys()]) if (k.startsWith("list:") && !live.has(k)) runMemo.delete(k);
  draw(runs.length ? repeat(runs, x => x.id, x => runRow(s, x, false)) : html`<div class="empty">No runs yet.</div>`, box);
  const key = JSON.stringify(runs);
  if (lastRuns !== null && key !== lastRuns) layoutMoved();
  lastRuns = key;
}

// ---- an agent's page ----

function renderAgentHead(s, run) {
  const box = document.getElementById("agent-head");
  if (!box) return;
  const x = ((s && s.runs) || []).find(r => r.id === run);
  for (const k of [...runMemo.keys()]) if (k.startsWith("page:") && k !== "page:" + run) runMemo.delete(k);
  draw(x ? runRow(s, x, true)
    : html`<h2>Agent</h2><p class="note">This agent run isn't in the latest list (only the 15 most recent are).</p>`, box);
}

// What it did: its records, newest first, each line as the Activity view draws it (activity.js),
// kept by its record across polls, so it (and its "why?") stays put.
let logOf = null;
function renderAgentLog(s, run) {
  const box = document.getElementById("agent-log");
  if (!box) return;
  logOf = [s, run];
  const mine = ((s && s.audit) || []).filter(op => op.run === run).slice().reverse();
  const act = g.wicketActivity;
  // An explanation opened or arrived: the agent's log is drawn again (while its page is open).
  if (act && !act.redraws.has(redrawLog)) act.redraws.add(redrawLog);
  draw(mine.length && act ? repeat(mine, op => op.seq, op => act.lineView(op, false)) : html`<div class="empty">Nothing recorded for it in the latest activity.</div>`, box);
}
function redrawLog() { if (logOf && view === "agent") renderAgentLog(...logOf); }

// ---- what a run can reach (#173, #651) ----

// What it can reach first (its zone's rules, its live grants, the standing rules that apply to it,
// each with when it ends), then what its node holds, and the token's internals (blocks, every grant,
// the zone's Cedar) folded under Details. Every string is text: block sources hold strings an agent
// chose (a grant's path).
const pathsText = p => (p || ["/**"]).map(strip).join(" ");
const kv = (k, v) => html`<div class="row"><span class="meta">${k}</span><span class="mono">${strip(v)}</span></div>`;
const whenMs = ms => ms ? at(ms / 1000) : "—";
function reachLine(text, end, note) {
  const meta = end !== undefined || note ? html`<div class="meta">${end === undefined ? nothing : end}${note ? (end !== undefined ? " · " : "") + note : nothing}</div>` : nothing;
  return html`<div class="reach"><div class="mono">${text}</div>${meta}</div>`;
}

function authorityView(a, run, now) {
  const t = a.token || {};
  const reach = [];
  for (const r of t.reach || []) reach.push(reachLine(verbsOf(r.methods) + " " + strip(r.host) + "  " + pathsText(r.paths), undefined,
    "from its zone's rules" + (r.allow_dangerous ? "; including requests that can't be undone" : "") +
    ((r.decode_slash || []).length ? "; reads an encoded slash (%2F) as / in path part " + r.decode_slash.map(Number).join(", ") : "")));
  for (const gr of (t.grants || []).filter(gr => !gr.revoked && (!gr.expires_at || gr.expires_at > now))) {
    // All that the grant reaches (#715 review): a standing grant is a rule on the host (its methods,
    // path globs and allow_dangerous); a prefix grant covers every path under its path.
    const sr = gr.standing;
    const what = sr ? verbsOf(sr.methods) + " " + strip(gr.host) + "  " + pathsText(sr.paths)
      : verb(gr) + " " + strip(gr.host + gr.path) + (gr.prefix ? " and every path under it" : "");
    reach.push(reachLine(what, html`<span>allowed by ${decider(gr.approved_by)}; ends ${time(gr.expires_at)}</span>`,
      (gr.uses == null ? "any number of times" : plural(gr.uses, "more time", "more times")) +
      (sr && sr.allow_dangerous ? " · including requests that can't be undone" : "") +
      (gr.reached_node === false ? " · not yet on its server" : "")));
  }
  const st = (lastState && lastState.standing && lastState.standing.rules) || [];
  const row = ((lastState && lastState.runs) || []).find(x => x.id === run) || {};
  for (const r of st.filter(r => r.live && (r.for === "zone" ? r.zone === t.zone : row.agent && String(r.principal || "").endsWith("/z/" + row.zone + "/a/" + row.agent)))) {
    const end = html`<span>always allowed, ${r.expires_at ? time(r.expires_at, "ends " + at(r.expires_at)) : "until removed"}</span>`;
    reach.push(reachLine(verbsOf(r.rule.methods) + " " + strip(r.rule.host) + "  " + pathsText(r.rule.paths), end, (r.for === "zone" ? "for every agent in its zone" : "for this agent") +
      (r.rule.allow_dangerous ? "; including requests that can't be undone" : "") + " · allowed by " + decider(r.decided_by)));
  }
  // What its zone forbids beats everything above, a grant included.
  for (const f of t.forbid || []) reach.push(reachLine("never " + strip(f.host) + "  " + pathsText(f.paths), undefined, "forbidden by its zone's rules, even if you allow it"));
  if (!t.held) reach.push(html`<div class="note">No token now: ${strip(t.why)}</div>`);
  else if (!reach.length) reach.push(html`<div class="empty">Nothing: everything it asks for waits for you.</div>`);

  const sl = a.holdings && a.holdings.slice;
  const held = a.holdings ? [
    kv("keys it can use", a.holdings.secrets.length ? a.holdings.secrets.map(strip).join(", ") : "none"),
    kv("model budget left on its server", sl ? num(sl.requests) + " requests, " + num(sl.output_tokens) + " output tokens" + (sl.input_tokens != null ? ", " + num(sl.input_tokens) + " input tokens" : "") : "none"),
  ] : nothing;
  const details = t.held ? html`<details class="more"><summary>Technical details: its token, grants and zone policy</summary>${kv("status", strip(a.status) + (a.feed ? " · node feed epoch " + strip(a.feed.epoch) : ""))}${kv("token", "box " + strip(t.box_path) + " · epoch " + strip(t.epoch) + " · zone " + strip(t.zone) + " · minted by " + strip(t.issued_by) +
      (t.loads === true ? " · loads" : " · does NOT load: " + strip((t.loads || {}).error || "")))}${(t.blocks || []).map(b => html`<div class="row"><span class=${b.revoked ? "blocked" : "ok"}>${"block " + b.index + " · " + strip(b.kind) + (b.revoked ? " · REVOKED" : "")}</span><span class="meta">${"revocation " + strip(b.revocation_fingerprint) + (b.signed_by ? " · signed by " + strip(b.signed_by) : "")}</span></div><pre class="src">${b.source}</pre>`)}${(t.grants || []).map(gr => kv(gr.id, gr.method + " " + gr.host + gr.path + " · " + (gr.uses == null ? "unlimited uses" : gr.uses + " uses (counted on the node)") +
      " · ends " + at(gr.expires_at) + " · approved by " + (gr.approved_by || "?") + " at " + at(gr.approved_at) +
      (gr.revoked ? " · revoked" : "") + (gr.reached_node === false ? " · not yet on its node" : "")))}${t.zone_cedar ? html`<div class="meta">zone policy (Cedar, generated from the manifest)</div><pre class="src">${t.zone_cedar}</pre>` : nothing}</details>` : nothing;

  return html`<h4>Can reach</h4>${reach}<h4>Where it runs</h4>${a.revoked ? html`<div class="callout warn">${"Stopped by " + strip(a.revoked.by) + ": " + strip(a.revoked.reason)}</div>` : nothing}${kv("server", strip(a.node))}${a.deadline ? kv("its permissions end", whenMs(a.deadline.until_ms) + (a.deadline.stopped ? " (stopped)" : "")) : nothing}${held}${kv("organisation rules", a.policy.version ? strip(a.policy.version) + (a.policy.current ? " (current)" : " (not the installed " + strip(a.policy.installed || "none") + ")") : "none")}${details}`;
}

// Into the agent page's detail card (console.js's openDetail). Each answer is drawn into a fresh
// element, since the card is shared with Activity's "why?" and emptied on each open.
async function showAuthority(run) {
  const body = openDetail("Permissions");
  const out = document.createElement("div");
  try {
    const a = await getJson("/api/runs/" + encodeURIComponent(run) + "/authority");
    render(authorityView(a, run, nowSecs()), out);
    body.replaceChildren(...out.childNodes);
  } catch (e) { body.replaceChildren(el("div", "blocked", strip(e.message))); }
}

// ---- Start an agent ----

// Runs start only from manifests the server lists (its allowlisted directories); the page sends a
// root and a file name, never a path. Its select and textarea are the same elements across polls, so
// what the operator picked and typed stays.
let startPick = null;
const pickOf = m => JSON.stringify([m.root, m.name]);
function renderStart(s) {
  const box = document.getElementById("start");
  if (!box) return;
  const ms = s.manifests || [];
  if (!ms.length) { draw(html`<div class="empty">No manifests to start: put one in the installation's manifests directory.</div>`, box); return; }
  // What a select shows by itself: the first that can start.
  if (!ms.some(m => m.valid && pickOf(m) === startPick)) startPick = (ms.find(m => m.valid) && pickOf(ms.find(m => m.valid))) || null;
  const m = ms.find(x => pickOf(x) === startPick);
  // The zone view (#62): which hosts the egress proxy inspects and which it splices through; and the
  // image its box starts from (#171), or why it can't start.
  const hosts = html`${m && m.valid ? (m.image ? html`<div>${"image " + strip(m.image)}</div>` : html`<div class="pend">${"image refused: " + strip(m.image_error)}</div>`) : nothing}${((m && m.hosts) || []).map(h => html`<div><span class=${h.mode === "spliced" ? "pend" : "ok"}>${(h.mode === "spliced" ? "spliced" : "inspected").padEnd(10)}</span>${strip(h.host) + (h.mode === "spliced" ? " (every method and path; not inspected)" : " (" + strip(h.why) + ")")}</div>`)}`;
  const pick = e => { startPick = e.target.value; renderStart(lastState || s); };
  const go = e => {
    if (!startPick) return;
    const task = e.target.closest("#start").querySelector("textarea");
    const [root, manifest] = JSON.parse(startPick);
    signed({ action: "start_run", root, manifest, task: task.value });
    task.value = "";
  };
  draw(html`<select @change=${pick}>${ms.map(x => html`<option .value=${pickOf(x)} ?disabled=${!x.valid} ?selected=${pickOf(x) === startPick}>${strip(x.root + "/" + x.name) + (x.valid ? " · " + strip(x.agent ? "agent " + x.agent : "program " + x.program) + " · zone " + strip(x.zone) : " · invalid")}</option>`)}</select><div class="meta">${hosts}</div><textarea placeholder="Task (optional; replaces the manifest's task, agents only)"></textarea><div class="buttons"><button class="approve" @click=${go}>Start run</button></div><div class="meta">The run's principal is you (this passkey), not the host user.</div>`, box);
}

g.wicketAgents = { renderRuns, renderAgentHead, renderAgentLog, showAuthority, renderStart };

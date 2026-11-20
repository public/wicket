// The redesigned console's Inbox, Agents and an agent's page, as lit-html templates rendered into the
// light DOM (the console's stylesheet is global). Every string from the API goes in as a text binding.
import { html, render, nothing } from "../vendor/lit-html/lit-html.js";
import { repeat } from "../vendor/lit-html/directives/repeat.js";
import {
  strip, setSkew, nowSecs, plural, rel, clock, iso, at, whenMs, riskClass, riskLabel, riskCode, span, asks, verb, verbsOf,
  pathsText, num, problemList, describeOp,
} from "./helpers.js";

let s = null;              // the last state polled
let signedIn = false, stale = "";
let view = "inbox", agentRun = "";
let authority = { run: "" }; // { run, a } or { run, err }: the agent page's permissions
const shownIds = new Set(); // request cards whose agent identity is unfolded

// ---- small pieces ----
const time = (t, text, cls) => html`<time class=${cls || nothing} title=${t ? iso(t) : nothing} datetime=${t ? iso(t) : nothing}>${text ?? at(t)}</time>`;
function idEl(id) {
  id = strip(id);
  return html`<span class="id-short" title=${id}>${id.length <= 18 ? id : html`<span class="id-head">${id.slice(0, -6)}</span><span class="id-tail">${id.slice(-6)}</span>`}</span>`;
}
// A URL broken only after its slashes and dots, so it wraps at a segment, not mid-word.
const wrapped = (cls, text) => html`<div class=${cls}>${String(text).split(/(?<=[/.?&])/).map(p => html`${p}<wbr>`)}</div>`;
const kv = (k, v) => html`<div class="row"><span class="meta">${k}</span><span class="mono">${strip(v)}</span></div>`;
const empty = text => html`<div class="empty">${text}</div>`;
const runName = id => { const x = ((s && s.runs) || []).find(r => r.id === id); return x ? (x.agent ? strip(x.agent) : "a program") : strip(id); };

// ---- Inbox ----
function whoAsks(p) {
  const id = p.identity || {};
  if (id.verified) {
    const open = shownIds.has(p.id);
    const flip = () => { open ? shownIds.delete(p.id) : shownIds.add(p.id); draw(); };
    return [html`<span class="who-ask"><span class="ok">✓ </span><button type="button" class="idname" title="Show its identity" aria-expanded=${String(open)} @click=${flip}>${strip(id.agent)}</button> · zone ${strip(id.zone)}<div class="idline" ?hidden=${!open}>${strip(id.id)}</div></span>`, true];
  }
  if ((id.error || "").startsWith("no identity was issued")) return [html`<span class="who-ask">a program (it has no agent identity)</span>`, true];
  return [html`<span class="who-ask"><span class="bad">We can't confirm which agent this is (${strip(id.error || "unknown")}). Only Don't allow is offered.</span></span>`, false];
}
function renderWho(list) {
  const line = r => strip(r.agent) + " — " + strip(r.tool) + ": " + strip(r.call).slice(0, 120);
  const rows = list.flatMap(a => {
    const rs = a.requesters || [];
    if (a.basis === "none" || !rs.length) return list.length > 1 ? [html`<div>Asked by (in the box): unknown — no tool call was in flight</div>`] : [];
    if (a.basis === "ambiguous") return [html`<div>Asked by (in the box): one of ${rs.length} concurrent calls:</div>`, ...rs.map(r => html`<div class="cand">• ${line(r)}</div>`)];
    return [html`<div>Asked by (in the box): ${line(rs[0])}</div>`];
  });
  return html`<div class="who">${list.length ? nothing : html`<div>Asked by (in the box): unknown (no agent event stream)</div>`}${rows}${list.length > 1 ? html`<div class="warn">Asked by more than one agent: one grant would serve all of them.</div>` : nothing}<div class="note">${list.length ? "As the agent reports it, not proven: anything" : "Anything"} in this box could use the grant.</div></div>`;
}
function where(p) {
  return html`<div class="where"><span class="host">${strip(p.host)}</span>${p.path && p.path !== "/" ? wrapped("path", strip(p.path) + (p.scope_prefix ? "…" : "")) : nothing}${p.scope_prefix ? html`<div class="meta">and every page under it</div>` : nothing}</div>`;
}
const decide = (id, choice) => () => console.info("decide", { id, choice });
function pendingCard(p) {
  const a = asks(p), [who, idOk] = whoAsks(p), id = p.identity || {};
  // The first button's words are the server's terms for it (`once_terms`): a push is granted as a window.
  const ot = p.once_terms || { uses: 1, ttl_secs: 600 };
  const win = ot.uses !== 1;
  const oneStep = win || p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible";
  const once = html`<button class="approve" @click=${decide(p.id, "once")}>${win ? "Allow for " + span(ot.ttl_secs) : a.internal ? "Allow" : "Allow once"}</button>`;
  const hour = html`<button @click=${decide(p.id, "hour")}>Allow for 1 hour</button>`;
  const deny = html`<button class="deny apart" @click=${decide(p.id, "deny")}>Don't allow</button>`;
  const buttons = !idOk ? [deny] : a.internal || oneStep ? [once, deny] : [once, hour, deny];
  return html`<div class="card req" data-id=${p.id}>
    <div class="req-head"><span class="risk ${riskClass(p.risk)}">${riskLabel(p.risk)}</span>${time(p.created_at, rel(p.created_at, s.now), "age")}</div>
    <dl class="fields">
      <dt>Who</dt><dd>${who}</dd>
      ${a.internal ? html`<dt>Wants to</dt><dd class="said">${a.what.charAt(0).toLowerCase() + a.what.slice(1)}</dd>`
        : html`<dt>Wants to</dt><dd class="said">${verb(p)}</dd><dt>Where</dt><dd>${where(p)}</dd>`}
      <dt>Why</dt><dd class="why">“${a.why}”</dd>
    </dl>
    <div class="buttons ladder">${buttons}</div>
    <details class="more req-more"><summary>Details</summary>
      ${id.verified ? html`<div class="chain">On behalf of: ${(id.acting_for || []).map(strip).join(" → ")}</div>` : nothing}
      <div class="mono raw">${strip(p.method + " " + p.host + p.path)} · risk class ${riskCode(p.risk)}</div>
      ${renderWho(p.attribution || [])}
      <div class="meta">${p.id} · zone ${strip(p.zone)} · run ${idEl(p.run)}</div>
      ${idOk && !a.internal && oneStep ? html`<div class="note">${win ? "A push is allowed as one window: any number of requests for " + span(ot.ttl_secs) + ", for its ref discovery and upload." : "This kind is allowed one request at a time."}</div>` : nothing}
    </details>
  </div>`;
}
function statusLine() {
  const runs = s.runs || [];
  const working = runs.filter(r => r.status === "running" && !r.revoked).length;
  const waiting = waitingCount(), problems = problemList(s).length;
  const part = (n, one, many, href, cls) => html`<a class=${cls || ""} href=${href}>${plural(n, one, many)}</a>`;
  const parts = [part(working, "agent working", "agents working", "#agents")];
  if (waiting) parts.push(part(waiting, "request waiting for you", "requests waiting for you", "#inbox", "warn"));
  parts.push(problems ? part(problems, "problem", "problems", "#health", "bad") : html`<span class="ok">no problems</span>`);
  return parts.map((x, i) => html`${i ? " · " : ""}${x}`);
}
const waitingCount = () => s ? s.pending.length + (((s.standing || {}).asks) || []).length : 0;
function inbox() {
  const problems = problemList(s), n = waitingCount();
  return html`<p class="status" id="status" aria-live="polite">${statusLine()}</p>
    <div class="grid inbox">
      <div>
        <h3 class="sub" id="waiting-h">${n ? "Needs you (" + n + ")" : "Needs you"}</h3>
        <div id="pending" class="deck">${s.pending.length ? repeat(s.pending, p => p.id, pendingCard) : empty("Nothing is waiting for you.")}</div>
      </div>
      <div>
        <h3 class="sub">Problems</h3>
        <div id="problems" class="card flush">${problems.length ? problems.map(([tone, text, href]) => html`<a class="problem ${tone}" href=${href}>${text}</a>`) : empty("Nothing is wrong.")}</div>
      </div>
    </div>`;
}

// ---- Agents, and an agent's page ----
function renderRun(x, page) {
  const name = x.agent ? strip(x.agent) : "program run";
  const status = x.revoked ? "revoked" : String(x.status || "");
  const tone = ({ running: "good", revoked: "bad", failed: "bad", hibernated: "info" })[status] || "";
  const waiting = (s.pending || []).some(p => p.run === x.id);
  const href = "#agent/" + encodeURIComponent(x.id);
  return html`<div class="row run">
    <div>
      <div class="run-head">${page ? html`<h2 class="run-name">${name}</h2>` : html`<a class="run-name" href=${href}>${name}</a>`}<span class="meta"> · zone ${strip(x.zone)}</span><span class="pill ${waiting ? "warn" : tone}">${waiting ? "waiting for you" : ({ running: "working", exited: "finished", revoked: "stopped by you", hibernated: "asleep" })[status] || strip(status)}</span></div>
      <div class="meta">${time(x.started_at, "started " + rel(x.started_at, s.now))}${x.ended_at ? html` · ${time(x.ended_at, "ended " + rel(x.ended_at, s.now))}` : nothing} · ${idEl(x.id)}</div>
      <div class="links">${x.acp && x.status === "running" && !x.revoked ? html`<a class="session" href=${"/session?run=" + encodeURIComponent(x.id)}>Live session</a>` : nothing}${x.remote_url && x.remote_url.startsWith("https://") ? html`<a class="session" href=${x.remote_url} target="_blank" rel="noopener noreferrer">Remote Control session ↗</a>` : nothing}${page ? nothing : html`<a href=${href}>What it can reach ›</a>`}</div>
    </div>
    ${page && x.status === "running" && x.has_identity && !x.revoked ? html`<span class="acts"><button class="deny" @click=${() => console.info("stop", x.id)}>Stop agent…</button></span>` : nothing}
  </div>`;
}
function reachLine(text, end, note) {
  const meta = end !== undefined || note ? html`<div class="meta">${end ?? nothing}${note ? (end !== undefined ? " · " : "") + note : nothing}</div>` : nothing;
  return html`<div class="reach"><div class="mono">${text}</div>${meta}</div>`;
}
function permissions() {
  const { a, err } = authority;
  if (err) return html`<div class="blocked">${err}</div>`;
  if (!a) return html`<div class="meta">loading…</div>`;
  const t = a.token || {}, now = nowSecs();
  const reach = (t.reach || []).map(r => reachLine(verbsOf(r.methods) + " " + strip(r.host) + "  " + pathsText(r.paths), undefined,
    "from its zone's rules" + (r.allow_dangerous ? "; including requests that can't be undone" : "")));
  for (const g of (t.grants || []).filter(g => !g.revoked && (!g.expires_at || g.expires_at > now))) {
    reach.push(reachLine(verb(g) + " " + strip(g.host + g.path), html`<span>you allowed it; ends ${time(g.expires_at)}</span>`,
      (g.uses == null ? "any number of times" : plural(g.uses, "more time", "more times")) + " · allowed by " + strip(g.approved_by || "?") +
      (g.reached_node === false ? " · not yet on its server" : "")));
  }
  const row = s.runs.find(x => x.id === authority.run) || {};
  for (const r of ((s.standing && s.standing.rules) || []).filter(r => r.live && (r.for === "zone" ? r.zone === t.zone : row.agent && String(r.principal || "").endsWith("/z/" + row.zone + "/a/" + row.agent)))) {
    reach.push(reachLine(verbsOf(r.rule.methods) + " " + strip(r.rule.host) + "  " + pathsText(r.rule.paths),
      html`<span>always allowed, ${r.expires_at ? time(r.expires_at, "ends " + at(r.expires_at)) : "until removed"}</span>`, r.for === "zone" ? "for every agent in its zone" : "for this agent"));
  }
  if (!t.held) reach.push(html`<div class="note">No token now: ${strip(t.why)}</div>`);
  else if (!reach.length) reach.push(empty("Nothing: everything it asks for waits for you."));
  const sl = a.holdings && a.holdings.slice;
  return html`<h4>Can reach</h4>${reach}
    <h4>Where it runs</h4>
    ${a.revoked ? html`<div class="callout warn">Stopped by ${strip(a.revoked.by)}: ${strip(a.revoked.reason)}</div>` : nothing}
    ${kv("server", a.node)}
    ${a.deadline ? kv("its permissions end", whenMs(a.deadline.until_ms) + (a.deadline.stopped ? " (stopped)" : "")) : nothing}
    ${a.holdings ? [kv("keys it can use", a.holdings.secrets.length ? a.holdings.secrets.map(strip).join(", ") : "none"),
      kv("model budget left on its server", sl ? num(sl.requests) + " requests, " + num(sl.output_tokens) + " output tokens" + (sl.input_tokens != null ? ", " + num(sl.input_tokens) + " input tokens" : "") : "none")] : nothing}
    ${kv("organisation rules", a.policy.version ? strip(a.policy.version) + (a.policy.current ? " (current)" : " (not the installed " + strip(a.policy.installed || "none") + ")") : "none")}
    ${t.held ? technical(a, t) : nothing}`;
}
function technical(a, t) {
  const when = x => at(x);
  return html`<details class="more"><summary>Technical details: its token, grants and zone policy</summary>
    ${kv("status", strip(a.status) + (a.feed ? " · node feed epoch " + strip(a.feed.epoch) : ""))}
    ${kv("token", "box " + strip(t.box_path) + " · epoch " + strip(t.epoch) + " · zone " + strip(t.zone) + " · minted by " + strip(t.issued_by) +
      (t.loads === true ? " · loads" : " · does NOT load: " + strip((t.loads || {}).error || "")))}
    ${(t.blocks || []).map(b => html`<div class="row"><span class=${b.revoked ? "blocked" : "ok"}>block ${b.index} · ${strip(b.kind)}${b.revoked ? " · REVOKED" : ""}</span><span class="meta">revocation ${strip(b.revocation_fingerprint)}${b.signed_by ? " · signed by " + strip(b.signed_by) : ""}</span></div><pre class="src">${b.source}</pre>`)}
    ${(t.grants || []).map(g => kv(g.id, g.method + " " + g.host + g.path + " · " + (g.uses == null ? "unlimited uses" : g.uses + " uses (counted on the node)") +
      " · ends " + when(g.expires_at) + " · approved by " + (g.approved_by || "?") + " at " + when(g.approved_at) +
      (g.revoked ? " · revoked" : "") + (g.reached_node === false ? " · not yet on its node" : "")))}
    ${t.zone_cedar ? html`<div class="meta">zone policy (Cedar, generated from the manifest)</div><pre class="src">${t.zone_cedar}</pre>` : nothing}
  </details>`;
}
function logLine(op) {
  const [tag, tone, text, why] = describeOp(op, runName);
  return html`<div class="logline">${op.ts ? time(op.ts, clock(op.ts)) : html`<span></span>`}<span class="tag ${tone}">${tag}</span><span class="text">${text}${why ? html` <button class="link" @click=${() => console.info("why", op.seq)}>why?</button>` : nothing}</span></div>`;
}
function agentPage() {
  const x = s.runs.find(r => r.id === agentRun);
  const mine = (s.audit || []).filter(op => op.run === agentRun).reverse();
  return html`<a class="back" href="#agents">‹ Agents</a>
    <div id="agent-head">${x ? renderRun(x, true) : html`<h2>Agent</h2><p class="note">This agent run isn't in the latest list (only the 15 most recent are).</p>`}</div>
    <div class="card" id="detail"><div class="card-head"><h3 id="detail-title">Permissions</h3></div><div id="detail-body">${permissions()}</div></div>
    <div class="card"><h3>Recent activity</h3><div class="log" id="agent-log">${mine.length ? repeat(mine, op => op.seq, logLine) : empty("Nothing recorded for it in the latest activity.")}</div></div>`;
}

// ---- the page ----
const TABS = [["inbox", "Inbox"], ["agents", "Agents"], ["activity", "Activity"], ["settings", "Settings"]];
function page() {
  const n = waitingCount(), alerts = s ? problemList(s).length : 0;
  const count = v => v === "inbox" ? html`<span class="count" id="nav-waiting" ?hidden=${!n}>${n || ""}</span>`
    : v === "settings" ? html`<span class="count bad" id="nav-health" ?hidden=${!alerts}>${alerts || ""}</span>` : nothing;
  const sect = (v, label, body) => html`<section class="view" id=${"view-" + v} aria-labelledby=${label} ?hidden=${view !== v}>${view === v && s ? body() : nothing}</section>`;
  return html`<a class="skip" href="#main">Skip to the page</a>
    <header class="top">
      <div class="bar"><h1>wicket</h1><span id="tenant">${s ? "tenant " + s.tenant : ""}</span></div>
      <nav id="nav" aria-label="Views" ?hidden=${!signedIn}>${TABS.map(([v, label]) => html`<a href=${"#" + v} data-view=${v} aria-current=${v === view || (view === "agent" && v === "agents") ? "page" : nothing}>${label}${count(v)}</a>`)}</nav>
    </header>
    <div class="banner" id="stale" role="status" ?hidden=${!stale}>${stale}</div>
    <main id="main">
      <div id="auth" class="card narrow" ?hidden=${signedIn}>Sign in to approve or deny what your agents are waiting on (not in this prototype).</div>
      <div id="console" ?hidden=${!signedIn}>
        ${sect("inbox", "inbox-h", () => html`<h2 id="inbox-h" class="sr-only">Inbox</h2>${inbox()}`)}
        ${sect("agents", "agents-h", () => html`<div class="view-head"><h2 id="agents-h">Agents</h2><button type="button" class="approve" id="start-open" @click=${() => console.info("start")}>Start an agent…</button></div>
          <div class="card flush" id="runs">${s.runs.length ? repeat(s.runs, x => x.id, x => renderRun(x, false)) : empty("No runs yet.")}</div>`)}
        ${sect("agent", "detail-title", agentPage)}
        ${sect("activity", "activity-h", () => html`<h2 id="activity-h">Activity</h2><p class="note">Not in this prototype.</p>`)}
        ${sect("settings", "settings-h", () => html`<h2 id="settings-h">Settings</h2><p class="note">Not in this prototype.</p>`)}
      </div>
    </main>`;
}
function draw() {
  const n = waitingCount();
  document.title = n ? "(" + n + ") wicket" : "wicket";
  render(page(), document.body);
}

// ---- routing, by the address's hash, so the back button works ----
async function loadAuthority(run) {
  authority = { run };
  let next;
  try {
    const r = await fetch("/api/runs/" + encodeURIComponent(run) + "/authority");
    const j = await r.json().catch(() => ({ error: "unreadable answer" }));
    next = r.ok ? { run, a: j } : { run, err: strip(j.error || r.statusText) };
  } catch (e) { next = { run, err: strip(e.message) }; }
  if (authority.run === run) { authority = next; draw(); }
}
function fromHash() {
  const h = location.hash;
  const ag = /^#agent\/([A-Za-z0-9_-]{1,80})$/.exec(h);
  if (ag) { view = "agent"; agentRun = ag[1]; loadAuthority(agentRun); }
  else if (["#agents", "#activity", "#settings"].includes(h)) view = h.slice(1);
  else view = h === "#notifications" ? "settings" : "inbox";
  draw();
  if (view === "inbox" && h === "#health") document.getElementById("problems")?.scrollIntoView();
  else window.scrollTo(0, 0);
}

// ---- polling: one at a time, each bounded ----
let polling = false;
async function poll() {
  if (polling || !signedIn) return;
  polling = true;
  try {
    const r = await fetch("/api/state", { signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    s = await r.json();
    if (typeof s.now === "number") setSkew(s.now - Date.now() / 1000);
    stale = "";
  } catch (e) {
    stale = "Can't reach wicket (" + (e.name === "TimeoutError" ? "no answer in 10 s" : e.message || "no answer") + "). Retrying.";
  } finally { polling = false; }
  draw();
}
async function boot() {
  // Like the other prototypes, no sign-in check first: it costs every candidate the same round trip.
  signedIn = true;
  await poll();
  fromHash();
}
window.addEventListener("hashchange", fromHash);
boot();
setInterval(poll, 2000);

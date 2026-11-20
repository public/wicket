// The redesigned console's Inbox, Agents and agent page in plain DOM code, feature for feature with the
// Preact prototype (../preact/src/main.jsx). Every string from the API goes in as a text node.
import "../../shared/console.css";
import {
  strip, plural, setSkew, nowSecs, rel, clock, iso, at, riskClass, riskLabel, riskCode, span, asks, verb, verbsOf,
  num, pathsText, problemList, line, egressOf,
} from "./helpers.js";

// ---- building elements ----

// h("div.card.req", { attrs and on* handlers }, ...children): strings and numbers become text nodes,
// arrays are flattened, null, undefined and false are skipped.
function h(tag, props, ...kids) {
  const [name, ...cls] = tag.split(".");
  const e = document.createElement(name);
  if (cls.length) e.className = cls.join(" ");
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = (e.className ? e.className + " " : "") + v;
    else if (k === "hidden") e.hidden = !!v;
    else e.setAttribute(k, v === true ? "" : String(v));
  }
  add(e, kids);
  return e;
}
function add(e, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    e.append(typeof k === "object" ? k : document.createTextNode(String(k)));
  }
}
const $ = id => document.getElementById(id);

// Relative times that stay true in elements kept across polls: refreshed in place after each poll.
const live = new Set();
function time(t, text, cls) {
  return h("time", { class: cls, title: t ? iso(t) : undefined, datetime: t ? iso(t) : undefined }, text === undefined ? at(t) : text);
}
function relTime(t, prefix, cls) {
  const e = time(t, (prefix || "") + rel(t), cls);
  e.__rel = [t, prefix || ""];
  live.add(e);
  return e;
}
function refreshTimes() {
  for (const e of live) {
    if (!e.isConnected) { live.delete(e); continue; }
    const text = e.__rel[1] + rel(e.__rel[0]);
    if (e.textContent !== text) e.textContent = text;
  }
}

// A list kept by key across polls: an item's element is rebuilt only when its data changed.
function keyed(box, items, keyOf, build, empty) {
  const had = box.__kept || new Map(), now = new Map();
  const nodes = items.map(x => {
    const k = keyOf(x), sig = JSON.stringify(x), old = had.get(k);
    const node = old && old.sig === sig ? old.node : build(x);
    now.set(k, { sig, node });
    return node;
  });
  box.__kept = now;
  if (!nodes.length && empty) nodes.push(empty());
  if (nodes.length !== box.children.length || nodes.some((n, i) => n !== box.children[i])) box.replaceChildren(...nodes);
}

// ---- small pieces ----

function idShort(id) {
  id = strip(id);
  return h("span.id-short", { title: id }, id.length <= 18 ? id : [h("span.id-head", {}, id.slice(0, -6)), h("span.id-tail", {}, id.slice(-6))]);
}
const wrapped = (cls, text) => h("div", { class: cls }, String(text).split(/(?<=[/.?&])/).map(part => [part, h("wbr")]));
const field = (label, cls, ...kids) => [h("dt", {}, label), h("dd", { class: cls }, kids)];
const kv = (k, v) => h("div.row", {}, h("span.meta", {}, k), h("span.mono", {}, strip(v)));

// ---- the Inbox ----

function status(s) {
  const working = (s.runs || []).filter(r => r.status === "running" && !r.revoked).length;
  const waiting = (s.pending || []).length + ((s.standing || {}).asks || []).length;
  const problems = problemList(s).length;
  const part = (n, one, many, href, cls) => h("a", { class: cls, href }, plural(n, one, many));
  const parts = [part(working, "agent working", "agents working", "#agents")];
  if (waiting) parts.push(part(waiting, "request waiting for you", "requests waiting for you", "#inbox", "warn"));
  parts.push(problems ? part(problems, "problem", "problems", "#health", "bad") : h("span.ok", {}, "no problems"));
  $("status").replaceChildren(...parts.flatMap((x, i) => i ? [" · ", x] : [x]));
}

// Who asks: the agent and its zone behind a button that shows its full identity, or said plainly.
function whoAsks(id) {
  if (id.verified) {
    const idline = h("div.idline", { hidden: true }, strip(id.id));
    const name = h("button.idname", { type: "button", title: "Show its identity", "aria-expanded": "false" }, strip(id.agent));
    name.addEventListener("click", () => { idline.hidden = !idline.hidden; name.setAttribute("aria-expanded", String(!idline.hidden)); });
    return h("span.who-ask", {}, h("span.ok", {}, "✓ "), name, " · zone " + strip(id.zone), idline);
  }
  if ((id.error || "").startsWith("no identity was issued")) return h("span.who-ask", {}, "a program (it has no agent identity)");
  return h("span.who-ask", {}, h("span.bad", {}, "We can't confirm which agent this is (" + strip(id.error || "unknown") + "). Only Don't allow is offered."));
}

// Which call in the box asked, as the agent's event stream reports it: helpful, not proof.
function askedBy(list) {
  const say = r => strip(r.agent) + " — " + strip(r.tool) + ": " + strip(r.call).slice(0, 120);
  return h("div.who", {},
    !list.length && h("div", {}, "Asked by (in the box): unknown (no agent event stream)"),
    list.map(a => {
      const rs = a.requesters || [];
      if (a.basis === "none" || !rs.length) return list.length > 1 ? h("div", {}, "Asked by (in the box): unknown — no tool call was in flight") : null;
      if (a.basis === "ambiguous") return [h("div", {}, "Asked by (in the box): one of " + rs.length + " concurrent calls:"), rs.map(r => h("div.cand", {}, "• " + say(r)))];
      return h("div", {}, "Asked by (in the box): " + say(rs[0]));
    }),
    list.length > 1 && h("div.warn", {}, "Asked by more than one agent: one grant would serve all of them."),
    h("div.note", {}, (list.length ? "As the agent reports it, not proven: anything" : "Anything") + " in this box could use the grant."));
}

function pendingCard(p) {
  const a = asks(p), id = p.identity || {};
  const idOk = !!id.verified || (id.error || "").startsWith("no identity was issued");
  // The first button's words are the server's terms for it: a git push is granted as a window.
  const ot = p.once_terms || { uses: 1, ttl_secs: 600 };
  const window_ = ot.uses !== 1;
  const decide = choice => () => console.info("decide", { id: p.id, choice });
  const once = h("button.approve", { disabled: !idOk, onclick: decide("once") }, window_ ? "Allow for " + span(ot.ttl_secs) : a.internal ? "Allow" : "Allow once");
  const hour = h("button", { disabled: !idOk, onclick: decide("hour") }, "Allow for 1 hour");
  const deny = h("button.deny.apart", { onclick: decide("deny") }, "Don't allow");
  // Only the steps the server grants: a push is one window, R3 and R4 one use, wicket's own kinds one decision.
  const single = window_ || p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible";
  const buttons = !idOk ? [deny] : a.internal || single ? [once, deny] : [once, hour, deny];
  return h("div.card.req", { "data-id": p.id },
    h("div.req-head", {}, h("span", { class: "risk " + riskClass(p.risk) }, riskLabel(p.risk)), relTime(p.created_at, "", "age")),
    h("dl.fields", {},
      field("Who", "", whoAsks(id)),
      a.internal
        ? field("Wants to", "said", a.what.charAt(0).toLowerCase() + a.what.slice(1))
        : [field("Wants to", "said", verb(p)),
          field("Where", "", h("div.where", {},
            h("span.host", {}, strip(p.host)),
            p.path && p.path !== "/" && wrapped("path", strip(p.path) + (p.scope_prefix ? "…" : "")),
            p.scope_prefix && h("div.meta", {}, "and every page under it")))],
      field("Why", "why", "“" + a.why + "”")),
    h("div.buttons.ladder", {}, buttons),
    h("details.more.req-more", {},
      h("summary", {}, "Details"),
      id.verified && h("div.chain", {}, "On behalf of: " + (id.acting_for || []).map(strip).join(" → ")),
      h("div.mono.raw", {}, strip(p.method + " " + p.host + p.path) + " · risk class " + riskCode(p.risk)),
      askedBy(p.attribution || []),
      h("div.meta", {}, p.id + " · zone " + strip(p.zone) + " · run ", idShort(p.run)),
      idOk && !a.internal && single && h("div.note", {}, window_
        ? "A push is allowed as one window: any number of requests for " + span(ot.ttl_secs) + ", for its ref discovery and upload."
        : "This kind is allowed one request at a time.")));
}

function inbox(s) {
  const waiting = s.pending.length + ((s.standing || {}).asks || []).length;
  status(s);
  $("waiting-h").textContent = waiting ? "Needs you (" + waiting + ")" : "Needs you";
  // A card's age is refreshed in place (refreshTimes), not by rebuilding the card.
  keyed($("pending"), s.pending, p => p.id, pendingCard, () => h("div.empty", {}, "Nothing is waiting for you."));
  keyed($("problems"), problemList(s), ([tone, text]) => tone + text, ([tone, text, href]) => h("a", { class: "problem " + tone, href }, text),
    () => h("div.empty", {}, "Nothing is wrong."));
}

// ---- Agents ----

function run(s, x, page) {
  const name = x.agent ? strip(x.agent) : "program run";
  const st = x.revoked ? "revoked" : String(x.status || "");
  const tone = ({ running: "good", revoked: "bad", failed: "bad", hibernated: "info" })[st] || "";
  const href = "#agent/" + encodeURIComponent(x.id);
  return h("div.row.run", {},
    h("div", {},
      h("div.run-head", {},
        page ? h("h2.run-name", {}, name) : h("a.run-name", { href }, name),
        h("span.meta", {}, " · zone " + strip(x.zone)),
        h("span", { class: "pill " + (x.waiting ? "warn" : tone) },
          x.waiting ? "waiting for you" : ({ running: "working", exited: "finished", revoked: "stopped by you", hibernated: "asleep" })[st] || strip(st))),
      h("div.meta", {}, relTime(x.started_at, "started "), x.ended_at && [" · ", relTime(x.ended_at, "ended ")], " · ", idShort(x.id)),
      h("div.links", {},
        x.acp && x.status === "running" && !x.revoked && h("a.session", { href: "/session?run=" + encodeURIComponent(x.id) }, "Live session"),
        x.remote_url && x.remote_url.startsWith("https://") && h("a.session", { href: x.remote_url, target: "_blank", rel: "noopener noreferrer" }, "Remote Control session ↗"),
        !page && h("a", { href }, "What it can reach ›"))),
    page && x.status === "running" && x.has_identity && !x.revoked &&
      h("span.acts", {}, h("button.deny", { onclick: () => console.info("stop", x.id) }, "Stop agent…")));
}
// Each run with whether a request of its waits: part of its key, so the pill follows.
const runs = s => s.runs.map(x => ({ ...x, waiting: s.pending.some(p => p.run === x.id) }));

// ---- an agent's page ----

function reachLine(text, end, note) {
  return h("div.reach", {}, h("div.mono", {}, text), (end !== undefined || note) && h("div.meta", {}, end, note && (end !== undefined ? " · " : "") + note));
}

// What a run can reach (its zone's rules, its live grants, the standing rules for it), then where it runs.
function permissions(s, runId, a) {
  const t = a.token || {};
  const now = nowSecs();
  const row = s.runs.find(x => x.id === runId) || {};
  const rules = ((s.standing || {}).rules || []).filter(r => r.live && (r.for === "zone" ? r.zone === t.zone
    : row.agent && String(r.principal || "").endsWith("/z/" + row.zone + "/a/" + row.agent)));
  const grants = (t.grants || []).filter(g => !g.revoked && (!g.expires_at || g.expires_at > now));
  const reach = [
    ...(t.reach || []).map(r => reachLine(verbsOf(r.methods) + " " + strip(r.host) + "  " + pathsText(r.paths), undefined,
      "from its zone's rules" + (r.allow_dangerous ? "; including requests that can't be undone" : ""))),
    ...grants.map(g => reachLine(verb(g) + " " + strip(g.host + g.path), h("span", {}, "you allowed it; ends ", time(g.expires_at)),
      (g.uses == null ? "any number of times" : plural(g.uses, "more time", "more times")) + " · allowed by " + strip(g.approved_by || "?") +
        (g.reached_node === false ? " · not yet on its server" : ""))),
    ...rules.map(r => reachLine(verbsOf(r.rule.methods) + " " + strip(r.rule.host) + "  " + pathsText(r.rule.paths),
      h("span", {}, "always allowed, ", r.expires_at ? time(r.expires_at, "ends " + at(r.expires_at)) : "until removed"),
      r.for === "zone" ? "for every agent in its zone" : "for this agent")),
  ];
  const sl = a.holdings && a.holdings.slice;
  return [
    h("h4", {}, "Can reach"),
    !t.held ? [reach, h("div.note", {}, "No token now: " + strip(t.why))] : reach.length ? reach : h("div.empty", {}, "Nothing: everything it asks for waits for you."),
    h("h4", {}, "Where it runs"),
    a.revoked && h("div.callout.warn", {}, "Stopped by " + strip(a.revoked.by) + ": " + strip(a.revoked.reason)),
    kv("server", a.node),
    a.deadline && kv("its permissions end", (a.deadline.until_ms ? at(a.deadline.until_ms / 1000) : "—") + (a.deadline.stopped ? " (stopped)" : "")),
    a.holdings && [
      kv("keys it can use", a.holdings.secrets.length ? a.holdings.secrets.map(strip).join(", ") : "none"),
      kv("model budget left on its server", sl ? num(sl.requests) + " requests, " + num(sl.output_tokens) + " output tokens" +
        (sl.input_tokens != null ? ", " + num(sl.input_tokens) + " input tokens" : "") : "none")],
    kv("organisation rules", a.policy.version ? strip(a.policy.version) + (a.policy.current ? " (current)" : " (not the installed " + strip(a.policy.installed || "none") + ")") : "none"),
    t.held && h("details.more", {},
      h("summary", {}, "Technical details: its token, grants and zone policy"),
      kv("status", strip(a.status) + (a.feed ? " · node feed epoch " + strip(a.feed.epoch) : "")),
      kv("token", "box " + strip(t.box_path) + " · epoch " + strip(t.epoch) + " · zone " + strip(t.zone) + " · minted by " + strip(t.issued_by) +
        (t.loads === true ? " · loads" : " · does NOT load: " + strip((t.loads || {}).error || ""))),
      (t.blocks || []).map(b => [
        h("div.row", {},
          h("span", { class: b.revoked ? "blocked" : "ok" }, "block " + b.index + " · " + strip(b.kind) + (b.revoked ? " · REVOKED" : "")),
          h("span.meta", {}, "revocation " + strip(b.revocation_fingerprint) + (b.signed_by ? " · signed by " + strip(b.signed_by) : ""))),
        h("pre.src", {}, b.source)]),
      (t.grants || []).map(g => kv(g.id, g.method + " " + g.host + g.path + " · " + (g.uses == null ? "unlimited uses" : g.uses + " uses (counted on the node)") +
        " · ends " + at(g.expires_at) + " · approved by " + (g.approved_by || "?") + " at " + at(g.approved_at) +
        (g.revoked ? " · revoked" : "") + (g.reached_node === false ? " · not yet on its node" : ""))),
      t.zone_cedar && [h("div.meta", {}, "zone policy (Cedar, generated from the manifest)"), h("pre.src", {}, t.zone_cedar)]),
  ];
}

let auth = null; // { run, a } or { run, error }, for the agent page shown
async function loadAuthority(runId) {
  auth = null;
  try {
    const r = await fetch("/api/runs/" + encodeURIComponent(runId) + "/authority");
    const j = await r.json().catch(() => ({ error: "unreadable answer" }));
    if (!r.ok) throw new Error(j.error || r.statusText);
    if (route.run === runId) auth = { run: runId, a: j };
  } catch (e) { if (route.run === runId) auth = { run: runId, error: strip(e.message) }; }
  draw();
}

function agentPage(s, runId) {
  const x = s.runs.find(r => r.id === runId);
  keyed($("agent-head"), x ? runs(s).filter(r => r.id === runId) : [], r => r.id, r => run(s, r, true),
    () => h("div", {}, h("h2", {}, "Agent"), h("p.note", {}, "This agent run isn't in the latest list (only the 15 most recent are).")));
  const body = $("detail-body"), sig = auth ? JSON.stringify([auth, s.standing, s.runs.find(r => r.id === runId)]) : "loading";
  if (body.__sig !== sig) {
    body.__sig = sig;
    body.replaceChildren(...[!auth ? h("div.meta", {}, "loading…") : auth.error ? h("div.blocked", {}, auth.error) : permissions(s, runId, auth.a)].flat(Infinity).filter(Boolean));
  }
  const runName = id => { const r = s.runs.find(r => r.id === id); return r ? (r.agent ? strip(r.agent) : "a program") : strip(id); };
  keyed($("agent-log"), (s.audit || []).filter(op => op.run === runId).reverse(), op => op.seq, op => {
    const [tag, tone, text] = line(op, runName);
    return h("div.logline", {}, op.ts ? time(op.ts, clock(op.ts)) : h("span"), h("span", { class: "tag " + tone }, tag), h("span.text", {}, text,
      op.run && egressOf(op) && [" ", h("button.link", { onclick: () => console.info("why", op.seq) }, "why?")]));
  }, () => h("div.empty", {}, "Nothing recorded for it in the latest activity."));
}

// ---- the page ----

// The view from the address's hash, so the back button works: #inbox (the default), #agents, #agent/<run>.
const route = { view: "inbox", run: "" };
function onHash() {
  const hh = location.hash, ag = /^#agent\/([A-Za-z0-9_-]{1,80})$/.exec(hh);
  route.view = ag ? "agent" : ["#agents", "#activity", "#settings"].includes(hh) ? hh.slice(1) : "inbox";
  if (ag && route.run !== ag[1]) { route.run = ag[1]; for (const id of ["agent-head", "agent-log"]) $(id).__kept = null; $("detail-body").__sig = null; loadAuthority(route.run); }
  if (!ag) route.run = "";
  window.scrollTo(0, 0);
  draw();
}

let state = null, stale = "";
function draw() {
  for (const v of ["inbox", "agents", "agent", "other"]) $("view-" + v).hidden = v !== (["activity", "settings"].includes(route.view) ? "other" : route.view);
  for (const a of document.querySelectorAll("nav a")) {
    if (a.dataset.view === route.view || (route.view === "agent" && a.dataset.view === "agents")) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  $("other-h").textContent = route.view === "activity" ? "Activity" : "Settings";
  $("stale").hidden = !stale; $("stale").textContent = stale;
  if (!state) return;
  const s = state;
  const waiting = s.pending.length + ((s.standing || {}).asks || []).length, alerts = problemList(s).length;
  document.title = waiting ? "(" + waiting + ") wicket" : "wicket";
  $("tenant").textContent = "tenant " + s.tenant;
  for (const [id, n] of [["nav-waiting", waiting], ["nav-health", alerts]]) { $(id).hidden = !n; $(id).textContent = n ? String(n) : ""; }
  $("console").hidden = false;
  if (route.view === "inbox") inbox(s);
  if (route.view === "agents") keyed($("runs"), runs(s), x => x.id, x => run(s, x, false), () => h("div.empty", {}, "No runs yet."));
  if (route.view === "agent") agentPage(s, route.run);
  refreshTimes();
}

// GET /api/state every 2 s, one poll at a time, each bounded; a failed one is said, and the poll goes on.
let busy = false, heard = 0;
async function poll() {
  if (busy) return;
  busy = true;
  try {
    const r = await fetch("/api/state", { signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    if (typeof j.now === "number") setSkew(j.now - Date.now() / 1000);
    heard = Date.now();
    state = j; stale = "";
  } catch (e) {
    const why = e.name === "TimeoutError" ? "no answer in 10 s" : /^HTTP/.test(e.message) ? e.message : "no answer";
    stale = "Can't reach wicket (" + why + ")" + (heard ? " since " + new Date(heard).toISOString().slice(11, 19) + "Z; what is shown is as of then" : "") + ". Retrying.";
  } finally { busy = false; }
  draw();
}

$("start-open").addEventListener("click", () => console.info("start"));
addEventListener("hashchange", onHash);
onHash();
poll();
setInterval(poll, 2000);

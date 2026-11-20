// The redesigned console's Inbox, Agents and an agent's page, in SolidJS. Every string from the API
// is rendered as text (JSX expressions become text nodes): nothing is parsed as markup.
import { render } from "solid-js/web";
import { createSignal, createMemo, createResource, createEffect, For, Index, Show, Switch, Match } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import "../../shared/console.css";
import { strip, plural, rel, clock, iso, at, riskClass, riskLabel, riskCode, span, num, asks, verb, verbsOf, problemList, lineOf } from "./helpers.js";

// ---- state: polled every 2 s and reconciled into one store, keyed by id, so a card or row whose
// data didn't change keeps its proxy, and <For> (which keys by reference) keeps its DOM node.
const [s, setS] = createStore({ ready: false, now: 0, tenant: "", pending: [], runs: [], audit: [] });
let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  try {
    const r = await fetch("/api/state");
    if (r.ok) {
      const j = await r.json();
      // Audit records have no id: key them by their sequence number.
      j.audit = (j.audit || []).map(op => ({ id: "seq:" + op.seq, ...op }));
      setS(reconcile({ ...j, ready: true }, { key: "id" }));
    }
  } catch (e) { /* keep polling */ } finally { polling = false; }
}

// ---- routing by location.hash, so the back button works.
const [hash, setHash] = createSignal(location.hash);
window.addEventListener("hashchange", () => {
  setHash(location.hash);
  if (location.hash === "#health") document.getElementById("problems")?.scrollIntoView();
  else window.scrollTo(0, 0);
});
const route = createMemo(() => {
  const h = hash(), ag = /^#agent\/([A-Za-z0-9_-]{1,80})$/.exec(h);
  if (ag) return { view: "agent", run: ag[1] };
  return { view: ["#agents", "#activity", "#settings"].includes(h) ? h.slice(1) : "inbox" };
});
const view = () => route().view;
const agentRun = () => route().run;

const waiting = () => s.pending.length + ((s.standing && s.standing.asks) || []).length;
const problems = createMemo(() => problemList(s));
const runName = id => { const x = s.runs.find(r => r.id === id); return x ? (x.agent ? strip(x.agent) : "a program") : strip(id); };

// ---- small pieces
function Time(props) {
  return <time class={props.class} title={props.t ? iso(props.t) : undefined} datetime={props.t ? iso(props.t) : undefined}>
    {props.text ?? at(props.t, s.now)}
  </time>;
}
// A long id cut in the middle, its head and tail kept; the whole id is its title.
function IdShort(props) {
  const id = () => strip(props.id);
  return <span class="id-short" title={id()}>
    <Show when={id().length > 18} fallback={id()}>
      <span class="id-head">{id().slice(0, -6)}</span><span class="id-tail">{id().slice(-6)}</span>
    </Show>
  </span>;
}
// A URL broken only after its slashes and dots.
function Wrapped(props) {
  return <div class={props.class}><Index each={String(props.text).split(/(?<=[/.?&])/)}>{part => <>{part()}<wbr /></>}</Index></div>;
}
const Kv = props => <div class="row"><span class="meta">{props.k}</span><span class="mono">{strip(props.v)}</span></div>;

// ---- the Inbox
function Status() {
  const working = () => s.runs.filter(r => r.status === "running" && !r.revoked).length;
  return <p class="status" id="status" aria-live="polite">
    <a href="#agents">{plural(working(), "agent working", "agents working")}</a>
    <Show when={waiting()}>{" · "}<a class="warn" href="#inbox">{plural(waiting(), "request waiting for you", "requests waiting for you")}</a></Show>
    {" · "}
    <Show when={problems().length} fallback={<span class="ok">no problems</span>}>
      <a class="bad" href="#health">{plural(problems().length, "problem", "problems")}</a>
    </Show>
  </p>;
}

// Who asks: the agent and its zone, verified, its full identity behind a tap; or said plainly.
function WhoAsks(props) {
  const [open, setOpen] = createSignal(false);
  const id = () => props.id;
  return <span class="who-ask">
    <Switch fallback={<span class="bad">{"We can't confirm which agent this is (" + strip(id().error || "unknown") + "). Only Don't allow is offered."}</span>}>
      <Match when={id().verified}>
        <span class="ok">{"✓ "}</span>
        <button type="button" class="idname" title="Show its identity" aria-expanded={String(open())} onClick={() => setOpen(!open())}>{strip(id().agent)}</button>
        {" · zone " + strip(id().zone)}
        <div class="idline" hidden={!open()}>{strip(id().id)}</div>
      </Match>
      <Match when={(id().error || "").startsWith("no identity was issued")}>a program (it has no agent identity)</Match>
    </Switch>
  </span>;
}

// Which call in the box asked, as the agent reports it: helpful, not proof.
function AskedBy(props) {
  const list = () => props.list;
  const line = r => strip(r.agent) + " — " + strip(r.tool) + ": " + strip(r.call).slice(0, 120);
  return <div class="who">
    <Show when={!list().length}><div>Asked by (in the box): unknown (no agent event stream)</div></Show>
    <For each={list()}>{a => {
      const rs = () => a.requesters || [];
      return <Switch fallback={<div>{"Asked by (in the box): " + line(rs()[0])}</div>}>
        <Match when={a.basis === "none" || !rs().length}>
          <Show when={list().length > 1}><div>Asked by (in the box): unknown — no tool call was in flight</div></Show>
        </Match>
        <Match when={a.basis === "ambiguous"}>
          <div>{"Asked by (in the box): one of " + rs().length + " concurrent calls:"}</div>
          <For each={rs()}>{r => <div class="cand">{"• " + line(r)}</div>}</For>
        </Match>
      </Switch>;
    }}</For>
    <Show when={list().length > 1}><div class="warn">Asked by more than one agent: one grant would serve all of them.</div></Show>
    <div class="note">{(list().length ? "As the agent reports it, not proven: anything" : "Anything") + " in this box could use the grant."}</div>
  </div>;
}

// One pending request, as the reference's pendingCard builds it. `p` is the store's proxy for it.
function PendingCard(props) {
  const p = props.p;
  const a = createMemo(() => asks(p));
  const id = () => p.identity || {};
  const idOk = () => !!id().verified || (id().error || "").startsWith("no identity was issued");
  const ot = () => p.once_terms || { uses: 1, ttl_secs: 600 };
  const windowed = () => ot().uses !== 1;
  // Only the steps the server grants: a push is one window, R3 and R4 one use, wicket's own kinds one decision.
  const single = () => windowed() || p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible";
  const decide = choice => console.info("decide", { id: p.id, choice });
  return <div class="card req" data-id={p.id}>
    <div class="req-head">
      <span class={"risk " + riskClass(p.risk)}>{riskLabel(p.risk)}</span>
      <Time class="age" t={p.created_at} text={rel(p.created_at, s.now)} />
    </div>
    <dl class="fields">
      <dt>Who</dt><dd><WhoAsks id={id()} /></dd>
      <Show when={a().internal} fallback={<>
        <dt>Wants to</dt><dd class="said">{verb(p)}</dd>
        <dt>Where</dt>
        <dd><div class="where">
          <span class="host">{strip(p.host)}</span>
          <Show when={p.path && p.path !== "/"}><Wrapped class="path" text={strip(p.path) + (p.scope_prefix ? "…" : "")} /></Show>
          <Show when={p.scope_prefix}><div class="meta">and every page under it</div></Show>
        </div></dd>
      </>}>
        <dt>Wants to</dt><dd class="said">{a().what.charAt(0).toLowerCase() + a().what.slice(1)}</dd>
      </Show>
      <dt>Why</dt><dd class="why">{"“" + a().why + "”"}</dd>
    </dl>
    <div class="buttons ladder">
      <Show when={idOk()}>
        <button type="button" class="approve" onClick={() => decide("once")}>
          {windowed() ? "Allow for " + span(ot().ttl_secs) : a().internal ? "Allow" : "Allow once"}
        </button>
        <Show when={!a().internal && !single()}><button type="button" onClick={() => decide("hour")}>Allow for 1 hour</button></Show>
      </Show>
      <button type="button" class="deny apart" onClick={() => decide("deny")}>Don't allow</button>
    </div>
    <details class="more req-more">
      <summary>Details</summary>
      <Show when={id().verified}><div class="chain">{"On behalf of: " + (id().acting_for || []).map(strip).join(" → ")}</div></Show>
      <div class="mono raw">{strip(p.method + " " + p.host + p.path) + " · risk class " + riskCode(p.risk)}</div>
      <AskedBy list={p.attribution || []} />
      <div class="meta">{p.id + " · zone " + strip(p.zone) + " · run "}<IdShort id={p.run} /></div>
      <Show when={idOk() && !a().internal && single()}>
        <div class="note">{windowed() ? "A push is allowed as one window: any number of requests for " + span(ot().ttl_secs) + ", for its ref discovery and upload." :
          "This kind is allowed one request at a time."}</div>
      </Show>
    </details>
  </div>;
}

function Inbox() {
  return <section class="view" id="view-inbox" aria-labelledby="inbox-h" hidden={view() !== "inbox"}>
    <h2 id="inbox-h" class="sr-only">Inbox</h2>
    <Status />
    <div class="grid inbox">
      <div>
        <h3 class="sub" id="waiting-h">{waiting() ? "Needs you (" + waiting() + ")" : "Needs you"}</h3>
        <div id="pending" class="deck">
          <For each={s.pending} fallback={<div class="empty">Nothing is waiting for you.</div>}>{p => <PendingCard p={p} />}</For>
        </div>
      </div>
      <div>
        <h3 class="sub">Problems</h3>
        <div id="problems" class="card flush">
          <Show when={problems().length} fallback={<div class="empty">Nothing is wrong.</div>}>
            <Index each={problems()}>{x => <a class={"problem " + x()[0]} href={x()[2]}>{x()[1]}</a>}</Index>
          </Show>
        </div>
      </div>
    </div>
  </section>;
}

// ---- Agents: a run, as renderRun builds it; `page` for the head of an agent's page.
function Run(props) {
  const x = props.x;
  const name = () => x.agent ? strip(x.agent) : "program run";
  const href = () => "#agent/" + encodeURIComponent(x.id);
  const status = () => x.revoked ? "revoked" : String(x.status || "");
  const waits = () => s.pending.some(p => p.run === x.id);
  const tone = () => waits() ? "warn" : ({ running: "good", revoked: "bad", failed: "bad", hibernated: "info" })[status()] || "";
  const said = () => waits() ? "waiting for you" : ({ running: "working", exited: "finished", revoked: "stopped by you", hibernated: "asleep" })[status()] || strip(status());
  return <div class="row run">
    <div>
      <div class="run-head">
        <Show when={props.page} fallback={<a class="run-name" href={href()}>{name()}</a>}><h2 class="run-name">{name()}</h2></Show>
        <span class="meta">{" · zone " + strip(x.zone)}</span>
        <span class={"pill " + tone()}>{said()}</span>
      </div>
      <div class="meta">
        <Time t={x.started_at} text={"started " + rel(x.started_at, s.now)} />
        <Show when={x.ended_at}>{" · "}<Time t={x.ended_at} text={"ended " + rel(x.ended_at, s.now)} /></Show>
        {" · "}<IdShort id={x.id} />
      </div>
      <div class="links">
        <Show when={x.acp && x.status === "running" && !x.revoked}><a class="session" href={"/session?run=" + encodeURIComponent(x.id)}>Live session</a></Show>
        <Show when={x.remote_url && x.remote_url.startsWith("https://")}>
          <a class="session" href={x.remote_url} target="_blank" rel="noopener noreferrer">{"Remote Control session ↗"}</a>
        </Show>
        <Show when={!props.page}><a href={href()}>{"What it can reach ›"}</a></Show>
      </div>
    </div>
    <Show when={props.page && x.status === "running" && x.has_identity && !x.revoked}>
      <span class="acts"><button type="button" class="deny" onClick={() => console.info("stop", x.id)}>{"Stop agent…"}</button></span>
    </Show>
  </div>;
}

function Agents() {
  return <section class="view" id="view-agents" aria-labelledby="agents-h" hidden={view() !== "agents"}>
    <div class="view-head"><h2 id="agents-h">Agents</h2><button type="button" class="approve" id="start-open">{"Start an agent…"}</button></div>
    <div class="card flush" id="runs">
      <For each={s.runs} fallback={<div class="empty">No runs yet.</div>}>{x => <Run x={x} />}</For>
    </div>
  </section>;
}

// ---- an agent's page: its head, its permissions (fetched when the page opens), its recent activity.
async function getJson(path) {
  const r = await fetch(path);
  const j = await r.json().catch(() => ({ error: "unreadable answer" }));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const pathsText = p => (p || ["/**"]).map(strip).join(" ");
function Reach(props) {
  return <div class="reach">
    <div class="mono">{props.text}</div>
    <div class="meta">{props.end}{props.end && props.note ? " · " : ""}{props.note}</div>
  </div>;
}
function Permissions(props) {
  const a = props.a, t = a.token || {};
  const grants = () => (t.grants || []).filter(g => !g.revoked && (!g.expires_at || g.expires_at > s.now));
  const standing = () => {
    const row = s.runs.find(x => x.id === agentRun()) || {};
    return ((s.standing && s.standing.rules) || []).filter(r => r.live && (r.for === "zone" ? r.zone === t.zone : row.agent && String(r.principal || "").endsWith("/z/" + row.zone + "/a/" + row.agent)));
  };
  return <>
    <h4>Can reach</h4>
    <For each={t.reach || []}>{r => <Reach text={verbsOf(r.methods) + " " + strip(r.host) + "  " + pathsText(r.paths)}
      note={"from its zone's rules" + (r.allow_dangerous ? "; including requests that can't be undone" : "")} />}</For>
    <For each={grants()}>{g => <Reach text={verb(g) + " " + strip(g.host + g.path)}
      end={<span>you allowed it; ends <Time t={g.expires_at} /></span>}
      note={(g.uses == null ? "any number of times" : plural(g.uses, "more time", "more times")) + " · allowed by " + strip(g.approved_by || "?") +
        (g.reached_node === false ? " · not yet on its server" : "")} />}</For>
    <For each={standing()}>{r => <Reach text={verbsOf(r.rule.methods) + " " + strip(r.rule.host) + "  " + pathsText(r.rule.paths)}
      end={<span>always allowed, {r.expires_at ? <Time t={r.expires_at} text={"ends " + at(r.expires_at, s.now)} /> : "until removed"}</span>}
      note={r.for === "zone" ? "for every agent in its zone" : "for this agent"} />}</For>
    <Show when={!t.held}><div class="note">{"No token now: " + strip(t.why)}</div></Show>
    <Show when={t.held && !(t.reach || []).length && !grants().length && !standing().length}><div class="empty">Nothing: everything it asks for waits for you.</div></Show>
    <h4>Where it runs</h4>
    <Show when={a.revoked}><div class="callout warn">{"Stopped by " + strip(a.revoked.by) + ": " + strip(a.revoked.reason)}</div></Show>
    <Kv k="server" v={a.node} />
    <Show when={a.deadline}><Kv k="its permissions end" v={at(a.deadline.until_ms / 1000, s.now) + (a.deadline.stopped ? " (stopped)" : "")} /></Show>
    <Show when={a.holdings}>{h => <>
      <Kv k="keys it can use" v={h().secrets.length ? h().secrets.map(strip).join(", ") : "none"} />
      <Kv k="model budget left on its server" v={h().slice ? num(h().slice.requests) + " requests, " + num(h().slice.output_tokens) + " output tokens" +
        (h().slice.input_tokens != null ? ", " + num(h().slice.input_tokens) + " input tokens" : "") : "none"} />
    </>}</Show>
    <Kv k="organisation rules" v={a.policy.version ? strip(a.policy.version) + (a.policy.current ? " (current)" : " (not the installed " + strip(a.policy.installed || "none") + ")") : "none"} />
    <Show when={t.held}>
      <details class="more">
        <summary>Technical details: its token, grants and zone policy</summary>
        <Kv k="status" v={strip(a.status) + (a.feed ? " · node feed epoch " + strip(a.feed.epoch) : "")} />
        <Kv k="token" v={"box " + strip(t.box_path) + " · epoch " + strip(t.epoch) + " · zone " + strip(t.zone) + " · minted by " + strip(t.issued_by) +
          (t.loads === true ? " · loads" : " · does NOT load: " + strip((t.loads || {}).error || ""))} />
        <For each={t.blocks || []}>{b => <>
          <div class="row">
            <span class={b.revoked ? "blocked" : "ok"}>{"block " + b.index + " · " + strip(b.kind) + (b.revoked ? " · REVOKED" : "")}</span>
            <span class="meta">{"revocation " + strip(b.revocation_fingerprint) + (b.signed_by ? " · signed by " + strip(b.signed_by) : "")}</span>
          </div>
          <pre class="src">{b.source}</pre>
        </>}</For>
        <For each={t.grants || []}>{g => <Kv k={g.id} v={g.method + " " + g.host + g.path + " · " + (g.uses == null ? "unlimited uses" : g.uses + " uses (counted on the node)") +
          " · ends " + at(g.expires_at, s.now) + " · approved by " + (g.approved_by || "?") + " at " + at(g.approved_at, s.now) +
          (g.revoked ? " · revoked" : "") + (g.reached_node === false ? " · not yet on its node" : "")} />}</For>
        <Show when={t.zone_cedar}><div class="meta">zone policy (Cedar, generated from the manifest)</div><pre class="src">{t.zone_cedar}</pre></Show>
      </details>
    </Show>
  </>;
}

function LogLine(props) {
  const op = props.op;
  const l = createMemo(() => lineOf(op, runName));
  return <div class="logline" data-cat={l().cat}>
    {op.ts ? <Time t={op.ts} text={clock(op.ts, s.now)} /> : <span />}
    <span class={"tag " + (l().tone || "")}>{l().tag}</span>
    <span class="text">{l().text}<Show when={l().why}>{" "}<button type="button" class="link" onClick={() => console.info("explain", op.seq)}>why?</button></Show></span>
  </div>;
}

function Agent() {
  const run = createMemo(() => s.runs.find(r => r.id === agentRun()));
  const [authority] = createResource(() => view() === "agent" && agentRun(), r => getJson("/api/runs/" + encodeURIComponent(r) + "/authority"));
  const mine = createMemo(() => s.audit.filter(op => op.run === agentRun()).reverse());
  return <section class="view" id="view-agent" aria-labelledby="detail-title" hidden={view() !== "agent"}>
    <a class="back" href="#agents">{"‹ Agents"}</a>
    <div id="agent-head">
      <Show when={run()} keyed fallback={<><h2>Agent</h2><p class="note">This agent run isn't in the latest list (only the 15 most recent are).</p></>}>
        {x => <Run x={x} page />}
      </Show>
    </div>
    <div class="card" id="detail">
      <div class="card-head"><h3 id="detail-title">Permissions</h3></div>
      <div id="detail-body">
        <Switch>
          <Match when={authority.error}><div class="blocked">{strip(authority.error.message)}</div></Match>
          <Match when={authority.loading}><div class="meta">{"loading…"}</div></Match>
          <Match when={authority()} keyed>{a => <Permissions a={a} />}</Match>
        </Switch>
      </div>
    </div>
    <div class="card"><h3>Recent activity</h3>
      <div class="log" id="agent-log">
        <For each={mine()} fallback={<div class="empty">Nothing recorded for it in the latest activity.</div>}>{op => <LogLine op={op} />}</For>
      </div>
    </div>
  </section>;
}

// ---- the page
function Tab(props) {
  const here = () => view() === props.view || (view() === "agent" && props.view === "agents");
  return <a href={"#" + props.view} data-view={props.view} aria-current={here() ? "page" : undefined}>{props.children}</a>;
}
function App() {
  createEffect(() => { document.title = waiting() ? "(" + waiting() + ") wicket" : "wicket"; });
  return <>
    <a class="skip" href="#main">Skip to the page</a>
    <header class="top">
      <div class="bar"><h1>wicket</h1><span id="tenant">{s.tenant ? "tenant " + strip(s.tenant) : ""}</span></div>
      <nav id="nav" aria-label="Views" hidden={!s.ready}>
        <Tab view="inbox">Inbox<span class="count" id="nav-waiting" hidden={!waiting()}>{waiting() || ""}</span></Tab>
        <Tab view="agents">Agents</Tab>
        <Tab view="activity">Activity</Tab>
        <Tab view="settings">Settings<span class="count bad" id="nav-health" hidden={!problems().length}>{problems().length || ""}</span></Tab>
      </nav>
    </header>
    <main id="main">
      <div id="console" hidden={!s.ready}>
        <Inbox />
        <Agents />
        <Agent />
        <Show when={view() === "activity" || view() === "settings"}>
          <section class="view"><h2>{view() === "activity" ? "Activity" : "Settings"}</h2><p class="note">Not built in this prototype.</p></section>
        </Show>
      </div>
    </main>
  </>;
}

render(() => <App />, document.body);
poll();
setInterval(poll, 2000);

// The redesigned console's Inbox, Agents and agent page in Preact, against the console's API.
// Every string from the API is a JSX text child or attribute: Preact sets it as text, never as markup.
import { render, Fragment } from "preact";
import { useState, useEffect } from "preact/hooks";
import "../../shared/console.css";
import {
  strip, plural, setSkew, nowSecs, rel, clock, iso, at, riskClass, riskLabel, riskCode, span, asks, verb, verbsOf,
  num, pathsText, problemList, line, egressOf,
} from "./helpers.js";

// ---- small pieces ----

// A time, its exact UTC value in `title` and `datetime`.
const Time = ({ t, text, cls }) => (
  <time class={cls} title={t ? iso(t) : undefined} dateTime={t ? iso(t) : undefined}>{text === undefined ? at(t) : text}</time>
);

// A long id shortened in the middle, the whole id its title.
function IdShort({ id }) {
  id = strip(id);
  return (
    <span class="id-short" title={id}>
      {id.length <= 18 ? id : <><span class="id-head">{id.slice(0, -6)}</span><span class="id-tail">{id.slice(-6)}</span></>}
    </span>
  );
}

// A URL broken only after its slashes and dots.
const Wrapped = ({ cls, text }) => (
  <div class={cls}>{String(text).split(/(?<=[/.?&])/).map((part, i) => <Fragment key={i}>{part}<wbr /></Fragment>)}</div>
);

const Field = ({ label, cls, children }) => <><dt>{label}</dt><dd class={cls}>{children}</dd></>;

const Kv = ({ k, v }) => <div class="row"><span class="meta">{k}</span><span class="mono">{strip(v)}</span></div>;

// ---- the Inbox ----

function Status({ s }) {
  const working = (s.runs || []).filter(r => r.status === "running" && !r.revoked).length;
  const waiting = (s.pending || []).length + ((s.standing || {}).asks || []).length;
  const problems = problemList(s).length;
  const part = (n, one, many, href, cls) => <a class={cls} href={href}>{plural(n, one, many)}</a>;
  const parts = [part(working, "agent working", "agents working", "#agents")];
  if (waiting) parts.push(part(waiting, "request waiting for you", "requests waiting for you", "#inbox", "warn"));
  parts.push(problems ? part(problems, "problem", "problems", "#health", "bad") : <span class="ok">no problems</span>);
  return <p class="status" id="status" aria-live="polite">{parts.map((x, i) => <Fragment key={i}>{i ? " · " : ""}{x}</Fragment>)}</p>;
}

// Who asks: the agent and its zone behind a button that shows its full identity, or said plainly.
function WhoAsks({ id }) {
  const [open, setOpen] = useState(false);
  if (id.verified) return (
    <span class="who-ask">
      <span class="ok">{"✓ "}</span>
      <button type="button" class="idname" title="Show its identity" aria-expanded={String(open)} onClick={() => setOpen(!open)}>{strip(id.agent)}</button>
      {" · zone " + strip(id.zone)}
      <div class="idline" hidden={!open}>{strip(id.id)}</div>
    </span>
  );
  if ((id.error || "").startsWith("no identity was issued")) return <span class="who-ask">a program (it has no agent identity)</span>;
  return <span class="who-ask"><span class="bad">We can't confirm which agent this is ({strip(id.error || "unknown")}). Only Don't allow is offered.</span></span>;
}

// Which call in the box asked, as the agent's event stream reports it: helpful, not proof.
function AskedBy({ list }) {
  const say = r => strip(r.agent) + " — " + strip(r.tool) + ": " + strip(r.call).slice(0, 120);
  return (
    <div class="who">
      {!list.length && <div>Asked by (in the box): unknown (no agent event stream)</div>}
      {list.map((a, i) => {
        const rs = a.requesters || [];
        if (a.basis === "none" || !rs.length) return list.length > 1 ? <div key={i}>Asked by (in the box): unknown — no tool call was in flight</div> : null;
        if (a.basis === "ambiguous") return (
          <Fragment key={i}>
            <div>Asked by (in the box): one of {rs.length} concurrent calls:</div>
            {rs.map((r, j) => <div key={j} class="cand">{"• " + say(r)}</div>)}
          </Fragment>
        );
        return <div key={i}>Asked by (in the box): {say(rs[0])}</div>;
      })}
      {list.length > 1 && <div class="warn">Asked by more than one agent: one grant would serve all of them.</div>}
      <div class="note">{(list.length ? "As the agent reports it, not proven: anything" : "Anything") + " in this box could use the grant."}</div>
    </div>
  );
}

function PendingCard({ p, now }) {
  const a = asks(p), id = p.identity || {};
  const idOk = !!id.verified || (id.error || "").startsWith("no identity was issued");
  // The first button's words are the server's terms for it: a git push is granted as a window.
  const ot = p.once_terms || { uses: 1, ttl_secs: 600 };
  const window_ = ot.uses !== 1;
  const decide = choice => () => console.info("decide", { id: p.id, choice });
  const once = <button class="approve" disabled={!idOk} onClick={decide("once")}>{window_ ? "Allow for " + span(ot.ttl_secs) : a.internal ? "Allow" : "Allow once"}</button>;
  const hour = <button disabled={!idOk} onClick={decide("hour")}>Allow for 1 hour</button>;
  const deny = <button class="deny apart" onClick={decide("deny")}>Don't allow</button>;
  // Only the steps the server grants: a push is one window, R3 and R4 one use, wicket's own kinds one decision.
  const single = window_ || p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible";
  const buttons = !idOk ? deny : a.internal || single ? <>{once}{deny}</> : <>{once}{hour}{deny}</>;
  return (
    <div class="card req" data-id={p.id}>
      <div class="req-head">
        <span class={"risk " + riskClass(p.risk)}>{riskLabel(p.risk)}</span>
        <Time cls="age" t={p.created_at} text={rel(p.created_at, now)} />
      </div>
      <dl class="fields">
        <Field label="Who"><WhoAsks id={id} /></Field>
        {a.internal
          ? <Field label="Wants to" cls="said">{a.what.charAt(0).toLowerCase() + a.what.slice(1)}</Field>
          : <>
            <Field label="Wants to" cls="said">{verb(p)}</Field>
            <Field label="Where">
              <div class="where">
                <span class="host">{strip(p.host)}</span>
                {p.path && p.path !== "/" && <Wrapped cls="path" text={strip(p.path) + (p.scope_prefix ? "…" : "")} />}
                {p.scope_prefix && <div class="meta">and every page under it</div>}
              </div>
            </Field>
          </>}
        <Field label="Why" cls="why">{"“" + a.why + "”"}</Field>
      </dl>
      <div class="buttons ladder">{buttons}</div>
      <details class="more req-more">
        <summary>Details</summary>
        {id.verified && <div class="chain">On behalf of: {(id.acting_for || []).map(strip).join(" → ")}</div>}
        <div class="mono raw">{strip(p.method + " " + p.host + p.path) + " · risk class " + riskCode(p.risk)}</div>
        <AskedBy list={p.attribution || []} />
        <div class="meta">{p.id + " · zone " + strip(p.zone) + " · run "}<IdShort id={p.run} /></div>
        {idOk && !a.internal && single && <div class="note">{window_
          ? "A push is allowed as one window: any number of requests for " + span(ot.ttl_secs) + ", for its ref discovery and upload."
          : "This kind is allowed one request at a time."}</div>}
      </details>
    </div>
  );
}

function Inbox({ s }) {
  const waiting = s.pending.length + ((s.standing || {}).asks || []).length;
  const problems = problemList(s);
  return (
    <section class="view" id="view-inbox" aria-labelledby="inbox-h">
      <h2 id="inbox-h" class="sr-only">Inbox</h2>
      <Status s={s} />
      <div class="grid inbox">
        <div>
          <h3 class="sub" id="waiting-h">{waiting ? "Needs you (" + waiting + ")" : "Needs you"}</h3>
          <div id="pending" class="deck">
            {s.pending.length ? s.pending.map(p => <PendingCard key={p.id} p={p} now={s.now} />) : <div class="empty">Nothing is waiting for you.</div>}
          </div>
        </div>
        <div>
          <h3 class="sub">Problems</h3>
          <div id="problems" class="card flush">
            {problems.length
              ? problems.map(([tone, text, href]) => <a key={tone + text} class={"problem " + tone} href={href}>{text}</a>)
              : <div class="empty">Nothing is wrong.</div>}
          </div>
        </div>
      </div>
    </section>
  );
}

// ---- Agents ----

// A run: who, where, its state and times, its pages; on its own page, Stop.
function Run({ s, x, page }) {
  const name = x.agent ? strip(x.agent) : "program run";
  const status = x.revoked ? "revoked" : String(x.status || "");
  const tone = ({ running: "good", revoked: "bad", failed: "bad", hibernated: "info" })[status] || "";
  const waiting = (s.pending || []).some(p => p.run === x.id);
  const href = "#agent/" + encodeURIComponent(x.id);
  return (
    <div class="row run">
      <div>
        <div class="run-head">
          {page ? <h2 class="run-name">{name}</h2> : <a class="run-name" href={href}>{name}</a>}
          <span class="meta">{" · zone " + strip(x.zone)}</span>
          <span class={"pill " + (waiting ? "warn" : tone)}>
            {waiting ? "waiting for you" : ({ running: "working", exited: "finished", revoked: "stopped by you", hibernated: "asleep" })[status] || strip(status)}
          </span>
        </div>
        <div class="meta">
          <Time t={x.started_at} text={"started " + rel(x.started_at, s.now)} />
          {x.ended_at ? <>{" · "}<Time t={x.ended_at} text={"ended " + rel(x.ended_at, s.now)} /></> : null}
          {" · "}<IdShort id={x.id} />
        </div>
        <div class="links">
          {x.acp && x.status === "running" && !x.revoked && <a class="session" href={"/session?run=" + encodeURIComponent(x.id)}>Live session</a>}
          {x.remote_url && x.remote_url.startsWith("https://") &&
            <a class="session" href={x.remote_url} target="_blank" rel="noopener noreferrer">Remote Control session {"↗"}</a>}
          {!page && <a href={href}>What it can reach {"›"}</a>}
        </div>
      </div>
      {page && x.status === "running" && x.has_identity && !x.revoked &&
        <span class="acts"><button class="deny" onClick={() => console.info("stop", x.id)}>Stop agent{"…"}</button></span>}
    </div>
  );
}

const Agents = ({ s }) => (
  <section class="view" id="view-agents" aria-labelledby="agents-h">
    <div class="view-head">
      <h2 id="agents-h">Agents</h2>
      <button type="button" class="approve" id="start-open" onClick={() => console.info("start")}>Start an agent…</button>
    </div>
    <div class="card flush" id="runs">
      {s.runs.length ? s.runs.map(x => <Run key={x.id} s={s} x={x} />) : <div class="empty">No runs yet.</div>}
    </div>
  </section>
);

// ---- an agent's page ----

function ReachLine({ text, end, note }) {
  const has = end !== undefined || note;
  return (
    <div class="reach">
      <div class="mono">{text}</div>
      {has && <div class="meta">{end}{note && (end !== undefined ? " · " : "") + note}</div>}
    </div>
  );
}

// What a run can reach (its zone's rules, its live grants, the standing rules for it), then where it runs.
function Permissions({ s, run, a }) {
  const t = a.token || {};
  const now = nowSecs();
  const row = s.runs.find(x => x.id === run) || {};
  const rules = ((s.standing || {}).rules || []).filter(r => r.live && (r.for === "zone" ? r.zone === t.zone
    : row.agent && String(r.principal || "").endsWith("/z/" + row.zone + "/a/" + row.agent)));
  const grants = (t.grants || []).filter(g => !g.revoked && (!g.expires_at || g.expires_at > now));
  const reach = [
    ...(t.reach || []).map((r, i) => <ReachLine key={"z" + i} text={verbsOf(r.methods) + " " + strip(r.host) + "  " + pathsText(r.paths)}
      note={"from its zone's rules" + (r.allow_dangerous ? "; including requests that can't be undone" : "")} />),
    ...grants.map(g => <ReachLine key={"g" + g.id} text={verb(g) + " " + strip(g.host + g.path)}
      end={<span>you allowed it; ends <Time t={g.expires_at} /></span>}
      note={(g.uses == null ? "any number of times" : plural(g.uses, "more time", "more times")) + " · allowed by " + strip(g.approved_by || "?") +
        (g.reached_node === false ? " · not yet on its server" : "")} />),
    ...rules.map((r, i) => <ReachLine key={"s" + i} text={verbsOf(r.rule.methods) + " " + strip(r.rule.host) + "  " + pathsText(r.rule.paths)}
      end={<span>always allowed, {r.expires_at ? <Time t={r.expires_at} text={"ends " + at(r.expires_at)} /> : "until removed"}</span>}
      note={r.for === "zone" ? "for every agent in its zone" : "for this agent"} />),
  ];
  const sl = a.holdings && a.holdings.slice;
  return (
    <>
      <h4>Can reach</h4>
      {!t.held ? <>{reach}<div class="note">No token now: {strip(t.why)}</div></>
        : reach.length ? reach : <div class="empty">Nothing: everything it asks for waits for you.</div>}
      <h4>Where it runs</h4>
      {a.revoked && <div class="callout warn">Stopped by {strip(a.revoked.by)}: {strip(a.revoked.reason)}</div>}
      <Kv k="server" v={a.node} />
      {a.deadline && <Kv k="its permissions end" v={(a.deadline.until_ms ? at(a.deadline.until_ms / 1000) : "—") + (a.deadline.stopped ? " (stopped)" : "")} />}
      {a.holdings && <>
        <Kv k="keys it can use" v={a.holdings.secrets.length ? a.holdings.secrets.map(strip).join(", ") : "none"} />
        <Kv k="model budget left on its server" v={sl ? num(sl.requests) + " requests, " + num(sl.output_tokens) + " output tokens" +
          (sl.input_tokens != null ? ", " + num(sl.input_tokens) + " input tokens" : "") : "none"} />
      </>}
      <Kv k="organisation rules" v={a.policy.version ? strip(a.policy.version) + (a.policy.current ? " (current)" : " (not the installed " + strip(a.policy.installed || "none") + ")") : "none"} />
      {t.held && (
        <details class="more">
          <summary>Technical details: its token, grants and zone policy</summary>
          <Kv k="status" v={strip(a.status) + (a.feed ? " · node feed epoch " + strip(a.feed.epoch) : "")} />
          <Kv k="token" v={"box " + strip(t.box_path) + " · epoch " + strip(t.epoch) + " · zone " + strip(t.zone) + " · minted by " + strip(t.issued_by) +
            (t.loads === true ? " · loads" : " · does NOT load: " + strip((t.loads || {}).error || ""))} />
          {(t.blocks || []).map(b => (
            <Fragment key={b.index}>
              <div class="row">
                <span class={b.revoked ? "blocked" : "ok"}>{"block " + b.index + " · " + strip(b.kind) + (b.revoked ? " · REVOKED" : "")}</span>
                <span class="meta">{"revocation " + strip(b.revocation_fingerprint) + (b.signed_by ? " · signed by " + strip(b.signed_by) : "")}</span>
              </div>
              <pre class="src">{b.source}</pre>
            </Fragment>
          ))}
          {(t.grants || []).map(g => <Kv key={g.id} k={g.id} v={g.method + " " + g.host + g.path + " · " + (g.uses == null ? "unlimited uses" : g.uses + " uses (counted on the node)") +
            " · ends " + at(g.expires_at) + " · approved by " + (g.approved_by || "?") + " at " + at(g.approved_at) +
            (g.revoked ? " · revoked" : "") + (g.reached_node === false ? " · not yet on its node" : "")} />)}
          {t.zone_cedar && <><div class="meta">zone policy (Cedar, generated from the manifest)</div><pre class="src">{t.zone_cedar}</pre></>}
        </details>
      )}
    </>
  );
}

function AgentPage({ s, run }) {
  const [auth, setAuth] = useState(null);
  useEffect(() => {
    let live = true;
    setAuth(null);
    fetch("/api/runs/" + encodeURIComponent(run) + "/authority")
      .then(async r => { const j = await r.json().catch(() => ({ error: "unreadable answer" })); if (!r.ok) throw new Error(j.error || r.statusText); return j; })
      .then(a => live && setAuth({ a }), e => live && setAuth({ error: strip(e.message) }));
    return () => { live = false; };
  }, [run]);
  const x = s.runs.find(r => r.id === run);
  const runName = id => { const r = s.runs.find(r => r.id === id); return r ? (r.agent ? strip(r.agent) : "a program") : strip(id); };
  const mine = (s.audit || []).filter(op => op.run === run).reverse();
  return (
    <section class="view" id="view-agent" aria-labelledby="detail-title">
      <a class="back" href="#agents">{"‹ Agents"}</a>
      <div id="agent-head">
        {x ? <Run s={s} x={x} page /> : <><h2>Agent</h2><p class="note">This agent run isn't in the latest list (only the 15 most recent are).</p></>}
      </div>
      <div class="card" id="detail">
        <div class="card-head"><h3 id="detail-title">Permissions</h3></div>
        <div id="detail-body">
          {!auth ? <div class="meta">loading…</div>
            : auth.error ? <div class="blocked">{auth.error}</div>
            : <Permissions s={s} run={run} a={auth.a} />}
        </div>
      </div>
      <div class="card">
        <h3>Recent activity</h3>
        <div class="log" id="agent-log">
          {mine.length ? mine.map(op => {
            const [tag, tone, text] = line(op, runName);
            return (
              <div key={op.seq} class="logline">
                {op.ts ? <Time t={op.ts} text={clock(op.ts)} /> : <span />}
                <span class={"tag " + tone}>{tag}</span>
                <span class="text">{text}{op.run && egressOf(op) && <>{" "}<button class="link" onClick={() => console.info("why", op.seq)}>why?</button></>}</span>
              </div>
            );
          }) : <div class="empty">Nothing recorded for it in the latest activity.</div>}
        </div>
      </div>
    </section>
  );
}

// ---- the page ----

// The view from the address's hash, so the back button works: #inbox (the default), #agents, #agent/<run>.
function route() {
  const h = location.hash;
  const ag = /^#agent\/([A-Za-z0-9_-]{1,80})$/.exec(h);
  if (ag) return { view: "agent", run: ag[1] };
  if (["#agents", "#activity", "#settings"].includes(h)) return { view: h.slice(1), run: "" };
  return { view: "inbox", run: "" };
}
function useRoute() {
  const [r, setR] = useState(route);
  useEffect(() => {
    const on = () => { setR(route()); window.scrollTo(0, 0); };
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return r;
}

// GET /api/state every 2 s, one poll at a time, each bounded; a failed one is said, and the poll goes on.
function useState2s() {
  const [s, setS] = useState(null), [stale, setStale] = useState("");
  useEffect(() => {
    let busy = false, heard = 0;
    const tick = async () => {
      if (busy) return;
      busy = true;
      try {
        const r = await fetch("/api/state", { signal: AbortSignal.timeout(10000) });
        if (!r.ok) throw new Error("HTTP " + r.status);
        const j = await r.json();
        if (typeof j.now === "number") setSkew(j.now - Date.now() / 1000);
        heard = Date.now();
        setS(j); setStale("");
      } catch (e) {
        const why = e.name === "TimeoutError" ? "no answer in 10 s" : /^HTTP/.test(e.message) ? e.message : "no answer";
        setStale("Can't reach wicket (" + why + ")" + (heard ? " since " + new Date(heard).toISOString().slice(11, 19) + "Z; what is shown is as of then" : "") + ". Retrying.");
      } finally { busy = false; }
    };
    tick();
    const t = setInterval(tick, 2000);
    return () => clearInterval(t);
  }, []);
  return [s, stale];
}

const TABS = [["inbox", "Inbox"], ["agents", "Agents"], ["activity", "Activity"], ["settings", "Settings"]];

function App() {
  const { view, run } = useRoute();
  const [s, stale] = useState2s();
  const waiting = s ? s.pending.length + ((s.standing || {}).asks || []).length : 0;
  const alerts = s ? problemList(s).length : 0;
  useEffect(() => { document.title = waiting ? "(" + waiting + ") wicket" : "wicket"; }, [waiting]);
  const count = (n, cls) => <span class={"count" + (cls ? " " + cls : "")} hidden={!n}>{n ? String(n) : ""}</span>;
  return (
    <>
      <a class="skip" href="#main">Skip to the page</a>
      <header class="top">
        <div class="bar"><h1>wicket</h1><span id="tenant">{s ? "tenant " + s.tenant : ""}</span></div>
        <nav id="nav" aria-label="Views">
          {TABS.map(([v, label]) => (
            <a key={v} href={"#" + v} data-view={v} aria-current={view === v || (view === "agent" && v === "agents") ? "page" : undefined}>
              {label}{v === "inbox" && count(waiting)}{v === "settings" && count(alerts, "bad")}
            </a>
          ))}
        </nav>
      </header>
      <div class="banner" id="stale" role="status" hidden={!stale}>{stale}</div>
      <main id="main">
        {s && <div id="console">
          {view === "inbox" ? <Inbox s={s} />
            : view === "agents" ? <Agents s={s} />
            : view === "agent" ? <AgentPage s={s} run={run} />
            : <section class="view"><h2>{view === "activity" ? "Activity" : "Settings"}</h2><p class="note">Not in this prototype.</p></section>}
        </div>}
      </main>
    </>
  );
}

render(<App />, document.body);

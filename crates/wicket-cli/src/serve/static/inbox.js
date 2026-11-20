// The Inbox (docs/explanation/console-design.md), drawn with lit-html (#574, the port's step 2): the
// status line, the request cards and the problems. Every string from the API goes in as a template
// value, which lit-html sets as text, never as HTML.
//
// console.js is still a classic script: its helpers (strip, asks, act, …) are globals, and this
// module calls them; the signing path (act, signed, describe and the sheet) is console.js's and
// unchanged. console.js calls window.wicketInbox's functions where it drew these itself.
import { html, render, nothing } from "lit-html";
import { repeat } from "lit-html/directives/repeat.js";

// console.js's helpers are named bare: a classic script's top-level `const` and `function`
// declarations are global names a module can use, though `const`s aren't properties of globalThis.
const g = globalThis;

// lit-html renders after what a container already holds: the first time, it is emptied of the
// page's own placeholder.
const owned = new WeakSet();
function draw(value, box) {
  if (!owned.has(box)) { box.replaceChildren(); owned.add(box); }
  render(value, box);
}

// A URL broken only after its slashes and dots, so it wraps at a segment, not mid-word.
const wrapped = (cls, text) => html`<div class=${cls}>${String(text).split(/(?<=[/.?&])/).map(part => html`${part}<wbr>`)}</div>`;

// The "Where" of a request: its host, then its path quieter and wrapped at its slashes.
const where = p => html`<div class="where"><span class="host">${strip(p.host)}</span>${p.path && p.path !== "/" ? wrapped("path", strip(p.path) + (p.scope_prefix ? "…" : "")) : nothing}${p.scope_prefix ? html`<div class="meta">and every page under it</div>` : nothing}</div>`;

const field = (label, value, cls) => html`<dt>${label}</dt><dd class=${cls || ""}>${value}</dd>`;

// One request (labelled fields: who, wants to, where, why, risk; then the choices; the rest under
// Details), as pendingCard drew it. Elements from console.js's helpers (who asks, its identity line,
// the run id, the age) are made once per card content and kept, so a poll that changes nothing
// changes nothing on the page.
const memo = new Map();
function card(s, p) {
  const key = JSON.stringify([p.risk, p.method, p.host, p.path, p.scope_prefix, p.reason, p.identity, p.attribution, p.zone, p.run, p.lease, p.claims, p.once_terms]);
  let m = memo.get(p.id);
  if (!m || m.key !== key) {
    const [who, idOk] = whoAsks(p.identity || {});
    const age = timeEl(p.created_at, rel(p.created_at, s.now)); age.className = "age";
    m = { key, who, idOk, age, warn: renderWho(p.attribution || [], "warnings"), list: renderWho(p.attribution || [], "list"), run: idEl(p.run) };
    memo.set(p.id, m);
  } else m.age.textContent = rel(p.created_at, s.now);
  const a = asks(p);
  const id = p.identity || {};
  // The first button's words are the server's terms for it (`once_terms`): a git push is granted as
  // a window whatever is picked, and the card mustn't say otherwise.
  const ot = p.once_terms || { uses: 1, ttl_secs: 600 };
  const window_ = ot.uses !== 1;
  const onceLabel = window_ ? "Allow for " + span(ot.ttl_secs) + " (any number of uses)" : a.internal ? "Allow" : "Allow once (expires in " + span(ot.ttl_secs) + ")";
  const once = html`<button class="approve" ?disabled=${!m.idOk} @click=${() => act("approve", { id: p.id, uses: 1, ttl_secs: 600 })}>${onceLabel}</button>`;
  const hour = html`<button ?disabled=${!m.idOk} @click=${() => act("approve", { id: p.id, unlimited: true, ttl_secs: 3600 })}>Allow for 1 hour (any number of uses)</button>`;
  const deny = html`<button class="deny apart" @click=${() => act("deny", { id: p.id })}>Don't allow</button>`;
  // Only the steps the server grants: a push is one window, R3 and R4 one use, wicket's own kinds one
  // decision (#597 re-review, #621).
  const oneStep = window_ || p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible";
  const buttons = !m.idOk ? [deny] : a.internal || oneStep ? [once, deny] : [once, hour, deny];
  const note = m.idOk && !a.internal && oneStep
    ? html`<div class="note">${window_ ? "A push is allowed as one window: any number of requests for " + span(ot.ttl_secs) + ", for its ref discovery and upload." : "This kind is allowed one request at a time."}</div>`
    : nothing;
  return html`<div class="card req ${p.id === openId ? "opened" : ""}" data-id=${p.id}>
    <div class="req-head"><span class="risk ${riskClass(p.risk)}">${riskWords(p.risk)}</span>${m.age}</div>
    <dl class="fields">
      ${field("Who", m.who)}
      ${a.internal ? field("Wants to", a.what.charAt(0).toLowerCase() + a.what.slice(1), "said")
        : html`${field("Wants to", verb(p) + " (" + strip(p.method) + ")", "said")}${field("Where", where(p))}`}
      ${a.said.map(([label, text]) => field(label + (label === "Why" ? "" : ", as the agent says"), "“" + text + "”", label === "Why" ? "why" : "asked"))}
      ${a.wicket ? field("wicket says", a.wicket, "why") : nothing}
    </dl>
    ${m.warn}
    <div class="buttons ladder">${buttons}</div>
    <details class="more req-more"><summary>Details</summary>
      ${id.verified ? html`<div class="chain">On behalf of: ${(id.acting_for || []).map(strip).join(" → ")}</div>` : nothing}
      <div class="mono raw">${strip(p.method + " " + p.host + p.path) + " · risk class " + riskCode(p.risk)}</div>
      ${a.mixed ? html`<div class="meta">The request's text, with the agent's words in it: “${a.mixed}”</div>` : nothing}
      ${m.list}
      <div class="meta">${p.id + " · zone " + strip(p.zone) + " · run "}${m.run}</div>
      ${note}
    </details>
  </div>`;
}

// The order and set of cards last drawn: when they change, the layout moved, and taps are ignored
// for a moment (console.js's `settled`), so a tap can't land on a card that just moved under it.
let lastOrder = null;
let openId = "";

function renderPending(s) {
  const box = document.getElementById("pending");
  if (!box) return;
  const live = new Set(s.pending.map(p => p.id));
  for (const id of [...memo.keys()]) if (!live.has(id)) memo.delete(id);
  const order = s.pending.map(p => p.id).join(",");
  draw(s.pending.length ? repeat(s.pending, p => p.id, p => card(s, p)) : html`<div class="empty">Nothing is waiting for you.</div>`, box);
  if (lastOrder !== null && order !== lastOrder) layoutMoved();
  lastOrder = order;
}

// A request opened from a notification: its card, outlined (#644); "" for none.
function setOpen(id, s) {
  openId = id || "";
  if (s) renderPending(s);
  return openId ? document.querySelector('#pending .req[data-id="' + openId.replace(/[^A-Za-z0-9_-]/g, "") + '"]') : null;
}

// How things are, in one line: agents working, requests waiting, problems; each part a link.
function renderStatus(s) {
  const box = document.getElementById("status");
  if (!box) return;
  const runs = s.runs || [];
  const working = runs.filter(r => r.status === "running" && !r.revoked).length;
  const waiting = (s.pending || []).length + (((s.standing || {}).asks) || []).length;
  const problems = problemList(s).length;
  const part = (n, one, many, href, cls) => html`<a class=${cls || ""} href=${href}>${plural(n, one, many)}</a>`;
  draw(html`${part(working, "agent working", "agents working", "#agents")}${waiting ? html` · ${part(waiting, "request waiting for you", "requests waiting for you", "#inbox", "warn")}` : nothing} · ${problems ? part(problems, "problem", "problems", "#health", "bad") : html`<span class="ok">no problems</span>`}`, box);
}

// What is wrong, in plain words, each linking to where to act.
function renderProblems(s) {
  const box = document.getElementById("problems");
  if (!box) return;
  const list = problemList(s);
  draw(list.length ? list.map(([tone, text, href]) => html`<a class="problem ${tone}" href=${href}>${text}</a>`) : html`<div class="empty">Nothing is wrong.</div>`, box);
}

g.wicketInbox = { renderPending, renderStatus, renderProblems, setOpen };

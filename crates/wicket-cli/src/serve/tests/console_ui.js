"use strict";
// The console page's approval flow (#124), run under node against a small fake DOM:
// - pending cards are kept by request id, so a poll that changes nothing replaces nothing;
// - a tap just after the cards moved is ignored;
// - a tap opens an in-page confirmation built from the action the server returned, and only its own
//   sign button starts the passkey ceremony;
// - nothing is re-rendered while the confirmation or the ceremony is open.
// Usage: node console_ui.js path/to/console.js
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

class Node {
  constructor(tag) { this.tagName = tag; this.children = []; this.parent = null; this._text = ""; this.className = ""; this.hidden = false; this.disabled = false; this.dataset = {}; this.onclick = null; this.listeners = {}; this.value = ""; }
  append(...ns) { for (const n of ns) { if (typeof n === "string") n = new Text(n); if (n.parent) n.parent.children.splice(n.parent.children.indexOf(n), 1); n.parent = this; this.children.push(n); } }
  replaceChildren(...ns) { for (const c of this.children) c.parent = null; this.children = []; this.append(...ns); }
  set textContent(t) { this._text = String(t); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
  addEventListener(k, f) { this.listeners[k] = f; }
  focus() {}
  scrollIntoView() {}
  click() { if (!this.disabled && this.onclick) return this.onclick({ preventDefault() {} }); }
  all(pred, out = []) { for (const c of this.children) { if (pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
class Text { constructor(t) { this._t = t; this.parent = null; } get textContent() { return this._t; } }

const ids = {};
for (const id of ["msg", "auth", "console", "tenant", "pending", "runs", "runform", "runform-title", "runform-text", "runform-go", "runform-cancel", "start", "decided", "audit", "operator", "confirm", "confirm-title", "confirm-what", "confirm-state", "confirm-go", "confirm-cancel", "detail", "detail-title", "detail-body", "detail-close", "policy"]) ids[id] = new Node("div");
ids.confirm.hidden = true;
let now = 100000;
let timers = [];
const calls = [];
let state = null;
// A hostile string an agent chose (a grant's path): it must stay text.
const HOSTILE = "/x<img src=x onerror=alert(1)>";
const authority = { status: "running", node: "local", policy: { version: null }, token: { held: true, box_path: "run_a", epoch: 0, zone: "z", issued_by: "the authority root", loads: true,
  blocks: [{ index: 0, kind: "zone", source: "check if reach(\"" + HOSTILE + "\");", signed_by: null, revocation_fingerprint: "0123456789abcdef", revoked: false }],
  grants: [{ id: "g-1", method: "POST", host: "h", path: HOSTILE, uses: 2, expires_at: 1, approved_by: "passkey:laptop", approved_at: 1, revoked: false, reached_node: true }] } };
const explained = { run: "run_a", policy: null, recorded: { method: "GET", host: "h", path: HOSTILE, outcome: "forbidden", decided_on: "the box's node", at: 1, detail: "d" },
  against_token_now: { available: true, decision: "forbidden", why: "block 0: check if " + HOSTILE, zone_says: "Forbidden" } };
let nextAction = null;
const reply = (body, ok = true) => ({ ok, status: ok ? 200 : 400, json: async () => body });
const fetch = async (path, opts) => {
  calls.push({ path, body: opts && opts.body ? JSON.parse(opts.body) : null });
  if (path === "/api/me") return reply({ who: { state: "operator" } });
  if (path === "/api/state") return reply(state);
  if (path === "/api/action/begin") return reply({ action: nextAction, publicKey: { challenge: "Y2g", rpId: "localhost", allowCredentials: [] } });
  if (path === "/api/action/finish") return reply({ ok: "done" });
  if (path === "/api/policy") return reply({ installed: null, current: null, versions: [], runs: [] });
  if (path.endsWith("/authority")) return reply(authority);
  if (path.startsWith("/api/explain/")) return reply(explained);
  return reply({}, false);
};
let ceremonies = 0;
const sandbox = {
  document: { createElement: t => new Node(t), createTextNode: t => new Text(t), getElementById: id => ids[id], addEventListener: (k, f) => { if (k === "DOMContentLoaded") sandbox.ready = f; } },
  fetch,
  navigator: { credentials: { get: async () => { ceremonies++; return { rawId: new ArrayBuffer(1), response: { clientDataJSON: new ArrayBuffer(1), authenticatorData: new ArrayBuffer(1), signature: new ArrayBuffer(1) } }; } } },
  performance: { now: () => now },
  setTimeout: (f, ms) => { timers.push({ f, at: now + ms }); return timers.length; },
  clearTimeout: () => {},
  setInterval: () => 0,
  btoa: s => Buffer.from(s, "binary").toString("base64"),
  atob: s => Buffer.from(s, "base64").toString("binary"),
  Uint8Array, ArrayBuffer, JSON, Math, String, Object, Array, Set, Map, Promise, Error, Date,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), sandbox);
const run = expr => vm.runInContext(expr, sandbox);
const flush = () => new Promise(r => setImmediate(r));
const advance = async ms => { now += ms; const due = timers.filter(t => t.at <= now); timers = timers.filter(t => t.at > now); for (const t of due) t.f(); await flush(); };

const req = (id, risk, path) => ({ id, risk, method: "POST", host: "api.example.com", path, scope_prefix: false, reason: "r", identity: { verified: true, agent: "lead", zone: "z", acting_for: [], id: "spiffe://x" }, attribution: [], zone: "z", run: "run_a", created_at: 0 });
const A = req("q-a", "R1ReadScoped", "/harmless"), B = req("q-b", "R3ExternalOrIrreversible", "/dangerous"), X = req("q-x", "R1ReadScoped", "/other");
const base = { now: 10, tenant: "t0", runs: [], manifests: [], decided: [], audit: [], passkeys: [] };
const cardsIn = () => ids.pending.children;
const idOf = c => c.all(n => n.className === "meta")[0].textContent.split(" ")[0];
const button = (card, label) => card.all(n => n.tagName === "button" && n.textContent.startsWith(label))[0];
const began = () => calls.filter(c => c.path === "/api/action/begin");

(async () => {
  state = { ...base, pending: [X, A, B] };
  sandbox.ready(); await flush(); await flush(); await flush();
  assert.deepStrictEqual(cardsIn().map(idOf), ["q-x", "q-a", "q-b"]);
  const aCard = cardsIn()[1];
  await advance(2000);

  // A poll that changes nothing keeps the same elements (and so the same buttons).
  await run("refresh()"); await flush();
  assert.strictEqual(cardsIn()[1], aCard, "an unchanged card is not rebuilt");
  await advance(2000);

  // The card above A goes: B's button is now where A's was. A tap right then is ignored.
  state = { ...base, pending: [A, B] };
  await run("refresh()"); await flush();
  assert.strictEqual(cardsIn()[0], aCard);
  button(cardsIn()[1], "Approve once").click(); await flush();
  assert.strictEqual(began().length, 0, "a tap just after the layout changed is ignored");

  // Once settled, a tap asks the server for the action and opens the confirmation; no passkey yet.
  await advance(1000);
  nextAction = { v: 1, action: "decide", request: "q-a", run: "run_a", method: "POST", host: "api.example.com", path: "/harmless", risk: "R1ReadScoped", prefix: false, decision: "approve", uses: 1, ttl_secs: 600, agent: "spiffe://x", requested_by: [] };
  button(aCard, "Approve once").click(); await flush();
  assert.strictEqual(began().length, 1);
  assert.strictEqual(began()[0].body.id, "q-a");
  assert.strictEqual(ids.confirm.hidden, false, "the confirmation is open");
  assert.strictEqual(ceremonies, 0, "the click alone starts no passkey ceremony");
  const what = ids["confirm-what"].textContent;
  assert.ok(what.includes("/harmless") && what.includes("q-a") && what.startsWith("Approve once"), what);
  // Its sign button isn't live at once (a second tap aimed at the card mustn't land on it).
  assert.strictEqual(ids["confirm-go"].disabled, true);
  ids["confirm-go"].click(); await flush();
  assert.strictEqual(ceremonies, 0);

  // While it is open, polls change nothing on the page, even if the agent reshuffles the cards.
  const before = cardsIn().slice();
  state = { ...base, pending: [X, B, A] };
  await run("refresh()"); await flush();
  assert.deepStrictEqual(cardsIn(), before, "no re-render while confirming");
  // And another card's buttons can't start a second ceremony.
  button(cardsIn()[1], "Approve once").click(); await flush();
  assert.strictEqual(began().length, 1);

  // Its own button signs exactly the action shown; then the page refreshes again.
  await advance(1000);
  ids["confirm-go"].click(); await flush(); await flush();
  assert.strictEqual(ceremonies, 1);
  const fin = calls.filter(c => c.path === "/api/action/finish");
  assert.strictEqual(fin.length, 1);
  assert.strictEqual(fin[0].body.challenge, "Y2g");
  assert.strictEqual(ids.confirm.hidden, true);
  await flush();
  assert.deepStrictEqual(cardsIn().map(idOf), ["q-x", "q-b", "q-a"]);

  // Cancel closes it without a ceremony.
  await advance(1000);
  nextAction = { ...nextAction, request: "q-b", decision: "deny", uses: null, ttl_secs: null };
  button(cardsIn()[1], "Deny").click(); await flush();
  assert.strictEqual(ids.confirm.hidden, false);
  assert.ok(ids["confirm-what"].textContent.startsWith("Deny"), ids["confirm-what"].textContent);
  ids["confirm-cancel"].listeners.click(); await flush();
  assert.strictEqual(ids.confirm.hidden, true);
  assert.strictEqual(ceremonies, 1);
  console.log("console approval flow: ok");

  // #173: a run's authority and an explained decision open read-only in the detail card, and an
  // agent's strings in them stay text (the fake DOM has no innerHTML: only textContent exists).
  run("showAuthority('run_a')"); await flush(); await flush();
  assert.strictEqual(ids.detail.hidden, false);
  const text = ids["detail-body"].textContent;
  assert.ok(text.includes(HOSTILE) && text.includes("block 0 · zone") && text.includes("approved by passkey:laptop"), text);
  assert.ok(ids["detail-body"].all(n => n.tagName === "img").length === 0, "no element from an agent's string");
  run("showExplain(7)"); await flush(); await flush();
  assert.ok(ids["detail-body"].textContent.includes("block 0: check if " + HOSTILE), ids["detail-body"].textContent);
  assert.ok(calls.some(c => c.path === "/api/explain/7"));
  ids["detail-close"].listeners.click();
  assert.strictEqual(ids.detail.hidden, true);
  console.log("console authority views: ok");
})().catch(e => { console.error(e); process.exit(1); });

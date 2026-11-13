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
for (const id of ["msg", "auth", "console", "tenant", "pending", "runs", "runform", "runform-title", "runform-text", "runform-go", "runform-cancel", "start", "decided", "audit", "operator", "confirm", "confirm-title", "confirm-what", "confirm-state", "confirm-go", "confirm-cancel", "manifests", "mfedit", "mfedit-title", "mfedit-body", "mfedit-close"]) ids[id] = new Node("div");
ids.confirm.hidden = true;
let now = 100000;
let timers = [];
const calls = [];
let state = null;
let nextAction = null;
const reply = (body, ok = true) => ({ ok, status: ok ? 200 : 400, json: async () => body });
const fetch = async (path, opts) => {
  calls.push({ path, body: opts && opts.body ? JSON.parse(opts.body) : null });
  if (path === "/api/me") return reply({ who: { state: "operator" } });
  if (path === "/api/state") return reply(state);
  if (path === "/api/action/begin") return reply({ action: nextAction, publicKey: { challenge: "Y2g", rpId: "localhost", allowCredentials: [] } });
  if (path === "/api/action/finish") return reply({ ok: "done" });
  if (path === "/api/manifests/check") return reply({ valid: true, sha256: "bb", saved_sha256: "aa", diff: { widens: true, widening: ["reach api.example.com"], changes: ["+ reach x"] } });
  if (path.startsWith("/api/manifests/")) return reply({ root: "manifests", name: "a.yaml", yaml: "task: <b>hi</b>\n", valid: true, writable: true, history: [{ version: "1-aa.yaml", saved_before: 1, sha256_prefix: "aa" }],
    fields: [{ path: "task", value: "<b>hi</b>", default: false }, { path: "zone.isolation", value: "gvisor", default: true }],
    grants: { task: "<b>hi</b>", image: { Ok: "img" }, isolation: "Gvisor", unlisted_hosts: "escalate", reach: [], hosts: [], forbid: [], inject: [{ secret: "gh", host: "h", header: "authorization", secret_set: false, bound_to_host: true }], volumes: [], limits: {}, org_policy: null } });
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

  // #172: a manifest opens with its fields (defaults marked) and its secrets by name; editing checks
  // it, and Save asks the server for the signed action, which says that it widens authority.
  run("openManifest('manifests', 'a.yaml')"); await flush(); await flush(); await flush();
  assert.strictEqual(ids.mfedit.hidden, false);
  const mt = ids["mfedit-body"].textContent;
  assert.ok(mt.includes("zone.isolation = \"gvisor\"   (default)") && mt.includes("NOT SET in the vault") && mt.includes("<b>hi</b>"), mt);
  assert.ok(ids["mfedit-body"].all(n => n.tagName === "b").length === 0, "YAML stays text");
  assert.ok(mt.includes("WIDENS authority:"), mt);
  nextAction = { v: 1, action: "save_manifest", root: "manifests", name: "a.yaml", sha256: "bbbbbbbbbbbbbbbb", previous_sha256: "aaaaaaaaaaaaaaaa", widens: true, widening: ["reach api.example.com"], changes: ["+ reach x"] };
  const save = ids["mfedit-body"].all(n => n.tagName === "button" && n.textContent === "Save…")[0];
  save.disabled = false; save.click(); await flush();
  assert.ok(ids["confirm-what"].textContent.startsWith("Save manifests/a.yaml") && ids["confirm-what"].textContent.includes("WIDENS authority: reach api.example.com"), ids["confirm-what"].textContent);
  ids["confirm-cancel"].listeners.click(); await flush();
  console.log("console manifest editor: ok");
})().catch(e => { console.error(e); process.exit(1); });

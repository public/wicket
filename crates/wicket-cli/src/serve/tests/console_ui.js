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
  prepend(...ns) { const keep = this.children; this.children = []; this.append(...ns); for (const c of keep) this.children.push(c); }
  replaceChildren(...ns) { for (const c of this.children) c.parent = null; this.children = []; this.append(...ns); }
  set textContent(t) { this._text = String(t); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
  addEventListener(k, f) { this.listeners[k] = f; }
  focus() {}
  setAttribute(k, v) { this.attrs = { ...(this.attrs || {}), [k]: String(v) }; }
  getAttribute(k) { return (this.attrs || {})[k] ?? null; }
  scrollIntoView() {}
  click() { if (!this.disabled && this.onclick) return this.onclick({ preventDefault() {} }); }
  all(pred, out = []) { for (const c of this.children) { if (pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
class Text { constructor(t) { this._t = t; this.parent = null; } get textContent() { return this._t; } }

const ids = {};
for (const id of ["msg", "stale", "auth", "console", "tenant", "pending", "runs", "runform", "runform-title", "runform-text", "runform-go", "runform-cancel", "start", "decided", "audit", "operator", "confirm", "confirm-title", "confirm-what", "confirm-blast", "confirm-update", "confirm-state", "confirm-go", "confirm-cancel", "detail", "detail-title", "detail-body", "detail-close", "policy", "manifests", "mfedit", "mfedit-title", "mfedit-body", "mfedit-close", "push", "health", "placed", "fenced", "capacity", "capacity-form", "standing-asks", "standing-rules", "standing-pointer", "secrets", "secret-edit", "secret-edit-title", "secret-edit-body", "secret-edit-go", "secret-edit-cancel"]) ids[id] = new Node("div");
ids.confirm.hidden = true;
let now = 100000;
const EPOCH = 1700000000000;
let skew = 0; // how far the phone's clock is off
let slowBegin = null, slowPasskey = null;
let timers = [];
let intervalId = 0;
const alive = new Set();
const calls = [];
let state = null;
// A hostile string an agent chose (a grant's path): it must stay text.
const HOSTILE = "/x<img src=x onerror=alert(1)>";
let nextAction = null, begun = null;
// Web Push: a fake browser (permission, service worker, push manager) and server (devices).
let permAsked = 0, permAskedAt = -1, swRegistered = null, swListener = null, subscribed = null, pushDevices = [];
const fakeSub = { endpoint: "https://fcm.googleapis.com/fcm/send/dev1", options: { applicationServerKey: null },
  toJSON() { return { endpoint: this.endpoint, keys: { p256dh: "BPK", auth: "AU" } }; }, unsubscribe: async () => { subscribed = null; return true; } };
const swReg = { pushManager: { getSubscription: async () => subscribed,
  subscribe: async o => { assert.strictEqual(o.userVisibleOnly, true); assert.deepStrictEqual(Array.from(o.applicationServerKey), [4, 1, 2]); fakeSub.options.applicationServerKey = o.applicationServerKey.buffer; subscribed = fakeSub; return fakeSub; } } };
const devId = ep => require("crypto").createHash("sha256").update(ep).digest("hex").slice(0, 16);
let stateFail = null;
const reply = (body, ok = true) => ({ ok, status: ok ? 200 : 400, json: async () => body });
const fetch = async (path, opts) => {
  calls.push({ path, body: opts && opts.body ? JSON.parse(opts.body) : null });
  if (path === "/api/me") return reply({ who: { state: "operator" } });
  if (path === "/api/state") {
    if (stateFail === "network") throw new TypeError("Failed to fetch");
    if (stateFail) return { ok: false, status: stateFail, json: async () => ({}) };
    return reply(state);
  }
  if (path === "/api/action/begin") {
    const b = JSON.parse(opts.body);
    // Push actions: the server's signed JSON, as the fake server sees the device.
    const a = b.action === "push_subscribe" ? { v: 1, action: b.action, device: devId(b.endpoint), label: b.label, service: "fcm.googleapis.com", details: b.details, replaces: false }
      : b.action === "push_details" ? { v: 1, action: b.action, device: b.id, label: "laptop", service: "fcm.googleapis.com", details: true } : nextAction;
    begun = { body: b, action: a };
    if (slowBegin) await slowBegin;
    return reply({ action: a, publicKey: { challenge: "Y2g", rpId: "localhost", allowCredentials: [] }, expires_in_ms: 120000 });
  }
  if (path === "/api/action/finish") {
    const b = begun && begun.body;
    if (b && b.action === "push_subscribe") pushDevices = pushDevices.filter(d => d.id !== devId(b.endpoint)).concat([{ id: devId(b.endpoint), label: b.label, service: "fcm.googleapis.com", details: b.details, created: 1, last_success: null }]);
    if (b && b.action === "push_details") for (const d of pushDevices) if (d.id === b.id) d.details = true;
    return reply({ ok: "done" });
  }
  if (path === "/api/manifests/check") return reply({ valid: true, sha256: "bb", saved_sha256: "aa", diff: { widens: true, widening: ["reach api.example.com"], changes: ["+ reach x"] } });
  if (path.startsWith("/api/manifests/")) return reply({ root: "manifests", name: "a.yaml", yaml: "task: <b>hi</b>\n", valid: true, writable: true, history: [{ version: "1-aa.yaml", saved_before: 1, sha256_prefix: "aa" }],
    fields: [{ path: "task", value: "<b>hi</b>", default: false }, { path: "zone.isolation", value: "gvisor", default: true }],
    grants: { task: "<b>hi</b>", image: { Ok: "img" }, isolation: "Gvisor", unlisted_hosts: "escalate", reach: [], hosts: [], forbid: [], inject: [{ secret: "gh", host: "h", header: "authorization", secret_set: false, bound_to_host: true }], volumes: [], limits: {}, org_policy: null } });

  if (path === "/api/push") return reply({ public_key: "BAEC", devices: pushDevices, min_interval_secs: 30 });
  if (path === "/api/push/subscribe") return reply({ error: "registering a device is a signed action" }, false);
  if (path === "/api/push/remove") { const b = JSON.parse(opts.body); pushDevices = pushDevices.filter(d => d.id !== b.id); return reply({ ok: "device removed" }); }
  if (path === "/api/push/details") { const b = JSON.parse(opts.body); for (const d of pushDevices) if (d.id === b.id) d.details = b.details; return reply({ ok: "ok" }); }
  if (path === "/api/policy") return reply({ installed: null, current: null, versions: [], runs: [] });
  return reply({}, false);
};
let ceremonies = 0;
const sandbox = {
  document: { createElement: t => new Node(t), createTextNode: t => new Text(t), getElementById: id => ids[id], addEventListener: (k, f) => { if (k === "DOMContentLoaded") sandbox.ready = f; } },
  fetch,
  window: { PushManager: function () {}, Notification: {}, addEventListener() {} },
  Notification: { requestPermission: async () => { permAsked++; permAskedAt = calls.length; return "granted"; } },
  crypto: require("crypto").webcrypto, TextEncoder,
  navigator: { userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
    serviceWorker: { register: async (u, o) => { swRegistered = [u, o.scope]; return swReg; }, ready: Promise.resolve(swReg),
      getRegistration: async () => (swRegistered ? swReg : undefined), addEventListener: (k, f) => { if (k === "message") swListener = f; } },
    credentials: { get: async () => { ceremonies++; if (slowPasskey) await slowPasskey; return { rawId: new ArrayBuffer(1), response: { clientDataJSON: new ArrayBuffer(1), authenticatorData: new ArrayBuffer(1), signature: new ArrayBuffer(1) } }; } } },
  performance: { now: () => now },
  setTimeout: (f, ms) => { const id = ++intervalId; alive.add(id); timers.push({ f: () => { if (alive.delete(id)) f(); }, at: now + ms }); return id; },
  clearTimeout: id => { alive.delete(id); },
  setInterval: (f, ms) => { const id = ++intervalId; alive.add(id); const arm = () => timers.push({ f: () => { if (alive.has(id)) { f(); arm(); } }, at: now + ms }); arm(); return id; },
  clearInterval: id => { alive.delete(id); },
  btoa: s => Buffer.from(s, "binary").toString("base64"),
  atob: s => Buffer.from(s, "base64").toString("binary"),
  Uint8Array, ArrayBuffer, JSON, Math, String, Object, Array, Set, Map, Promise, Error,
  // The wall clock moves with the harness's timers (a fixed offset keeps it a plausible date).
  Date: Object.assign(function (...a) { return a.length ? new Date(...a) : new Date(EPOCH + now + skew); }, { now: () => EPOCH + now + skew, UTC: Date.UTC, parse: Date.parse }),
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), sandbox);
const run = expr => vm.runInContext(expr, sandbox);
const flush = () => new Promise(r => setImmediate(r));
const advance = async ms => { now += ms; const due = timers.filter(t => t.at <= now); timers = timers.filter(t => t.at > now); for (const t of due) t.f(); await flush(); };

const req = (id, risk, path) => ({ id, risk, method: "POST", host: "api.example.com", path, scope_prefix: false, reason: "r", identity: { verified: true, agent: "lead", zone: "z", acting_for: [], id: "spiffe://x" }, attribution: [], zone: "z", run: "run_a", created_at: 0 });
const A = req("q-a", "R1ReadScoped", "/harmless"), B = req("q-b", "R3ExternalOrIrreversible", "/dangerous"), X = req("q-x", "R1ReadScoped", "/other");
const base = { now: 10, tenant: "t0", runs: [], manifests: [], decided: [], audit: [], passkeys: [] };
const began = () => calls.filter(c => c.path === "/api/action/begin");

(async () => {
  state = { ...base, pending: [X, A, B] };
  sandbox.ready(); await flush(); await flush(); await flush();
  await advance(2000);
  // The cards themselves are drawn by inbox.js with lit-html (#574), which needs a real DOM: that
  // they stay put across polls, move only when the list does, and say what the server grants is
  // ci/console-browsers/inbox.mjs's. Here, their buttons' path: act(), with its settle guard.

  // Without inbox.js (here, as when the module fails to load), the cards' place says they can't be
  // shown, rather than that nothing is waiting.
  // So for the Agents view without agents.js.
  for (const id of ["pending", "runs", "start"]) assert.ok(ids[id].textContent.includes("can't be shown"), id + ": " + ids[id].textContent);

  // The cards just moved (inbox.js says so): a tap right then is ignored.
  state = { ...base, pending: [A, B] };
  await run("refresh()"); await flush();
  run("layoutMoved()");
  run("act('approve', { id: 'q-b', uses: 1, ttl_secs: 600 })"); await flush();
  assert.strictEqual(began().length, 0, "a tap just after the layout changed is ignored");

  // Once settled, a tap asks the server for the action and opens the confirmation; no passkey yet.
  await advance(1000);
  nextAction = { v: 1, action: "decide", request: "q-a", run: "run_a", method: "POST", host: "api.example.com", path: "/harmless", risk: "R1ReadScoped", prefix: false, decision: "approve", uses: 1, ttl_secs: 600, agent: "spiffe://x", requested_by: [],
    effect_sha256: "0123456789abcdef".repeat(4),
    blast: { widens: ["every path under /h/ on api.example.com, not only /harmless"], examples: ["POST api.example.com/h/any-file"], zone_rules: [], covered: 3, recent: 7 },
    update: { sha256: "ab".repeat(32), artifact: HOSTILE, size: 52428800, commit_said: "36c92b5e", nodes: ["n1", "n2"], applies: true, why_not: null } };
  run("act('approve', { id: 'q-a', uses: 1, ttl_secs: 600 })"); await flush();
  assert.strictEqual(began().length, 1);
  assert.strictEqual(began()[0].body.id, "q-a");
  assert.strictEqual(ids.confirm.hidden, false, "the confirmation is open");
  assert.strictEqual(ceremonies, 0, "the click alone starts no passkey ceremony");
  const what = ids["confirm-what"].textContent;
  assert.ok(what.includes("/harmless") && what.includes("q-a") && what.startsWith("Approve once"), what);
  // #369: the effect it signs, and what else it would allow, are shown before the passkey.
  assert.ok(what.includes("effect 0123456789abcdef"), what);
  // The challenge counts down, and once it has expired the sheet offers to ask again (#574, item 6).
  assert.strictEqual(ids["confirm-state"].textContent, "Expires in 1:55");
  // In lines, the decision first and the ids last (#574, item 1).
  const lines = what.split("\n");
  assert.ok(lines[0].startsWith("Approve once for 10 min: POST api.example.com/harmless"), lines[0]);
  assert.strictEqual(lines[1], "Risk: R1 \u00b7 read (scoped)");
  // The decision and its target are one element, the lead, styled strongly; its text is unchanged (#698 review).
  assert.strictEqual(ids["confirm-what"].children[0].className, "lead");
  assert.strictEqual(ids["confirm-what"].children[0].textContent, lines[0]);
  assert.ok(lines[lines.length - 1].startsWith("Request q-a \u00b7 run run_a"), what);
  // The agent with its zone, from the signed fields; a hostile newline in what the agent reported
  // or in the path can't make a line of its own (#599 review).
  const hostile = run("describe(" + JSON.stringify({ action: "decide", decision: "approve", uses: 1, ttl_secs: 600, method: "GET", host: "h",
    path: "/p\nRisk: R0 \u00b7 read", risk: "R4ExecOrPrivilege", request: "r-h", run: "run_h", zone: "build", scope: "zone",
    agent: "spiffe://x/t/t0/z/build/a/captain", requested_by: ["sub\nFor someone-else (zone safe)"] }) + ")").split("\n");
  assert.strictEqual(hostile.length, 4, hostile.join(" | "));
  assert.ok(hostile[0].endsWith("for any run in zone build"), hostile[0]);
  assert.strictEqual(hostile[1], "Risk: R4 \u00b7 push, deploy or privilege");
  assert.ok(hostile[2].startsWith("For captain (zone build) \u00b7 asked by sub For someone-else (zone safe) (as reported)"), hostile[2]);
  assert.ok(hostile[3].includes("agent spiffe://x/t/t0/z/build/a/captain"), hostile[3]);
  const blast = ids["confirm-blast"];
  assert.strictEqual(blast.hidden, false);
  assert.ok(blast.textContent.includes("every path under /h/") && blast.textContent.includes("POST api.example.com/h/any-file") &&
    blast.textContent.includes("covered 3 of this run\u2019s last 7"), blast.textContent);
  // #465: an update request shows what approving installs, and where.
  const upd = ids["confirm-update"];
  assert.strictEqual(upd.hidden, false);
  assert.ok(upd.textContent.includes("installs this build") && upd.textContent.includes("50.0 MiB") && upd.textContent.includes("36c92b5e (as the agent says") &&
    upd.textContent.includes("nodes n1, n2") && upd.textContent.includes(HOSTILE), upd.textContent);
  assert.ok(upd.all(n => n.tagName === "img").length === 0, "an agent-chosen name stays text");
  // Its sign button isn't live at once (a second tap aimed at the card mustn't land on it).
  assert.strictEqual(ids["confirm-go"].disabled, true);
  ids["confirm-go"].click(); await flush();
  assert.strictEqual(ceremonies, 0);

  // While it is open, another card's buttons can't start a second ceremony (that polls don't redraw
  // the cards meanwhile is inbox.mjs's).
  state = { ...base, pending: [X, B, A] };
  run("act('approve', { id: 'q-b', uses: 1, ttl_secs: 600 })"); await flush();
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

  // Cancel closes it without a ceremony.
  await advance(1000);
  nextAction = { ...nextAction, request: "q-b", decision: "deny", uses: null, ttl_secs: null, blast: null, update: null };
  run("act('deny', { id: 'q-b' })"); await flush();
  assert.strictEqual(ids.confirm.hidden, false);
  assert.ok(ids["confirm-what"].textContent.startsWith("Deny"), ids["confirm-what"].textContent);
  assert.strictEqual(ids["confirm-blast"].hidden, true, "a denial widens nothing");
  assert.strictEqual(ids["confirm-update"].hidden, true, "and installs nothing");
  // A box on another node: the artifact is fetched from its outbox there, once approved.
  await run('renderUpdate(document.getElementById("confirm-update"), { sha256: "ab".repeat(32), node: "far", applies: true, nodes: [], commit_said: null })');
  assert.ok(ids["confirm-update"].textContent.includes("on node far, fetched from there when you approve"), ids["confirm-update"].textContent);
  await run('renderUpdate(document.getElementById("confirm-update"), null)');
  ids["confirm-cancel"].listeners.click(); await flush();
  assert.strictEqual(ids.confirm.hidden, true);
  assert.strictEqual(ceremonies, 1);
  // #574 (B4, item 8): a server that can't answer for a moment is said to be so, and the page stays
  // up and goes on polling; only a 401 signs it out.
  for (const fail of [502, "network"]) {
    stateFail = fail;
    await run("refresh()"); await flush();
    assert.strictEqual(ids.console.hidden, false, "still signed in after " + fail);
    assert.ok(!ids.stale.hidden && ids.stale.textContent.startsWith("Can't reach wicket (" + (fail === 502 ? "HTTP 502" : "no answer") + ")"), ids.stale.textContent);
  }
  stateFail = null;
  await run("refresh()"); await flush();
  assert.strictEqual(ids.stale.hidden, true, "heard from again");
  // #574: the confirmation states the effect's terms, which the passkey signs: a git push is a
  // window (unlimited uses for 5 minutes, #26), whatever the card asked for.
  const push = JSON.stringify({ action: "decide", decision: "approve", uses: 1, ttl_secs: 600, method: "POST", host: "github.com",
    path: "/acme/app.git/git-receive-pack", risk: "R4ExecOrPrivilege", request: "r-p", run: "run_a",
    effect: { terms: { uses: null, ttl_secs: 300, scope: "run" } } });
  const said = run("describe(" + push + ")");
  assert.ok(said.startsWith("Approve any number of uses for 5 min: POST github.com/acme/app.git/git-receive-pack"), said);
  // A whole hour reads as one, as on the card (#574).
  assert.ok(run("describe(" + JSON.stringify({ action: "decide", decision: "approve", method: "GET", host: "h", path: "/p", effect: { terms: { uses: null, ttl_secs: 3600 } } }) + ")").startsWith("Approve any number of uses for 1 hour"));
  // Risk said as what it means, code first.
  assert.strictEqual(run("riskLabel('R4ExecOrPrivilege')"), "R4 \u00b7 push, deploy or privilege");
  assert.strictEqual(run("riskWords('R4ExecOrPrivilege')"), "Pushes code, deploys, or gains privileges");
  // A cancelled passkey is said as such, as an error that stays; a reply with no text is "Done.".
  run("toastError({ name: 'NotAllowedError', message: 'The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/' }, null, true)");
  assert.deepStrictEqual([ids.msg.textContent, ids.msg.className], ["Passkey cancelled. Nothing was signed.", "error"]);
  assert.strictEqual(ids.msg.getAttribute("role"), "alert", "an error is announced");
  // A NotAllowedError away from a passkey (a refused notification permission) is said as it is.
  run("toastError({ name: 'NotAllowedError', message: 'Permission denied' }, 'Notifications')");
  assert.strictEqual(ids.msg.textContent, "Notifications: Permission denied");
  run("toast(undefined)");
  assert.deepStrictEqual([ids.msg.textContent, ids.msg.className], ["Done.", ""]);
  assert.ok(run("describe(" + JSON.stringify({ action: "decide", decision: "approve", uses: 1, ttl_secs: 600, method: "GET", host: "h", path: "/p", effect: { terms: { uses: 1, ttl_secs: 600 } } }) + ")").startsWith("Approve once for 10 min"));
  // Left open past the challenge's two minutes: said, nothing signed, and "Ask again" begins anew.
  await advance(1000);
  nextAction = { v: 1, action: "decide", request: "q-x", run: "run_a", method: "GET", host: "h", path: "/p", risk: "R0Read", decision: "approve", uses: 1, ttl_secs: 600 };
  const expiryBegun = began().length;
  // A slow begin: "Preparing" stays up (not gone after 3 s), and nothing opens until it answers.
  let answer; slowBegin = new Promise(r => { answer = r; });
  const opening = run("signed({ action: 'decide', id: 'q-x', decision: 'approve' })"); await flush();
  await advance(4000);
  assert.deepStrictEqual([ids.msg.hidden, ids.msg.textContent], [false, "Preparing…"], "a slow begin still says so");
  assert.strictEqual(ids.confirm.hidden, true);
  // The phone's clock is three minutes fast: it doesn't matter, the time left is counted from arrival.
  skew = 180000;
  slowBegin = null; answer(); await opening; await flush();
  assert.strictEqual(ids.msg.hidden, true, "the sheet replaces it");
  // The time the server says is left (expires_in_ms), on the wall clock, five seconds early.
  assert.strictEqual(ids["confirm-state"].textContent, "Expires in 1:55", "a fast phone clock doesn't expire it at once");
  await advance(116000);
  assert.strictEqual(ids["confirm-state"].textContent, "This expired before it was signed. Nothing was signed.");
  assert.strictEqual(ids["confirm-go"].textContent, "Ask again");
  // "Ask again" begins anew inside the open sheet: it says so, and a tap while it prepares does nothing.
  slowBegin = new Promise(r => { answer = r; });
  ids["confirm-go"].click(); await flush();
  assert.strictEqual(began().length, expiryBegun + 2, "asked again");
  assert.strictEqual(ids.confirm.hidden, false, "the sheet stays open, so a second tap can't land beneath it");
  assert.strictEqual(ids["confirm-state"].textContent, "Preparing…");
  assert.strictEqual(ids["confirm-go"].disabled, true);
  const ceremoniesBefore = ceremonies;
  ids["confirm-go"].click(); await flush();
  await run("signed({ action: 'decide', id: 'q-a', decision: 'approve' })"); await flush();
  assert.strictEqual(began().length, expiryBegun + 2, "a tap while preparing begins nothing more");
  slowBegin = null; answer(); await flush(); await flush();
  assert.strictEqual(ids["confirm-state"].textContent, "Expires in 1:55");
  // The settle guard holds again after the sheet is refilled.
  assert.strictEqual(ids["confirm-go"].disabled, true);
  ids["confirm-go"].click(); await flush();
  assert.strictEqual(ceremonies, ceremoniesBefore, "no passkey from a tap just after Ask again");
  // Waiting for the passkey, the countdown stops: a slow passkey isn't said to have expired.
  await advance(1000);
  let passkeyDone; slowPasskey = new Promise(r => { passkeyDone = r; });
  ids["confirm-go"].click(); await flush();
  assert.strictEqual(ids["confirm-state"].textContent, "Waiting for your passkey…");
  await advance(200000);
  assert.strictEqual(ids["confirm-state"].textContent, "Waiting for your passkey…", "no expiry while waiting for the passkey");
  slowPasskey = null; passkeyDone(); await flush(); await flush(); await flush();
  assert.strictEqual(ids.confirm.hidden, true);
  // Cancel while "Ask again" prepares: the begin that comes back late doesn't reopen the sheet.
  await advance(1000);
  await run("signed({ action: 'decide', id: 'q-x', decision: 'approve' })"); await flush();
  await advance(116000);
  slowBegin = new Promise(r => { answer = r; });
  ids["confirm-go"].click(); await flush();
  ids["confirm-cancel"].listeners.click(); await flush();
  assert.strictEqual(ids.confirm.hidden, true);
  slowBegin = null; answer(); await flush(); await flush();
  assert.strictEqual(ids.confirm.hidden, true, "a begin for a closed sheet is dropped");
  await advance(1000);
  const afterCancel = began().length;
  await run("signed({ action: 'decide', id: 'q-x', decision: 'approve' })"); await flush();
  assert.deepStrictEqual([began().length, ids.confirm.hidden], [afterCancel + 1, false], "and the next tap opens a sheet as usual");
  ids["confirm-cancel"].listeners.click(); await flush();
  skew = 0;
  // An error that stays is gone once a sheet opens: it would sit above it.
  run("toastError({ name: 'Error', message: 'earlier' })");
  assert.strictEqual(ids.msg.hidden, false);
  await advance(1000);
  await run("signed({ action: 'decide', id: 'q-x', decision: 'approve' })"); await flush();
  assert.strictEqual(ids.msg.hidden, true, "the error toast goes when the sheet opens");
  ids["confirm-cancel"].listeners.click(); await flush();
  // Who asked (#574, item 5): a named call is labelled apart from "On behalf of"; that anything in
  // the box could use the grant is always said; with no event stream, the asker is unknown.
  const NOTE = "anything in this box could use the grant.";
  const alone = run("renderWho([{ basis: 'none', requesters: [] }])").textContent;
  assert.ok(!alone.includes("Asked by") && alone.includes(NOTE), alone);
  const who = run("renderWho([{ basis: 'exact', requesters: [{ agent: 'release-captain', tool: 'Bash', call: 'git push' }] }])").textContent;
  assert.ok(who.startsWith("Asked by (in the box): release-captain — Bash: git push") && who.includes("not proven") && who.includes(NOTE), who);
  const noStream = run("renderWho([])").textContent;
  assert.ok(noStream.startsWith("Asked by (in the box): unknown (no agent event stream)") && noStream.includes("Anything in this box could use the grant."), noStream);
  // Two askers, one with no call in flight: both are listed, the unknown one too (#601 review).
  const two = run("renderWho([{ basis: 'exact', requesters: [{ agent: 'a', tool: 'Bash', call: 'x' }] }, { basis: 'none', requesters: [] }])").textContent;
  assert.ok(two.includes("Asked by (in the box): a — Bash: x") && two.includes("Asked by (in the box): unknown — no tool call was in flight") && two.includes("more than one agent"), two);
  // The full identity is behind a real button that says whether it is shown; opening it moves the
  // card's buttons, so a tap right after is ignored.
  const card = run("(() => { const c = el('div'); renderAgent(c, { verified: true, agent: 'release-captain', zone: 'build', acting_for: ['passkey:phone'], id: 'spiffe://x/a/release-captain' }); return c; })()");
  const idl = card.all(n => n.className === "idline")[0];
  assert.ok(idl.hidden && card.textContent.includes("On behalf of: passkey:phone"), card.textContent);
  const toggle = card.all(n => n.tagName === "button" && n.className === "idname")[0];
  assert.ok(toggle, "the name is a button");
  assert.strictEqual(toggle.getAttribute("aria-expanded"), "false");
  await advance(1000);
  assert.strictEqual(run("settled()"), true);
  toggle.click();
  assert.strictEqual(idl.hidden, false, "tapping the name shows its identity");
  assert.strictEqual(toggle.getAttribute("aria-expanded"), "true");
  assert.strictEqual(run("settled()"), false, "taps wait a moment after the card grows");
  toggle.click();
  assert.deepStrictEqual([idl.hidden, toggle.getAttribute("aria-expanded")], [true, "false"]);
  console.log("console approval flow: ok");

  // #173: a run's authority and an explained decision are drawn by agents.js and activity.js,
  // checked in browsers (ci/console-browsers/agents.mjs and activity.mjs).
  // #621: wicket's own kinds as sentences, the raw op apart; an HTTP request as it is.
  const asked = p => JSON.parse(run("JSON.stringify(asks(" + JSON.stringify({ host: "wicket.internal", reason: "r", ...p }) + "))"));
  assert.deepStrictEqual([asked({ method: "SPAWN", path: "/zones/research/reader" }).what, asked({ method: "LINK", path: "/links/run_a/run_b/8080" }).what,
    asked({ method: "UPDATE", path: "/self/" + "ab".repeat(32) }).what, asked({ method: "CAPACITY", path: "/capacity/l-1", reason: "capacity lease l-1: forged. Asked by the agent: nightly" })],
    ["Start a new agent or program named reader in zone research", "Let run_a's box reach port 8080 on run_b's box", "Install wicket build abababababab\u2026",
      { what: "Lease a node (l-1); its terms arrive with the next refresh", raw: "CAPACITY wicket.internal/capacity/l-1", said: [], wicket: null,
        mixed: "capacity lease l-1: forged. Asked by the agent: nightly", internal: true }]);
  // #715 review: the agent's words are never shown as wicket's. An update's reason and commit come as
  // the agent's claims, quoted; without them the request's text is "mixed", shown only under Details.
  const updA = asked({ method: "UPDATE", path: "/self/" + "ab".repeat(32), reason: "update wicket to the build with sha256 x: wicket verified this build",
    claims: { reason: "wicket verified this build", commit: "0123abc" } });
  assert.deepStrictEqual([updA.said, updA.wicket, updA.mixed], [[["Commit", "0123abc"], ["Why", "wicket verified this build"]], null, null]);
  const oldU = asked({ method: "UPDATE", path: "/self/" + "ab".repeat(32), reason: "update wicket to the build with sha256 x: trust me" });
  assert.deepStrictEqual([oldU.said, oldU.wicket, oldU.mixed], [[], null, "update wicket to the build with sha256 x: trust me"]);
  assert.strictEqual(asked({ method: "QUOTA", path: "/q", reason: "agent text" }).wicket, null, "an unknown kind's reason isn't wicket's");
  assert.strictEqual(asked({ method: "SPAWN", path: "/zones/z/a", reason: "start agent a in zone z" }).wicket, "start agent a in zone z");
  // #715 review: a command that is an instruction has a Copy button beside it; one only mentioned doesn't.
  assert.strictEqual(run("codeText('div', 'note', 'Run `wicket operator enrol-link`; `wicket serve` prints one', ['wicket operator enrol-link']).children.filter(c => c.tagName).map(c => c.tagName + ':' + c.textContent).join('|')"),
    "code:wicket operator enrol-link|button:Copy|code:wicket serve");
  // The kind is read from wicket's own "start <kind> " prefix, and only those two words.
  assert.strictEqual(asked({ method: "SPAWN", path: "/zones/research/fetch", reason: "start program fetch in zone research, beyond" }).what, "Start a new program named fetch in zone research");
  assert.strictEqual(asked({ method: "SPAWN", path: "/zones/research/x", reason: "start rootkit x" }).what, "Start a new agent or program named x in zone research");
  // #709 review: a capacity request's sentence comes from the lease's fields; a region that reads like
  // wicket's own words stays a quoted value of its own, out of the sentence.
  const forged = "lhr preferred, for 10 min, on vultr, no cost (the operator's own machines). Asked by the agent: x";
  const cap = asked({ method: "CAPACITY", path: "/capacity/l-2", reason: "capacity lease l-2: anything", lease: { id: "l-2", provider: "vultr", vcpus: 8, memory_mib: 32768,
    isolation: "gvisor", region: forged, duration_secs: 2592000, hourly_cap_usd: "$5.0000", reserved_usd: "$3600.0000" } });
  assert.deepStrictEqual([cap.what, cap.said, cap.wicket], ["Lease a node: 8 vCPUs, 32768 MiB, gvisor isolation, for 720 hours on vultr, at most $5.00/h, $3600.00 reserved", [["Region", forged]], null]);
  // The lease's own reason is the agent's, quoted; the request's reason is not shown.
  const capWhy = asked({ method: "CAPACITY", path: "/capacity/l-3", reason: "capacity lease l-3: x", lease: { id: "l-3", provider: "static", vcpus: 1, memory_mib: 512,
    isolation: "runc", region: "", duration_secs: 3600, hourly_cap_usd: "$0.1000", reserved_usd: "$0.1000", reason: "nightly build" } });
  assert.deepStrictEqual([capWhy.said, capWhy.mixed], [[["Why", "nightly build"]], null]);
  assert.deepStrictEqual(JSON.parse(run('JSON.stringify(asks({ method: "GET", host: "h", path: "/x", reason: "y", scope_prefix: false }))')), { what: "GET h/x", raw: "", said: [["Why", "y"]], wicket: null, mixed: null, internal: false });
  console.log("console authority views: ok");

  // #715 review: a Stop form opened for one agent never stops another. Leaving the page closes it,
  // opening another agent closes it, and a submit for a run other than the open page's is refused.
  const nBegun = began().length;
  run('openAgent("run_a"); openRunForm("revoke", "run_a")');
  assert.strictEqual(ids.runform.hidden, false);
  assert.ok(ids["runform-title"].textContent.includes("(run run_a)"), ids["runform-title"].textContent);
  run('show("agents")');
  assert.strictEqual(ids.runform.hidden, true, "leaving the agent's page closes its Stop form");
  run('openAgent("run_a"); openRunForm("revoke", "run_a"); openAgent("run_b")');
  assert.strictEqual(ids.runform.hidden, true, "opening another agent closes the form");
  run('document.getElementById("runform").hidden = false; document.getElementById("runform").dataset.run = "run_a"; submitRunForm({ preventDefault() {} })');
  await flush();
  assert.strictEqual(began().length, nBegun, "a form for run_a, submitted on run_b's page, signs nothing");
  console.log("console stop form: ok");

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

  // WebCrypto's digest resolves off the microtask queue: give it real time too.
  const settle = async () => { for (let i = 0; i < 20; i++) await flush(); await new Promise(r => global.setTimeout(r, 5)); for (let i = 0; i < 20; i++) await flush(); };
  // Notifications: permission is asked only from the button's click, and first (iOS); then the
  // service worker is registered at the root, the browser subscribes with the server's key, and the
  // subscription is posted. Devices are listed as text, and can be removed.
  pushDevices = [];
  await run("renderPush()"); await flush();
  assert.strictEqual(permAsked, 0, "nothing asks for permission by itself");
  const enable = ids.push.all(n => n.tagName === "button" && n.textContent === "Enable notifications")[0];
  assert.ok(enable, ids.push.textContent);
  const callsBefore = calls.length;
  await enable.click(); await settle();
  assert.strictEqual(permAsked, 1);
  assert.strictEqual(permAskedAt, callsBefore, "permission is asked before anything else happens");
  assert.deepStrictEqual(swRegistered, ["/sw.js", "/"]);
  // Registering the device is a signed action: the confirmation says which device, and only its
  // sign button posts it.
  assert.ok(!calls.some(c => c.path === "/api/push/subscribe"), "no unsigned subscribe");
  const sp = began().filter(c => c.body.action === "push_subscribe").pop();
  assert.deepStrictEqual([sp.body.endpoint, sp.body.p256dh, sp.body.auth, sp.body.details, sp.body.label], [fakeSub.endpoint, "BPK", "AU", false, "iPhone · Safari"]);
  assert.ok(ids["confirm-what"].textContent.startsWith("Send notifications to iPhone · Safari (fcm.googleapis.com"), ids["confirm-what"].textContent);
  assert.strictEqual(pushDevices.length, 0, "nothing registered before it is signed");
  const signNow = async () => { await advance(1000); const before = ceremonies; await ids["confirm-go"].click(); await settle(); assert.strictEqual(ceremonies, before + 1, "a passkey ceremony"); };
  await signNow();
  assert.ok(ids.push.textContent.includes("iPhone · Safari (this device)"), ids.push.textContent);
  assert.strictEqual(ids.push.all(n => n.textContent === "Enable notifications").length, 0);
  // Showing the request on a device is signed; hiding it again is not.
  const box = () => ids.push.all(n => n.className === "row push-dev" && n.textContent.includes("(this device)"))[0];
  const tick = box().all(n => n.tagName === "input")[0];
  tick.checked = true; tick.onchange(); await settle();
  assert.strictEqual(began().pop().body.action, "push_details");
  assert.ok(ids["confirm-what"].textContent.startsWith("Show the agent and what it asks for"), ids["confirm-what"].textContent);
  await signNow();
  assert.strictEqual(pushDevices[0].details, true);
  assert.ok(!calls.some(c => c.path === "/api/push/details"), "details on is never posted unsigned");
  const untick = box().all(n => n.tagName === "input")[0];
  assert.strictEqual(untick.checked, true);
  untick.checked = false; untick.onchange(); await settle();
  assert.deepStrictEqual(calls.filter(c => c.path === "/api/push/details").map(c => c.body), [{ id: devId(fakeSub.endpoint), details: false }]);
  // The browser replaced the subscription (pushsubscriptionchange): the console doesn't know the new
  // one, so the page offers a signed re-registration (and the worker's message brings it up).
  const renewed = { ...fakeSub, endpoint: "https://fcm.googleapis.com/fcm/send/dev2", toJSON() { return { endpoint: this.endpoint, keys: { p256dh: "BPK2", auth: "AU2" } }; } };
  subscribed = renewed;
  swListener({ data: { resubscribe: true } }); await settle();
  const again = ids.push.all(n => n.tagName === "button" && n.textContent === "Re-register this device")[0];
  assert.ok(again, ids.push.textContent);
  await again.click(); await settle();
  const rs = began().pop().body;
  assert.deepStrictEqual([rs.action, rs.endpoint, rs.p256dh, rs.auth], ["push_subscribe", renewed.endpoint, "BPK2", "AU2"]);
  await signNow();
  assert.ok(ids.push.textContent.includes("(this device)") && !ids.push.all(n => n.textContent === "Re-register this device").length, ids.push.textContent);
  pushDevices = pushDevices.filter(d => d.id === devId(renewed.endpoint)); // the push service's 410 drops the old one
  pushDevices.push({ id: "other", label: HOSTILE, service: "web.push.apple.com", details: false, created: 1, last_success: null });
  await run("renderPush()"); await settle();
  assert.ok(ids.push.textContent.includes(HOSTILE) && ids.push.all(n => n.tagName === "img").length === 0, "a label stays text");
  const otherRow = ids.push.all(n => n.className === "row push-dev" && n.textContent.includes(HOSTILE))[0];
  await otherRow.all(n => n.tagName === "button" && n.textContent === "Remove")[0].click(); await settle();
  assert.deepStrictEqual(calls.filter(c => c.path === "/api/push/remove").map(c => c.body), [{ id: "other" }]);
  assert.ok(subscribed, "removing another device leaves this one subscribed");
  const mineRow = ids.push.all(n => n.className === "row push-dev" && n.textContent.includes("(this device)"))[0];
  await mineRow.all(n => n.tagName === "button" && n.textContent === "Remove")[0].click(); await settle();
  assert.strictEqual(subscribed, null, "removing this device unsubscribes the browser");
  // A tap on a notification while the console is open marks that request's card: inbox.mjs's.
  console.log("console notifications: ok");

  // Secrets: listed by name, kind, hosts and users; a value is typed into a password field cleared on
  // submit, begin carries only its salted sha256, and the value goes only with finish.
  const SECRET = "s3cret-VALUE-typed-in";
  const gh = { name: "gh", kind: "value", reference: null, hosts: ["api.github.com"], set_at: 1700000000,
    used_by: [{ root: "manifests", manifest: "d.yaml", zone: "docs", use: "inject", host: "api.github.com", header: "authorization", format: "Bearer {secret}", optional: false }],
    zones: ["docs"], runs: [{ run: "run_a", zone: "docs" }] };
  const login = { name: "login", kind: "reference", reference: { file: "/home/you/.claude/.credentials.json", pointer: "/a/token" }, hosts: [], set_at: 1700000000, used_by: [], zones: [], runs: [] };
  state = { ...base, pending: [], secrets: { secrets: [gh, login], missing: [{ name: "HOSTILE<b>", zones: ["z"], used_by: [] }], link_cli_only: "references are made on the host: wicket secret link NAME --file PATH" } };
  await run("refresh()"); await flush();
  const sx = ids.secrets.textContent;
  for (const want of ["gh", "sent only to api.github.com", "sent to api.github.com in its authorization header, as Bearer {secret}", "running now: run_a", "read from a file on the host", "/home/you/.claude/.credentials.json#/a/token", "needed, not set", "wicket secret link"]) assert.ok(sx.includes(want), want + " in " + sx);
  const sbtn = label => ids.secrets.all(n => n.tagName === "button" && n.textContent.startsWith(label));
  assert.strictEqual(sbtn("Replace value").length, 1, "a reference's value isn't set here");
  assert.strictEqual(sbtn("Hosts").length, 2, "a reference's hosts can be changed");
  sbtn("Replace value")[0].click(); await flush();
  assert.strictEqual(ids["secret-edit"].hidden, false);
  const input = id => ids["secret-edit-body"].all(n => n.id === id)[0];
  const vIn = input("secret-value");
  assert.strictEqual(vIn.type, "password"); assert.strictEqual(vIn.autocomplete, "off");
  vIn.value = SECRET;
  nextAction = { v: 1, action: "set_secret", name: "gh", replaces: true, hosts: ["api.github.com"], previous_hosts: ["api.github.com"], zones: ["docs"], value_sha256: "x", value_salt: "y" };
  const nBegan = began().length;
  await ids["secret-edit"].listeners.submit({ preventDefault() {} }); await flush(); await flush();
  assert.strictEqual(vIn.value, "", "no echo after submit");
  assert.strictEqual(ids["secret-edit"].hidden, true);
  assert.strictEqual(began().length, nBegan + 1);
  const sb = began()[nBegan].body;
  assert.ok(!JSON.stringify(sb).includes(SECRET) && !("value" in sb), "begin never carries the value");
  const salt = Buffer.from(sb.value_salt, "hex");
  assert.strictEqual(salt.length, 16);
  assert.strictEqual(sb.value_sha256, require("crypto").createHash("sha256").update(Buffer.concat([salt, Buffer.from(SECRET)])).digest("hex"));
  assert.ok(ids["confirm-what"].textContent.startsWith("Replace the value of secret gh") && !ids["confirm-what"].textContent.includes(SECRET));
  await advance(1000); await ids["confirm-go"].click(); await flush(); await flush();
  const sfin = calls.filter(c => c.path === "/api/action/finish").pop().body;
  assert.strictEqual(sfin.value, SECRET, "the value goes with finish");
  assert.ok(!ids.secrets.textContent.includes(SECRET));
  // Delete: a warning naming the zones and runs that use it, then the signed confirmation.
  sbtn("Delete")[0].click(); await flush();
  const warn = ids["secret-edit-body"].textContent;
  assert.ok(warn.includes("docs") && warn.includes("run_a"), warn);
  nextAction = { v: 1, action: "delete_secret", name: "gh", kind: "value", zones: ["docs"], runs: ["run_a"], hosts: [] };
  await ids["secret-edit"].listeners.submit({ preventDefault() {} }); await flush(); await flush();
  assert.strictEqual(began().pop().body.action, "delete_secret");
  assert.strictEqual(ids["confirm-go"].textContent, "Sign: delete");
  assert.ok(ids["confirm-what"].textContent.includes("running runs using it: run_a"));
  ids["confirm-cancel"].listeners.click(); await flush();
  console.log("console secrets: ok");

  // The Capacity card (#256): each live grant with what it covers, uses and leaves; Renew is a
  // signed action, Revoke only the session; the form issues one through a signed action.
  const grant = { id: "g-cap1", principal: "spiffe://x/t/t0/op/unix/" + HOSTILE, decided_by: "passkey:laptop", expires_at: 5000, created_at: 1,
    terms: { plans: ["vc2-1c-2gb"], regions: ["lhr"], hourly_usd: "$0.0500", daily_usd: "$1.0000", nodes: 2 },
    used: { nodes: 1, hourly_usd: "$0.0140", daily_usd: "$0.0200" }, left: { nodes: 1, hourly_usd: "$0.0360", daily_usd: "$0.9800" } };
  state = { ...base, pending: [], capacity: [grant] };
  await run("refresh()"); await flush();
  const capRow = ids.capacity.children[0];
  // #639: in lines, plain money, proper plurals, and the principal by its short name.
  for (const want of ["g-cap1", "Allows: 2 nodes at once of vc2-1c-2gb in lhr, up to $0.05/h and $1.00 a day", "Used today: 1 node, $0.014/h, $0.02",
    "Left today: 1 node, $0.036/h, $0.98", "Ends ", "granted by passkey:laptop"]) assert.ok(capRow.textContent.includes(want), want + " in " + capRow.textContent);
  assert.ok(capRow.textContent.startsWith(grant.principal), "a name with a slash in it is shown whole: " + capRow.textContent);
  assert.deepStrictEqual([run('principalName("spiffe://x/t/t0/op/unix/alex")'), run('principalName("spiffe://x/t/t0/z/build/a/sched")')], ["unix/alex", "sched (zone build)"]);
  // #645: one time format, relative to the server's clock, with the local time.
  assert.deepStrictEqual([run("rel(100, 100)"), run("rel(130, 100)"), run("rel(100, 400)"), run("rel(100 + 8 * 3600, 100)"), run("rel(0, 3 * 86400)")],
    ["just now", "in 30 s", "5 min ago", "in 8 h", "3 days ago"]);
  assert.match(run("at(1700000000, 1700000000 + 7200)"), /^\d\d:\d\d \(2 h ago\)$|^[A-Z][a-z]{2} \d\d:\d\d \(2 h ago\)$/);
  assert.strictEqual(run("at(0)"), "\u2014");
  assert.deepStrictEqual(["$0.0500", "$1.0000", "$0.0140", "$12.3400", "n/a"].map(v => run("money(" + JSON.stringify(v) + ")")), ["$0.05", "$1.00", "$0.014", "$12.34", "n/a"]);
  assert.strictEqual(ids.capacity.all(n => n.tagName === "img").length, 0, "a principal stays text");
  await advance(1000);
  nextAction = { v: 1, action: "capacity_renew", grant: "g-cap1", principal: grant.principal, terms: grant.terms, ttl_secs: 28800 };
  capRow.all(n => n.tagName === "button" && n.textContent === "Renew")[0].click(); await flush();
  assert.deepStrictEqual([began().pop().body.action, began().slice(-1)[0].body.id, began().slice(-1)[0].body.ttl_secs], ["capacity_renew", "g-cap1", 28800]);
  assert.ok(ids["confirm-what"].textContent.startsWith("Renew capacity grant g-cap1"), ids["confirm-what"].textContent);
  ids["confirm-cancel"].listeners.click(); await flush();
  // #640: Revoke asks in the page first; nothing is sent until its own button, and Cancel puts the row back.
  const capBtn = t => capRow.all(n => n.tagName === "button" && n.textContent === t)[0];
  capBtn("Revoke\u2026").click(); await flush();
  assert.ok(capRow.textContent.includes("Revoke capacity grant g-cap1?"), capRow.textContent);
  assert.strictEqual(calls.filter(c => c.path === "/api/capacity/revoke").length, 0, "nothing sent on the first tap");
  capBtn("Cancel").click();
  assert.ok(capBtn("Renew") && !capRow.textContent.includes("Revoke capacity grant"), "Cancel restores the row");
  await advance(1000);
  capBtn("Revoke\u2026").click(); await flush();
  await capBtn("Revoke").click(); await flush();
  assert.strictEqual(calls.filter(c => c.path === "/api/capacity/revoke").length, 0, "a tap just after the question appeared is ignored");
  await advance(1000);
  await capBtn("Revoke").click(); await flush();
  assert.deepStrictEqual(calls.filter(c => c.path === "/api/capacity/revoke").map(c => c.body), [{ id: "g-cap1" }]);
  const inputs = ids["capacity-form"].all(n => n.tagName === "input");
  assert.strictEqual(inputs.length, 7);
  ["unix/alex", "vc2-1c-2gb", "lhr", "0.05", "1", "2", "4"].forEach((v, i) => { inputs[i].value = v; });
  await advance(1000);
  nextAction = { v: 1, action: "capacity_grant", principal: "spiffe://x/t/t0/op/unix/alex", terms: grant.terms, ttl_secs: 14400 };
  ids["capacity-form"].all(n => n.tagName === "button" && n.textContent.startsWith("Grant"))[0].click(); await flush();
  const g = began().pop().body;
  assert.deepStrictEqual([g.action, g.principal, g.plans, g.regions, g.max_hourly_usd, g.max_daily_usd, g.nodes, g.ttl_secs],
    ["capacity_grant", "unix/alex", "vc2-1c-2gb", "lhr", "0.05", "1", 2, 14400]);
  assert.ok(ids["confirm-what"].textContent.startsWith("Grant spiffe://x/t/t0/op/unix/alex 2 node(s) at once"), ids["confirm-what"].textContent);
  ids["confirm-cancel"].listeners.click(); await flush();
  // #707 review: the rows' words, each kind of activity line, a past lease, a decided request.
  const T = s => run(s).textContent;
  for (const [op, want] of [
    [{ kind: "standing.revoked", body: { standing: "s-3", by: "passkey:laptop", rule: { host: "h", methods: ["GET"], paths: ["/**"] } } }, "standing reach s-3 ({ host: h, methods: [GET], paths: ['/**'] }) revoked by laptop"],
    [{ kind: "decision.refused", body: { target: "r-1", decision: "approve", by: "passkey:tablet", why: "above its risk" } }, "a decision (approve) on r-1 was refused for passkey:tablet: above its risk"],
    [{ kind: "grant.revoked", body: { grant: "g-41", by: "unix/alex" } }, "grant g-41 revoked by unix/alex"],
    [{ kind: "capacity.requested", body: { request: "r-9", principal: "spiffe://x/t/t0/op/unix/alex", ask: "1 \u00d7 vc2 in lhr", lifetime_secs: 3600 } }, "capacity asked for by unix/alex: 1 \u00d7 vc2 in lhr for 1 hour (r-9)"],
    [{ kind: "lease.requested", run: "run_s", body: { lease: "l-1", request: "r-9", spec: { plan: "vc2", region: "lhr" }, hourly_cap_usd_micros: 36000, duration_secs: 7200 } }, "lease l-1 asked for: vc2 in lhr, at most $0.036/h for 2 hours (r-9) \u00b7 run_s"],
    [{ kind: "op", run: "run_m", body: { kind: "llm", requests: 3, model: "m", status: 200, input_tokens: 12345, output_tokens: 56 } }, "m request #3 \u2192 200 \u00b7 12,345 in / 56 out tokens \u00b7 run_m"],
    [{ kind: "node.audit", body: { node: "n1", body: JSON.stringify({ kind: "box.restart" }) } }, "node n1: box.restart"],
    // #715 review: who decided is named; a parent agent isn't "you".
    [{ kind: "decision", body: { request: "r-7", decision: "approve", by: "agent:run_p" } }, "allowedr-7 by run_p (a parent agent)"],
    [{ kind: "run.fence_released", run: "run_f", body: { node: "n1", by: "passkey:laptop", signed: {}, why: "n1 was destroyed" } }, "run_f released from server n1 by laptop, signed with a passkey, though its box may still be running there: n1 was destroyed"],
    [{ kind: "run.fence_release_failed", run: "run_f", body: { node: "n1", by: "root", error: "renewed" } }, "run_f is still held: its release from server n1 couldn't be made: renewed"],
    [{ kind: "something.new", run: "run_z", body: {} }, "something.new \u00b7 run_z"],
  ]) { const l = JSON.parse(run("JSON.stringify(sentence(" + JSON.stringify({ seq: 1, ...op }) + "))")); assert.ok((l.tag + l.text).endsWith(want), want + " in " + l.tag + l.text); }
  // A decision on a run's request can be explained (activity.js draws its "why?"); others can't.
  const eg = { seq: 2, kind: "op", run: "run_a", body: { kind: "egress", outcome: "forbidden", method: "GET", host: "h", path: "/p" } };
  assert.deepStrictEqual(JSON.parse(run("JSON.stringify(sentence(" + JSON.stringify(eg) + "))")), { cat: "blocked", tag: "blocked", tone: "blocked", text: "run_a: read h/p", why: true });
  assert.strictEqual(JSON.parse(run("JSON.stringify(sentence(" + JSON.stringify({ ...eg, run: null }) + "))")).why, false);
  const lease = run('placedRow(' + JSON.stringify({ id: "uuid-1", name: "runner", past_lease: true, held_by: "run_h", lease_until: 1 }) + ')');
  assert.ok(lease.textContent.includes("still billing: run run_h holds it") && lease.all(n => n.tagName === "code")[0].textContent === "wicket node release uuid-1", lease.textContent);
  // The full principal is a tap away, not only a hover.
  const pe = run('principalEl("spiffe://x/t/t0/z/build/a/sched")');
  const peBtn = pe.all(n => n.tagName === "button")[0], peLine = pe.all(n => n.className === "idline")[0];
  assert.deepStrictEqual([peBtn.textContent, peLine.hidden, peLine.textContent], ["sched (zone build)", true, "spiffe://x/t/t0/z/build/a/sched"]);
  peBtn.click(); assert.strictEqual(peLine.hidden, false);
  // Server text's UTC times read as the rows' local times.
  assert.ok(!/T\d\d:\d\d:\d\dZ/.test(run('localTimes("disk 40%, CA until 2023-11-14T22:13:20Z")')), "localised");
  console.log("console capacity: ok");

  // Health alerts are lines under their node's row, not items squeezed into it (B7).
  state = { ...base, pending: [], health: { nodes: [{ node: "n1", summary: "ok", received_ms: 1, alerts: ["disk 91% full"] }] } };
  await run("refresh()"); await flush();
  const hrow = ids.health.children[0];
  assert.strictEqual(hrow.children[0].className, "row");
  assert.ok(hrow.children[1].textContent === "! disk 91% full" && hrow.children[1].className === "blocked", hrow.textContent);
  // The state store's sync and the audit export's progress (#635): a row each, above the nodes,
  // lagging and failing ones marked, the last error under its row.
  const nowS = 1763200000;
  state = { ...base, now: nowS, pending: [], health: { nodes: [], state_store: {
    stream: { endpoint: "https://s3.example.com", bucket: "b-1", state: "lagging", last_sync_ms: (nowS - 420) * 1000, behind_secs: 420, error: "monitor error: <b>refused</b>", error_ms: (nowS - 5) * 1000 },
    audit: [{ sink: "store", kind: "store", seq: 1180, head: 1204, behind: 24, behind_secs: 400, checkpoint_at: nowS - 900, error: "PUT: refused" },
            { sink: "collector", kind: "otlp", seq: 1204, head: 1204, behind: 0, behind_secs: 0, checkpoint_at: 0, error: null }],
    errors: ["audit-sinks.yaml: bad"] } } };
  await run("refresh()"); await flush();
  const hs = ids.health.children;
  assert.strictEqual(hs[0].children[0].textContent, "Record backup" + "https://s3.example.com (b-1) \u00b7 ledger lagging \u00b7 last sync 7 min ago");
  assert.strictEqual(hs[0].children[0].children[1].className, "blocked");
  assert.strictEqual(hs[0].children[1].textContent, "! last error 5 s ago: monitor error: <b>refused</b>", "as text, never markup");
  assert.ok(hs[1].children[0].textContent.endsWith("24 records behind (oldest 6 min) at 1180 of 1204 \u00b7 last checkpoint 15 min ago"), hs[1].textContent);
  assert.strictEqual(hs[1].children[0].children[1].className, "blocked");
  assert.strictEqual(hs[1].children[1].textContent, "! last error: PUT: refused");
  assert.strictEqual(hs[2].children[0].textContent, "Activity export to collectorcaught up at 1204 of 1204 \u00b7 last checkpoint never");
  assert.strictEqual(hs[2].children.length, 1, "no error, no line");
  assert.strictEqual(hs[3].textContent, "! audit-sinks.yaml: bad");
  assert.strictEqual(hs[4].className, "empty", "then the nodes");
  // Streaming: no mark, and an error from before the last sync isn't shown; one since is.
  const streaming = (error_ms) => ({ ...base, now: nowS, pending: [], health: { nodes: [], state_store: {
    stream: { endpoint: "https://s3.example.com", bucket: "b-1", state: "streaming", last_sync_ms: (nowS - 2) * 1000, behind_secs: 2, error: "old trouble", error_ms },
    audit: [], errors: [] } } });
  state = streaming((nowS - 600) * 1000);
  await run("refresh()"); await flush();
  assert.strictEqual(ids.health.children[0].children[0].children[1].className, "");
  assert.ok(ids.health.children[0].children[0].textContent.endsWith("ledger streaming \u00b7 last sync 2 s ago"));
  assert.strictEqual(ids.health.children[0].children.length, 1, "an error recovered from isn't shown");
  state = streaming((nowS - 1) * 1000);
  await run("refresh()"); await flush();
  assert.strictEqual(ids.health.children[0].children[1].textContent, "! last error 1 s ago: old trouble", "one after the last sync is");
  // Starting: pending, saying how long it has had no sync.
  state = { ...base, now: nowS, pending: [], health: { nodes: [], state_store: {
    stream: { endpoint: "https://s3.example.com", bucket: "b-1", state: "starting", last_sync_ms: null, behind_secs: 12, error: null, error_ms: null }, audit: [], errors: [] } } };
  await run("refresh()"); await flush();
  assert.strictEqual(ids.health.children[0].children[0].children[1].className, "pend");
  assert.ok(ids.health.children[0].children[0].textContent.endsWith("ledger starting \u00b7 no sync yet in 12 s"));
  // Sinks only (no state store): a row per sink and no state store row; a manual sink behind isn't marked.
  state = { ...base, now: nowS, pending: [], health: { nodes: [], state_store: { stream: null, errors: [],
    audit: [{ sink: "stdout", kind: "jsonl", seq: 3, head: 9, behind: 6, behind_secs: 4000, checkpoint_at: 0, error: null, manual: true }] } } };
  await run("refresh()"); await flush();
  assert.strictEqual(ids.health.children.length, 2, "the sink's row, then the nodes");
  assert.ok(ids.health.children[0].children[0].textContent.startsWith("Activity export to stdout6 records behind (oldest 66 min) (manual: fed only by wicket audit export)"), ids.health.children[0].textContent);
  assert.strictEqual(ids.health.children[0].children[0].children[1].className, "");
  // The rows' alerts come first, then a stale read says so, then the rows.
  state = { ...base, now: nowS, pending: [], health: { nodes: [], state_store: { stream: null, errors: [], stale: true, read_ms: (nowS - 400) * 1000,
    alerts: ["audit sink store: 24 records behind (oldest 6 min)"],
    audit: [{ sink: "store", kind: "store", seq: 1, head: 25, behind: 24, behind_secs: 400, checkpoint_at: 0, error: null, manual: false }] } } };
  await run("refresh()"); await flush();
  assert.strictEqual(ids.health.children[0].textContent, "! audit sink store: 24 records behind (oldest 6 min)");
  assert.strictEqual(ids.health.children[0].className, "blocked");
  assert.strictEqual(ids.health.children[1].textContent, "! not checked for 6 min: these rows may be out of date");
  assert.ok(ids.health.children[2].textContent.startsWith("Activity export to store24 records behind"));
  // An error the config alert already quotes is said once; a first read that is overdue says so.
  state = { ...base, now: nowS, pending: [], health: { nodes: [], state_store: { stream: null, audit: [], stale: true, read_ms: null, not_read_yet: true,
    errors: ["audit-sinks.yaml can't be read: x"], alerts: ["audit-sinks.yaml can't be read: x (for 5 min)"] } } };
  await run("refresh()"); await flush();
  assert.deepStrictEqual(ids.health.children.map(c => c.textContent),
    ["! audit-sinks.yaml can't be read: x (for 5 min)", "! not read yet: the console hasn't managed a first read of the state store", "No node has reported its health yet."]);
  // One poll at a time (B9): a second asked for while one is in flight runs after it, not beside it.
  let inFlight = 0, most = 0;
  const realFetch = sandbox.fetch;
  sandbox.fetch = async (p, o) => { inFlight++; most = Math.max(most, inFlight); try { await flush(); return await realFetch(p, o); } finally { inFlight--; } };
  const polled = calls.filter(c => c.path === "/api/state").length;
  await Promise.all([run("refresh()"), run("refresh()")]); for (let i = 0; i < 10; i++) await flush();
  assert.strictEqual(calls.filter(c => c.path === "/api/state").length - polled, 2, "the second ran after the first");
  assert.strictEqual(most, 1, "never two at once");
  // A decision made while a poll is in flight drops that poll's (older) answer, and polls again.
  const before2 = calls.filter(c => c.path === "/api/state").length;
  run("refresh()"); run("closeConfirm()"); for (let i = 0; i < 10; i++) await flush();
  assert.strictEqual(calls.filter(c => c.path === "/api/state").length - before2, 2, "polled again after the decision");
  sandbox.fetch = realFetch;
  console.log("console health and polling: ok");
  // Standing reach (#572): an ask shows its evidence and what it allows beyond it; approving it
  // narrowed is signed from a confirmation that names the narrowed rule; a rule is revoked with
  // the session only.
  const ask = { id: "s-1", principal: "spiffe://x/t/t0/z/work/a/worker", zone: "work", run: "run_w", reason: "CI <b>logs</b>",
    rule: { host: "ci.example", methods: ["GET", "POST"], paths: ["/jobs/**"], allow_dangerous: false },
    zone_digest: "0123456789abcdef0123",
    evidence: { requests: 3, granted: 2, denied: 1, undecided: 0, runs: 2, days: 1, own_asks: 4, ops: [{ method: "GET", path: "/jobs/1/logs", count: 2, granted: 2 }] },
    beyond: ["methods never asked for: POST"],
    narrowed: { host: "ci.example", methods: ["GET"], paths: ["/jobs/1/logs"], allow_dangerous: false }, created_at: 1700000000 };
  const rule = { id: "s-2", principal: ask.principal, zone: "work", rule: ask.narrowed, for: "agent", expires_at: null, live: true, decided_by: "passkey:laptop" };
  state = { ...base, pending: [], standing: { asks: [ask], rules: [rule] } };
  await run("refresh()"); await flush();
  const sa = ids["standing-asks"].textContent;
  // #715 review: the pill names the rule's methods; whether a POST changes data isn't guessed.
  assert.ok(!sa.includes("Changes data") && !sa.includes("Only reads"), sa);
  for (const want of ["always be allowed to read and send data to", "ci.example/jobs/**", "Methods: GET, POST", "Paths: /jobs/**", "Asked by worker (zone work)", "with this zone definition (0123456789ab", "2 granted of 3 blocked request(s) it covers in the last 14 days", "in 2 run(s) on 1 day(s)",
    "2 \u00d7 GET /jobs/1/logs (2 granted)", "and 4 ask(s) ahead of its own, not counted as evidence",
    "Wider than what it used: methods never asked for: POST", "Only what it used: methods GET, paths /jobs/1/logs"]) assert.ok(sa.includes(want), want + " in " + sa);
  assert.deepStrictEqual([ids["standing-pointer"].textContent, ids["standing-pointer"].hidden], ["Asking to be always allowed (1)", false]);
  // #650: what waits, counted where a background tab or an installed app shows it.
  assert.strictEqual(sandbox.document.title, "(1) wicket");
  const sbuttons = ids["standing-asks"].all(n => n.tagName === "button");
  assert.deepStrictEqual(sbuttons.map(n => [n.textContent, n.className]), [["Always: only what it used", "approve"], ["Always: as asked", ""],
    ["Always, for every agent in zone work", "deny"], ["Don't allow", "deny apart"]], "the narrowest first and primary; the widest marked");
  assert.strictEqual(ids["standing-asks"].all(n => n.tagName === "b").length, 0, "an agent's reason stays text");
  await advance(1000);
  nextAction = { v: 1, action: "standing_approve", standing: "s-1", principal: ask.principal, zone: "work", rule: ask.narrowed, for: "agent", ttl_secs: 2592000, narrowed: true, effect_sha256: "ab".repeat(32) };
  ids["standing-asks"].all(n => n.tagName === "button" && n.textContent === "Always: only what it used")[0].click(); await flush();
  const stb = began().pop().body;
  assert.deepStrictEqual([stb.action, stb.id, stb.for, stb.narrow], ["standing_approve", "s-1", "agent", true]);
  assert.ok(ids["confirm-what"].textContent.startsWith("Approve standing reach s-1 narrowed to its evidence: { host: ci.example, methods: [GET], paths: ['/jobs/1/logs'] }"), ids["confirm-what"].textContent);
  assert.ok(ids["confirm-what"].textContent.includes("for 30 days"), ids["confirm-what"].textContent);
  ids["confirm-cancel"].listeners.click(); await flush();
  // A poll with the same state keeps the same rows (a tap mid-poll lands where it was aimed).
  const askNode = ids["standing-asks"].children[0];
  await run("refresh()"); await flush();
  assert.strictEqual(ids["standing-asks"].children[0], askNode, "rebuilt on an unchanged poll");
  // A denial is signed as one.
  await advance(1000);
  nextAction = { v: 1, action: "standing_deny", standing: "s-1", rule: ask.rule };
  ids["standing-asks"].all(n => n.tagName === "button" && n.textContent === "Don't allow")[0].click(); await flush();
  assert.ok(ids["confirm-what"].textContent.startsWith("Deny standing reach s-1"), ids["confirm-what"].textContent);
  assert.deepStrictEqual([ids["confirm-go"].className, ids["confirm-go"].textContent], ["deny", "Sign: deny"]);
  ids["confirm-cancel"].listeners.click(); await flush();
  await advance(1000);
  const sr = ids["standing-rules"];
  assert.ok(sr.textContent.includes("until revoked") && sr.textContent.includes("by passkey:laptop"), sr.textContent);
  sr.all(n => n.tagName === "button" && n.textContent === "Revoke\u2026")[0].click(); await flush();
  assert.ok(sr.textContent.includes("Runs it allows lose it at once."), sr.textContent);
  await advance(1000);
  await sr.all(n => n.tagName === "button" && n.textContent === "Revoke")[0].click(); await flush();
  assert.deepStrictEqual(calls.filter(c => c.path === "/api/standing/revoke").map(c => c.body), [{ id: "s-2" }]);
  // #715 review: a rule that allows dangerous requests says so on its row.
  assert.ok(!sr.textContent.includes("can't be undone"), sr.textContent);
  const dangerRow = run("standingRuleRow(" + JSON.stringify({ ...rule, rule: { ...rule.rule, allow_dangerous: true } }) + ")");
  assert.ok(dangerRow.textContent.includes("including requests that can't be undone"), dangerRow.textContent);
  console.log("console standing reach: ok");
  // Fenced runs (#690): a run whose box may still be running on a node that won't confirm is listed
  // with its node and why; Release… opens a reason form in its own row, kept across a poll, and the
  // release is signed from a confirmation that says what it does, marked as dangerous.
  const fenced = { id: "run_f", fence: { run: "run_f", node: "n1", node_status: "revoked", node_seen_ms: null, fenced_until_ms: null,
    source: "unknown", why: "node n1 is <b>revoked</b> and won't confirm it", effect_sha256: "cd".repeat(32) } };
  state = { ...base, pending: [], fenced: [fenced] };
  await run("refresh()"); await flush();
  const fr = ids.fenced.textContent;
  for (const want of ["run_f", "fenced until its node confirms the box stopped", "node n1 (revoked) \u00b7 never reported", "node n1 is <b>revoked</b>"]) assert.ok(fr.includes(want), want + " in " + fr);
  assert.strictEqual(ids.fenced.all(n => n.tagName === "b").length, 0, "the reason stays text");
  await advance(1000);
  ids.fenced.all(n => n.tagName === "button" && n.textContent === "Release\u2026")[0].click(); await flush();
  const area = ids.fenced.all(n => n.tagName === "textarea")[0];
  assert.ok(!area.parent.hidden && area.value === "", "the form opens empty: a reason is typed, not offered");
  area.value = "n1 was destroyed";
  // A poll that changes nothing keeps the row, and what was typed.
  await run("refresh()"); await flush();
  assert.strictEqual(ids.fenced.all(n => n.tagName === "textarea")[0], area, "kept across a poll");
  nextAction = { v: 1, action: "release_fence", run: "run_f", node: "n1", node_status: "revoked", fenced_until_ms: null, why: fenced.fence.why, reason: "n1 was destroyed", effect_sha256: "cd".repeat(32) };
  ids.fenced.all(n => n.tagName === "button" && n.textContent === "Release")[0].click(); await flush();
  assert.deepStrictEqual((({ action, run, reason }) => [action, run, reason])(began().pop().body), ["release_fence", "run_f", "n1 was destroyed"]);
  const fw = ids["confirm-what"].textContent;
  assert.ok(fw.startsWith("Release run run_f's fence on node n1 (revoked, never reported), fenced until its node confirms the box stopped") && fw.includes("reason: n1 was destroyed") && fw.includes("effect cdcdcdcd"), fw);
  assert.deepStrictEqual([ids["confirm-go"].className, ids["confirm-go"].textContent], ["deny", "Sign: release"]);
  ids["confirm-cancel"].listeners.click(); await flush();
  state = { ...base, pending: [], fenced: [] };
  await run("refresh()"); await flush();
  assert.ok(ids.fenced.textContent.startsWith("None: no agent's box is held"), ids.fenced.textContent);
  console.log("console fenced runs: ok");

  // #711: Add a device signs an enrol_link; the sheet says who the device is enrolled as, and the
  // link the server returns is shown once in the passkeys card.
  state = { ...base, pending: [], passkeys: [{ id: "cred-1", name: "laptop" }] };
  await run("refresh()"); await flush();
  await advance(1000);
  assert.ok(!ids.operator.textContent.includes("run `wicket operator enrol-link` on the host and open"), ids.operator.textContent);
  nextAction = { v: 1, action: "enrol_link", tenant: "t0", credential: "cred-1", name: "laptop", enrols_as: "passkey/laptop", ttl_secs: 300, uses: 1 };
  ids.operator.all(n => n.tagName === "button" && n.textContent === "Add a device")[0].click(); await flush();
  assert.strictEqual(began().pop().body.action, "enrol_link");
  const ew = ids["confirm-what"].textContent;
  assert.ok(ew.startsWith("Make a one-time link that enrols another device as laptop (passkey/laptop, the same operator and authority)") && ew.includes("for 5 minutes"), ew);
  run("showEnrolLink({ link: 'https://c.example/enrol?t=abc', expires_in_secs: 300 })");
  ids["confirm-cancel"].listeners.click(); await flush();
  await run("refresh()"); await flush();
  assert.ok(ids.operator.textContent.includes("https://c.example/enrol?t=abc"), ids.operator.textContent);
  // Signing out forgets the link: whoever signs in next on this tab doesn't see it.
  ids.operator.all(n => n.tagName === "button" && n.textContent === "Sign out")[0].click(); await flush();
  assert.strictEqual(run("enrolLink"), null);
  await run("refresh()"); await flush();
  assert.ok(!ids.operator.textContent.includes("https://c.example/enrol?t=abc"), ids.operator.textContent);
  // boot() forgets it too, however it is reached.
  run("showEnrolLink({ link: 'https://c.example/enrol?t=def', expires_in_secs: 300 })");
  await run("boot()"); await flush();
  assert.strictEqual(run("enrolLink"), null);
  assert.ok(!ids.operator.textContent.includes("t=def"), ids.operator.textContent);
  console.log("console enrol a device: ok");

  // The service worker: a replaced subscription is subscribed again with the same key, any open
  // console is told, and one notification says so; tapping it opens the console's notifications.
  const sw = { listeners: {}, shown: [], posted: [], opened: [], subscribedWith: null, wins: [] };
  const swSelf = {
    location: { origin: "https://console.example" },
    addEventListener: (k, f) => { sw.listeners[k] = f; },
    skipWaiting() {},
    clients: { claim: async () => {}, matchAll: async () => sw.wins, openWindow: async u => { sw.opened.push(u); } },
    registration: { showNotification: async (t, o) => { sw.shown.push(o); }, pushManager: { subscribe: async o => { sw.subscribedWith = o; return {}; } } },
  };
  const swCtx = { self: swSelf, URL, JSON, Promise };
  vm.createContext(swCtx);
  vm.runInContext(fs.readFileSync(require("path").join(require("path").dirname(process.argv[2]), "sw.js"), "utf8"), swCtx);
  const fire = async (k, e) => { let p; sw.listeners[k]({ ...e, waitUntil: x => { p = x; } }); await p; };
  const key = new Uint8Array([4, 1, 2]).buffer;
  sw.wins = [{ url: "https://console.example/", postMessage: m => sw.posted.push(m), focus: async () => {} }, { url: "https://evil.example/", postMessage: () => assert.fail("another origin is told nothing") }];
  await fire("pushsubscriptionchange", { oldSubscription: { options: { applicationServerKey: key } }, newSubscription: null });
  assert.deepStrictEqual([sw.subscribedWith.userVisibleOnly, sw.subscribedWith.applicationServerKey], [true, key]);
  assert.strictEqual(JSON.stringify(sw.posted), JSON.stringify([{ resubscribe: true }]));
  assert.strictEqual(sw.shown.length, 1);
  assert.ok(sw.shown[0].body.includes("open the console") && sw.shown[0].data.resubscribe === true && sw.shown[0].tag !== "wicket-pending", JSON.stringify(sw.shown[0]));
  // The browser already made the new one, or there was none: nothing is subscribed, it still says so.
  sw.subscribedWith = null;
  await fire("pushsubscriptionchange", { oldSubscription: null, newSubscription: {} });
  assert.strictEqual(sw.subscribedWith, null);
  assert.strictEqual(sw.shown.length, 2);
  sw.wins = [];
  await fire("notificationclick", { notification: { close() {}, data: { resubscribe: true } } });
  assert.deepStrictEqual(sw.opened, ["https://console.example/#notifications"]);
  await fire("notificationclick", { notification: { close() {}, data: { id: "q-b" } } });
  assert.deepStrictEqual(sw.opened[1], "https://console.example/#pending/q-b");
  // A node-health notification opens the health section, in a new window or an open one (B5).
  await fire("notificationclick", { notification: { close() {}, data: { health: true } } });
  assert.deepStrictEqual(sw.opened[2], "https://console.example/#health");
  sw.posted = [];
  sw.wins = [{ url: "https://console.example/", postMessage: m => sw.posted.push(m), focus: async () => {} }];
  await fire("notificationclick", { notification: { close() {}, data: { health: true } } });
  assert.strictEqual(JSON.stringify(sw.posted), JSON.stringify([{ health: true }]));
  console.log("console service worker: ok");
})().catch(e => { console.error(e); process.exit(1); });

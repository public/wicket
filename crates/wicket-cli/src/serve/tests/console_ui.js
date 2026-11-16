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
for (const id of ["msg", "auth", "console", "tenant", "pending", "runs", "runform", "runform-title", "runform-text", "runform-go", "runform-cancel", "start", "decided", "audit", "operator", "confirm", "confirm-title", "confirm-what", "confirm-state", "confirm-go", "confirm-cancel", "detail", "detail-title", "detail-body", "detail-close", "policy", "manifests", "mfedit", "mfedit-title", "mfedit-body", "mfedit-close", "push", "placed", "capacity", "capacity-form", "secrets", "secret-edit", "secret-edit-title", "secret-edit-body", "secret-edit-go", "secret-edit-cancel"]) ids[id] = new Node("div");
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
let nextAction = null, begun = null;
// Web Push: a fake browser (permission, service worker, push manager) and server (devices).
let permAsked = 0, permAskedAt = -1, swRegistered = null, swListener = null, subscribed = null, pushDevices = [];
const fakeSub = { endpoint: "https://fcm.googleapis.com/fcm/send/dev1", options: { applicationServerKey: null },
  toJSON() { return { endpoint: this.endpoint, keys: { p256dh: "BPK", auth: "AU" } }; }, unsubscribe: async () => { subscribed = null; return true; } };
const swReg = { pushManager: { getSubscription: async () => subscribed,
  subscribe: async o => { assert.strictEqual(o.userVisibleOnly, true); assert.deepStrictEqual(Array.from(o.applicationServerKey), [4, 1, 2]); fakeSub.options.applicationServerKey = o.applicationServerKey.buffer; subscribed = fakeSub; return fakeSub; } } };
const devId = ep => require("crypto").createHash("sha256").update(ep).digest("hex").slice(0, 16);
const reply = (body, ok = true) => ({ ok, status: ok ? 200 : 400, json: async () => body });
const fetch = async (path, opts) => {
  calls.push({ path, body: opts && opts.body ? JSON.parse(opts.body) : null });
  if (path === "/api/me") return reply({ who: { state: "operator" } });
  if (path === "/api/state") return reply(state);
  if (path === "/api/action/begin") {
    const b = JSON.parse(opts.body);
    // Push actions: the server's signed JSON, as the fake server sees the device.
    const a = b.action === "push_subscribe" ? { v: 1, action: b.action, device: devId(b.endpoint), label: b.label, service: "fcm.googleapis.com", details: b.details, replaces: false }
      : b.action === "push_details" ? { v: 1, action: b.action, device: b.id, label: "laptop", service: "fcm.googleapis.com", details: true } : nextAction;
    begun = { body: b, action: a };
    return reply({ action: a, publicKey: { challenge: "Y2g", rpId: "localhost", allowCredentials: [] } });
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
  if (path.endsWith("/authority")) return reply(authority);
  if (path.startsWith("/api/explain/")) return reply(explained);
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
    credentials: { get: async () => { ceremonies++; return { rawId: new ArrayBuffer(1), response: { clientDataJSON: new ArrayBuffer(1), authenticatorData: new ArrayBuffer(1), signature: new ArrayBuffer(1) } }; } } },
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
  // A tap on a notification while the console is open marks that request's card.
  state = { ...base, pending: [A, B] };
  await run("refresh()"); await flush();
  swListener({ data: { open: "q-b" } });
  assert.deepStrictEqual(cardsIn().map(c => c.className), ["card req", "card req opened"]);
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
  for (const want of ["gh", "sent only to api.github.com", "header authorization", "format Bearer {secret}", "running now: run_a", "reference", "/home/you/.claude/.credentials.json#/a/token", "not set", "wicket secret link"]) assert.ok(sx.includes(want), want + " in " + sx);
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
  assert.ok(capRow.textContent.includes("g-cap1") && capRow.textContent.includes("left 1 node(s)") && capRow.textContent.includes("vc2-1c-2gb in lhr"), capRow.textContent);
  assert.strictEqual(ids.capacity.all(n => n.tagName === "img").length, 0, "a principal stays text");
  await advance(1000);
  nextAction = { v: 1, action: "capacity_renew", grant: "g-cap1", principal: grant.principal, terms: grant.terms, ttl_secs: 28800 };
  capRow.all(n => n.tagName === "button" && n.textContent === "Renew")[0].click(); await flush();
  assert.deepStrictEqual([began().pop().body.action, began().slice(-1)[0].body.id, began().slice(-1)[0].body.ttl_secs], ["capacity_renew", "g-cap1", 28800]);
  assert.ok(ids["confirm-what"].textContent.startsWith("Renew capacity grant g-cap1"), ids["confirm-what"].textContent);
  ids["confirm-cancel"].listeners.click(); await flush();
  await capRow.all(n => n.tagName === "button" && n.textContent === "Revoke")[0].click(); await flush();
  assert.deepStrictEqual(calls.filter(c => c.path === "/api/capacity/revoke").map(c => c.body), [{ id: "g-cap1" }]);
  const inputs = ids["capacity-form"].all(n => n.tagName === "input");
  assert.strictEqual(inputs.length, 7);
  ["unix/alex", "vc2-1c-2gb", "lhr", "0.05", "1", "2", "4"].forEach((v, i) => { inputs[i].value = v; });
  await advance(1000);
  nextAction = { v: 1, action: "capacity_grant", principal: "spiffe://x/t/t0/op/unix/alex", terms: grant.terms, ttl_secs: 14400 };
  ids["capacity-form"].all(n => n.tagName === "button")[0].click(); await flush();
  const g = began().pop().body;
  assert.deepStrictEqual([g.action, g.principal, g.plans, g.regions, g.max_hourly_usd, g.max_daily_usd, g.nodes, g.ttl_secs],
    ["capacity_grant", "unix/alex", "vc2-1c-2gb", "lhr", "0.05", "1", 2, 14400]);
  assert.ok(ids["confirm-what"].textContent.startsWith("Grant spiffe://x/t/t0/op/unix/alex 2 node(s) at once"), ids["confirm-what"].textContent);
  ids["confirm-cancel"].listeners.click(); await flush();
  console.log("console capacity: ok");

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
  console.log("console service worker: ok");
})().catch(e => { console.error(e); process.exit(1); });

// The Inbox's request cards in a real browser (#574): drawn by inbox.js with lit-html, so these checks
// moved here from the fake DOM of console_ui.js. The API is answered inside the page (page.route),
// with the state each step sets, and the passkey is a stub that counts its ceremonies.
//
//   node inbox.mjs URL [chromium] [firefox] [webkit]      (ci/console-browsers.sh runs it)
//
// What it holds the page to: an unchanged card is the same element across polls; a tap just after the
// cards moved does nothing; a card's button asks the server for the action and opens the sheet, with
// no passkey ceremony; while the sheet is open the cards don't move; each card offers only what the
// server grants, says how far a grant reaches on the card itself, and keeps an agent's strings as
// text; a request opened from a notification is outlined; taps wait after the first draw and after a
// card changes in place, as after the cards move; and without inbox.js the page says the requests
// can't be shown.
import assert from "node:assert";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const pw = require("playwright");

const [url, ...wanted] = process.argv.slice(2);
if (!url) { console.error("usage: node inbox.mjs URL [chromium] [firefox] [webkit]"); process.exit(2); }
const engines = wanted.length ? wanted : ["chromium", "firefox", "webkit"];

const HOSTILE = "/x<img src=x onerror=alert(1)>";
const req = (id, risk, path, extra) => ({ id, risk, method: "POST", host: "api.example.com", path, scope_prefix: false, reason: "r",
  identity: { verified: true, agent: "lead", zone: "z", acting_for: [], id: "spiffe://x/t/t0/z/z/a/lead" }, attribution: [], zone: "z", run: "run_a",
  created_at: 0, once_terms: { uses: 1, ttl_secs: 600 }, ...extra });
const A = req("q-a", "R1ReadScoped", "/harmless"), B = req("q-b", "R3ExternalOrIrreversible", "/dangerous"), X = req("q-x", "R1ReadScoped", "/other");
const base = { now: 10, tenant: "t0", runs: [], manifests: [], decided: [], audit: [], passkeys: [], health: { nodes: [] } };

async function check(engine) {
  const browser = await pw[engine].launch();
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  const problems = [];
  page.on("pageerror", e => problems.push("error: " + (e.stack || e.message).split("\n").slice(0, 3).join(" ")));
  page.on("console", m => { if (m.type() === "error") problems.push("console: " + m.text()); });
  let state = { ...base, pending: [X, A, B] };
  const begun = [], finished = [];
  await page.route("**/api/**", async route => {
    const r = route.request(), p = new URL(r.url()).pathname;
    const body = r.postData() ? JSON.parse(r.postData()) : null;
    const reply = (v, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(v) });
    if (p === "/api/me") return reply({ who: { state: "operator", credential: "AbCd" } });
    if (p === "/api/state") return reply(state);
    if (p === "/api/action/begin") {
      begun.push(body);
      return reply({ action: { v: 1, action: "decide", request: body.id, run: "run_a", method: "POST", host: "api.example.com", path: "/p", risk: "R1ReadScoped",
        decision: body.decision, uses: 1, ttl_secs: 600, agent: "spiffe://x", requested_by: [] }, publicKey: { challenge: "Y2g", rpId: "localhost", allowCredentials: [] }, expires_in_ms: 120000 });
    }
    if (p === "/api/action/finish") { finished.push(body); return reply({ ok: "done" }); }
    if (p === "/api/push") return reply({ public_key: "BAEC", devices: [], min_interval_secs: 30 });
    return reply({});
  });
  await page.addInitScript(() => {
    window.__ceremonies = 0;
    const buf = () => new Uint8Array([1]).buffer;
    Object.defineProperty(navigator, "credentials", { value: { get: async () => { window.__ceremonies++; return { rawId: buf(), response: { clientDataJSON: buf(), authenticatorData: buf(), signature: buf() } }; } } });
  });
  const ids = () => page.$$eval("#pending .req", cs => cs.map(c => c.dataset.id));
  const mark = id => page.evaluate(i => { document.querySelector(`#pending .req[data-id="${i}"]`).__mark = i; }, id);
  const marked = id => page.evaluate(i => { const c = document.querySelector(`#pending .req[data-id="${i}"]`); return !!c && c.__mark === i; }, id);
  // One whole poll that starts after the state was set: if the page's own (every 2 s) is in flight,
  // after it ends.
  const poll = () => page.evaluate(async () => { while (polling) await new Promise(r => setTimeout(r, 20)); await refresh(); });
  // That a tap sent nothing: a request it sent would have arrived by now.
  const sentNothing = async (n, why) => { await page.waitForTimeout(400); assert.strictEqual(begun.length, n, why); };
  const cardButton = (id, label) => page.locator(`#pending .req[data-id="${id}"] button`, { hasText: label }).first();
  try {
    await page.goto(url);
    await page.waitForSelector("#pending .req");
    assert.deepStrictEqual(await ids(), ["q-x", "q-a", "q-b"]);
    // The cards were just drawn: a tap right then is ignored.
    await cardButton("q-a", "Allow once").click();
    await sentNothing(0, "a tap just after the first draw is ignored");
    // An unchanged card is the same element after a poll (its buttons don't get replaced under a tap).
    await mark("q-a");
    await poll();
    assert.ok(await marked("q-a"), "an unchanged card is kept across a poll");

    // The card above A goes: B's button is where A's was. A tap right then is ignored.
    state = { ...base, pending: [A, B] };
    await poll();
    assert.deepStrictEqual(await ids(), ["q-a", "q-b"]);
    assert.ok(await marked("q-a"), "A is the same element after the cards moved");
    await cardButton("q-b", "Allow once").click();
    await sentNothing(0, "a tap just after the layout changed is ignored");

    // A card that changes in place, under the same id, can grow or change its buttons (an agent
    // confirmed: Don't allow alone becomes Allow once, Allow for 1 hour, Don't allow): taps wait then
    // too, though no card came, went or moved.
    await page.waitForTimeout(900);
    state = { ...base, pending: [A, { ...B, risk: "R1ReadScoped", identity: { verified: false, error: "token signature invalid" } }] };
    await poll();
    await page.waitForTimeout(900);
    state = { ...base, pending: [A, { ...B, risk: "R1ReadScoped" }] };
    await poll();
    assert.deepStrictEqual(await ids(), ["q-a", "q-b"]);
    await cardButton("q-b", "Allow once").click();
    await sentNothing(0, "a tap just after a card changed in place is ignored");
    state = { ...base, pending: [A, B] };
    await poll();

    // Once settled, a tap asks the server for the action and opens the sheet; no passkey yet.
    await page.waitForTimeout(900);
    await cardButton("q-a", "Allow once (expires in 10 min)").click();
    await page.waitForSelector("#confirm:not([hidden])");
    assert.deepStrictEqual(begun.map(b => [b.id, b.decision, b.uses, b.ttl_secs]), [["q-a", "approve", 1, 600]]);
    assert.strictEqual(await page.evaluate(() => window.__ceremonies), 0, "the card's tap alone starts no passkey ceremony");

    // While it is open, polls don't move the cards, even if the agent reshuffles them; and another
    // card's buttons start nothing.
    state = { ...base, pending: [X, B, A] };
    await poll();
    assert.deepStrictEqual(await ids(), ["q-a", "q-b"], "no redraw while the sheet is open");
    await cardButton("q-b", "Allow once").click({ force: true }).catch(() => {});
    await sentNothing(1, "another card can't open a second sheet");

    // The sheet's own button signs; then the page draws the cards as they are now, A still kept.
    await page.waitForTimeout(900);
    await page.click("#confirm-go");
    await page.waitForSelector("#confirm", { state: "hidden" });
    assert.strictEqual(await page.evaluate(() => window.__ceremonies), 1);
    assert.strictEqual(finished.length, 1);
    await poll();
    assert.deepStrictEqual(await ids(), ["q-x", "q-b", "q-a"]);
    assert.ok(await marked("q-a"), "A is kept through the decision");

    // Each card offers only what the server grants. A push is one window: its first button says so,
    // with no hour button, and Details says why; so for a push to another host, at R2.
    const push = req("q-push", "R4ExecOrPrivilege", "/acme/app.git/git-receive-pack", { host: "github.com", once_terms: { uses: null, ttl_secs: 300 } });
    const push2 = { ...push, id: "q-push2", risk: "R2WriteReversible", host: "git.example" };
    // An agent's strings stay text; an unconfirmed agent is offered only Don't allow.
    const hostile = req("q-h", "R2WriteReversible", HOSTILE, { reason: "<b>bold</b>" });
    const unverified = req("q-u", "R1ReadScoped", "/u", { identity: { verified: false, error: "token signature invalid" } });
    // How far a grant reaches is on the card, not only under Details (#709 review).
    const shared = req("q-s", "R1ReadScoped", "/s", { attribution: [{ basis: "exact", requesters: [{ agent: "a", tool: "Bash", call: "curl" }] }, { basis: "none", requesters: [] }] });
    state = { ...base, pending: [push, push2, hostile, unverified, shared] };
    await poll();
    const text = id => page.locator(`#pending .req[data-id="${id}"]`).innerText();
    const labels = id => page.$$eval(`#pending .req[data-id="${id}"] .ladder button`, bs => bs.map(b => b.textContent + (b.disabled ? " (disabled)" : "")));
    assert.deepStrictEqual(await labels("q-push"), ["Allow for 5 min (any number of uses)", "Don't allow"]);
    assert.deepStrictEqual(await labels("q-push2"), ["Allow for 5 min (any number of uses)", "Don't allow"]);
    assert.ok((await page.locator('#pending .req[data-id="q-push"] details').textContent()).includes("allowed as one window"));
    assert.strictEqual(await page.locator("#pending img, #pending b").count(), 0, "an agent's markup stays text");
    assert.ok((await text("q-h")).includes(HOSTILE) && (await text("q-h")).includes("<b>bold</b>"));
    assert.deepStrictEqual(await labels("q-u"), ["Don't allow"]);
    assert.ok((await text("q-u")).includes("We can't confirm which agent this is (token signature invalid)"));
    const onCard = await page.locator('#pending .req[data-id="q-s"] > .who').textContent();
    assert.ok(onCard.includes("could use the grant") && onCard.includes("more than one agent"), onCard);
    assert.ok(!(await page.locator('#pending .req[data-id="q-s"] details').textContent()).includes("could use the grant"));

    // A request opened from a notification is outlined (#644).
    await page.evaluate(() => openPending("q-u"));
    assert.ok(await page.locator('#pending .req[data-id="q-u"]').evaluate(c => c.classList.contains("opened")));

    // The status line and the problems, from the state.
    state = { ...base, pending: [A], runs: [{ id: "run_a", agent: "lead", zone: "z", status: "running" }], health: { nodes: [], control_disk_pct: 91 } };
    await poll();
    assert.strictEqual((await page.locator("#status").innerText()).trim(), "1 agent working · 1 request waiting for you · 1 problem");
    assert.strictEqual((await page.locator("#problems").innerText()).trim(), "The control host's disk is 91% full");
    state = { ...base, pending: [] };
    await poll();
    assert.strictEqual((await page.locator("#pending").innerText()).trim(), "Nothing is waiting for you.");
    assert.strictEqual((await page.locator("#problems").innerText()).trim(), "Nothing is wrong.");

    if (problems.length) throw new Error(problems.join("\n  "));

    // If inbox.js doesn't load, the cards' place says the requests can't be shown, rather than that
    // nothing is waiting.
    const bare = await (await browser.newContext()).newPage();
    await bare.route("**/inbox.js", r => r.abort());
    await bare.route("**/api/**", r => { const p = new URL(r.request().url()).pathname;
      return r.fulfill({ contentType: "application/json", body: JSON.stringify(p === "/api/me" ? { who: { state: "operator", credential: "AbCd" } } : p === "/api/state" ? { ...base, pending: [A] } : p === "/api/push" ? { public_key: "BAEC", devices: [], min_interval_secs: 30 } : {}) }); });
    await bare.goto(url);
    await bare.waitForFunction(() => document.getElementById("pending").textContent.includes("can't be shown"), null, { timeout: 10000 });
    console.log(`${engine} inbox: ok`);
  } finally {
    await browser.close();
  }
}

let failed = 0;
for (const engine of engines) {
  try { await check(engine); } catch (e) { failed++; console.error(`${engine} inbox: ${e.stack || e}`); }
}
process.exit(failed ? 1 : 0);

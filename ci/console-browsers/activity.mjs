// The Activity view in a real browser (#574): drawn by activity.js with lit-html (what each record
// says is console.js's `sentence`, tested under node by console_ui.js). The API is answered inside
// the page (page.route), with the state each step sets.
//
//   node activity.mjs URL [chromium] [firefox] [webkit]      (ci/console-browsers.sh runs it)
//
// What it holds the page to: the log is newest first, each line its time, tag and words; a line is
// the same element across polls; the filters show one kind of line and say which is on; a decision
// on a run's request has a "why?" that opens the server's explanation under it, which stays open
// across polls and closes on a second tap, and an agent's page has the same; recent decisions say
// allowed or refused, never "undefined"; an agent's strings stay text; and without activity.js its
// places say they can't be shown.
import assert from "node:assert";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const pw = require("playwright");

const [url, ...wanted] = process.argv.slice(2);
if (!url) { console.error("usage: node activity.mjs URL [chromium] [firefox] [webkit]"); process.exit(2); }
const engines = wanted.length ? wanted : ["chromium", "firefox", "webkit"];

// An agent's path with markup, a right-to-left override and a zero-width space in it: the markup stays
// text, and the two marks are shown as spaces (console.js's strip), never acted on.
const HOSTILE = "/x<img src=x onerror=alert(1)>\u202etxt.exe\u200b";
const SHOWN = HOSTILE.replace(/[\u202e\u200b]/g, " ");
const NOW = Math.floor(Date.now() / 1000);
const egress = (seq, outcome, path, run = "run_a") => ({ seq, ts: NOW - 100 + seq, kind: "op", run, body: { kind: "egress", outcome, method: "GET", host: "h.example", path } });
const audit = [
  { seq: 1, ts: NOW - 99, kind: "run.start", run: "run_a", body: { agent: "builder", zone: "z" } },
  egress(2, "allow", "/ok"),
  egress(3, "forbidden", HOSTILE),
  { seq: 4, ts: NOW - 96, kind: "decision", body: { request: "r-7", decision: "approve", by: "passkey:phone" } },
  { seq: 5, ts: NOW - 95, kind: "node.audit", body: { node: "n1", body: JSON.stringify({ kind: "box.restart" }) } },
];
const explained = { run: "run_a", policy: null, recorded: { method: "GET", host: "h.example", path: HOSTILE, outcome: "forbidden", decided_on: "the box's node", at: 1, detail: "d" },
  against_token_now: { available: true, decision: "forbidden", why: "block 0: check if " + HOSTILE, zone_says: "Forbidden" } };
const decided = [{ id: "r-5", run: "run_a", zone: "z", method: "GET", host: "h.example", path: "/p", status: "expired", created_at: NOW - 60 },
  { id: "r-6", run: "run_a", zone: "z", method: "POST", host: "h.example", path: "/q", status: "granted", created_at: NOW - 30 }];
const base = { now: NOW, tenant: "t0", pending: [], runs: [{ id: "run_a", zone: "z", agent: "builder", status: "running", started_at: NOW - 100, has_identity: true }],
  manifests: [], passkeys: [], health: { nodes: [] }, decided, audit };

async function check(engine) {
  const browser = await pw[engine].launch();
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  const problems = [];
  page.on("pageerror", e => problems.push("error: " + (e.stack || e.message).split("\n").slice(0, 3).join(" ")));
  page.on("console", m => { if (m.type() === "error") problems.push("console: " + m.text()); });
  let state = { ...base };
  const asked = [];
  let failNext = false;
  await page.route("**/api/**", async route => {
    const p = new URL(route.request().url()).pathname;
    const reply = (v, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(v) });
    if (p === "/api/me") return reply({ who: { state: "operator", credential: "AbCd" } });
    if (p === "/api/state") return reply(state);
    if (p.startsWith("/api/explain/")) { asked.push(p); if (failNext) { failNext = false; return reply({ error: "the node didn't answer" }, 502); } return reply(explained); }
    if (p === "/api/push") return reply({ public_key: "BAEC", devices: [], min_interval_secs: 30 });
    return reply({});
  });
  const poll = () => page.evaluate(async () => { while (polling) await new Promise(r => setTimeout(r, 20)); await refresh(); });
  const shown = () => page.$$eval("#audit .logline", ls => ls.filter(l => !l.hidden).map(l => l.querySelector(".tag").textContent + " " + l.querySelector(".text").textContent));
  try {
    await page.goto(url);
    await page.waitForSelector("#pending");
    await page.evaluate(() => { location.hash = "#activity"; });
    await page.waitForSelector("#audit .logline");
    // Newest first; each line a tag and words; an agent's path stays text.
    assert.deepStrictEqual(await shown(), ["node node n1: box.restart", "allowed r-7 by phone", `blocked builder: read h.example${SHOWN} why?`,
      "allowed builder: read h.example/ok why?", "start builder started: agent builder in zone z"]);
    assert.strictEqual(await page.locator("#audit img").count(), 0, "an agent's markup stays text");
    assert.ok(await page.locator("#audit .logline time").first().getAttribute("datetime"));
    // The same elements after a poll.
    await page.evaluate(() => { document.querySelector("#audit .logline").__mark = 1; });
    await poll();
    assert.ok(await page.evaluate(() => document.querySelector("#audit .logline").__mark === 1), "a line is kept across a poll");
    // The filters: one kind of line each, the pressed one said.
    const chip = label => page.locator("#filters button", { hasText: label });
    await chip("Blocked").click();
    assert.deepStrictEqual(await shown(), [`blocked builder: read h.example${SHOWN} why?`]);
    assert.deepStrictEqual(await page.$$eval("#filters button", bs => bs.filter(b => b.getAttribute("aria-pressed") === "true").map(b => b.textContent)), ["Blocked"]);
    await chip("Decisions").click();
    assert.deepStrictEqual(await shown(), ["allowed r-7 by phone"]);
    await chip("Servers").click();
    assert.deepStrictEqual(await shown(), ["node node n1: box.restart"]);
    await poll();
    assert.deepStrictEqual(await shown(), ["node node n1: box.restart"], "the filter holds across a poll");
    await chip("Everything").click();
    assert.strictEqual((await shown()).length, 5);
    // "why?" opens the server's explanation under its line; it stays open across a poll; a second
    // tap closes it without asking again.
    const why = page.locator("#audit .logline", { hasText: SHOWN }).locator("button", { hasText: "why?" });
    await why.click();
    await page.waitForSelector("#audit .explained pre");
    const ex = await page.locator("#audit .explained").innerText();
    assert.ok(ex.includes("block 0: check if " + SHOWN) && ex.includes("recorded") && ex.includes("Against the run's token"), ex);
    assert.strictEqual(await page.locator("#audit .explained img").count(), 0);
    assert.ok(!(await page.locator("#view-activity").textContent()).match(/[\u202e\u200b]/), "no bidi or zero-width mark reaches the page");
    assert.strictEqual(await why.getAttribute("aria-expanded"), "true");
    assert.deepStrictEqual(asked, ["/api/explain/3"]);
    await poll();
    assert.strictEqual(await page.locator("#audit .explained").count(), 1, "an opened explanation stays open across a poll");
    await why.click();
    assert.strictEqual(await page.locator("#audit .explained").count(), 0);
    await why.click();
    assert.strictEqual(await page.locator("#audit .explained").count(), 1);
    assert.strictEqual(asked.length, 1, "asked once");
    // A failed explanation is asked for again on the next tap, not kept.
    failNext = true;
    const why2 = page.locator("#audit .logline", { hasText: "/ok" }).locator("button", { hasText: "why?" });
    await why2.click();
    await page.waitForFunction(() => document.querySelector("#audit .explained .blocked"));
    await why2.click();
    await page.waitForFunction(() => document.querySelectorAll("#audit .explained pre").length === 2);
    assert.strictEqual(asked.length, 3, "asked again after it failed");
    await why2.click();
    // The browser logs the failure the test asked for: that one entry isn't a problem.
    const failed = problems.findIndex(p => p.includes("status of 502"));
    if (failed >= 0) problems.splice(failed, 1);
    // Recent decisions: allowed or refused, or the server's word; never "undefined".
    const pills = await page.$$eval("#decided .pill", ps => ps.map(p => [p.className, p.textContent]));
    assert.deepStrictEqual(pills, [["pill ", "expired"], ["pill good", "allowed"]]);
    assert.ok((await page.locator("#decided .decided").first().innerText()).includes("r-5 · zone z · asked"));
    // An agent's page has the same lines, and its "why?" too.
    await page.evaluate(() => { location.hash = "#agent/run_a"; });
    await page.waitForSelector("#agent-log .logline");
    assert.strictEqual(await page.locator("#agent-log .logline").count(), 3);
    assert.strictEqual(await page.locator("#agent-log .explained").count(), 1, "the explanation opened in the log is open here too");
    await page.locator("#agent-log button", { hasText: "why?" }).first().click();
    assert.strictEqual(await page.locator("#agent-log .explained").count(), 0);
    // Nothing yet.
    state = { ...base, audit: [], decided: [] };
    await poll();
    await page.evaluate(() => { location.hash = "#activity"; });
    assert.strictEqual((await page.locator("#audit").innerText()).trim(), "No activity yet.");
    assert.strictEqual((await page.locator("#decided").innerText()).trim(), "No decisions yet.");

    if (problems.length) throw new Error(problems.join("\n  "));

    // If activity.js doesn't load, the log, the decisions and an agent's log say they can't be shown,
    // rather than that nothing happened.
    const bare = await (await browser.newContext()).newPage();
    await bare.route("**/activity.js", r => r.abort());
    await bare.route("**/api/**", r => { const p = new URL(r.request().url()).pathname;
      return r.fulfill({ contentType: "application/json", body: JSON.stringify(p === "/api/me" ? { who: { state: "operator", credential: "AbCd" } } : p === "/api/state" ? base : p === "/api/push" ? { public_key: "BAEC", devices: [], min_interval_secs: 30 } : {}) }); });
    await bare.goto(url + "#activity");
    for (const id of ["audit", "decided"]) await bare.waitForFunction(i => document.getElementById(i).textContent.includes("can't be shown"), id, { timeout: 10000 });
    await bare.evaluate(() => { location.hash = "#agent/run_a"; });
    await bare.waitForFunction(() => document.getElementById("agent-log").textContent.includes("can't be shown"), null, { timeout: 10000 });
    console.log(`${engine} activity: ok`);
  } finally {
    await browser.close();
  }
}

let failed = 0;
for (const engine of engines) {
  try { await check(engine); } catch (e) { failed++; console.error(`${engine} activity: ${e.stack || e}`); }
}
process.exit(failed ? 1 : 0);

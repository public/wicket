// The Agents view and an agent's page in a real browser (#574): drawn by agents.js with lit-html, so
// these checks moved here from the fake DOM of console_ui.js. The API is answered inside the page
// (page.route), with the state each step sets.
//
//   node agents.mjs URL [chromium] [firefox] [webkit]      (ci/console-browsers.sh runs it)
//
// What it holds the page to: a run's row says who, where, its state and times, and links to its page;
// an unchanged row is the same element across polls, and a changed list makes taps wait; a live
// session and a remote session are linked only when they should be; an agent's page has Stop only for
// a running agent with an identity, and Stop names the agent; what a run can reach leads its page,
// with every kind of grant in words and the token's internals under Details; its activity is its own
// records; Start lists the manifests, shows what the picked one reaches, keeps what was typed across
// polls and asks the server to start exactly the one picked; and an agent's strings stay text.
import assert from "node:assert";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const pw = require("playwright");

const [url, ...wanted] = process.argv.slice(2);
if (!url) { console.error("usage: node agents.mjs URL [chromium] [firefox] [webkit]"); process.exit(2); }
const engines = wanted.length ? wanted : ["chromium", "firefox", "webkit"];

const HOSTILE = "/x<img src=x onerror=alert(1)>";
const NOW = Math.floor(Date.now() / 1000);
const run = (id, extra) => ({ id, zone: "z", agent: "builder", status: "running", started_at: NOW - 7200, has_identity: true, revoked: false, acp: false, ...extra });
const A = run("run_a"), X = run("run_x", { status: "exited", ended_at: NOW - 3600 });
const P = run("run_p", { agent: null, zone: "jobs" });
const authority = { status: "running", node: "local", policy: { version: null }, token: { held: true, box_path: "run_a", epoch: 0, zone: "z", issued_by: "the authority root", loads: true,
  reach: [{ host: "api.example.com", methods: ["GET"], paths: ["/v1/**"], allow_dangerous: false }, { host: "registry.example.com", methods: ["GET"], paths: ["/**"], allow_dangerous: false, decode_slash: [1] }],
  forbid: [{ host: "api.example.com", paths: ["/v1/admin/**"] }],
  blocks: [{ index: 0, kind: "zone", source: "check if reach(\"" + HOSTILE + "\");", signed_by: null, revocation_fingerprint: "0123456789abcdef", revoked: false }],
  grants: [{ id: "g-1", method: "POST", host: "h", path: HOSTILE, uses: 2, expires_at: 1, approved_by: "passkey:laptop", approved_at: 1, revoked: false, reached_node: true },
    { id: "g-2", method: "GET", host: "docs.example", path: "/guide/", prefix: true, uses: null, expires_at: 4e9, approved_by: "agent:run_p", approved_at: 1, revoked: false, reached_node: true },
    { id: "g-3", method: "GET", host: "ci.example", path: "", standing: { methods: ["GET", "POST"], paths: ["/jobs/**"], allow_dangerous: true }, uses: null, expires_at: 4e9,
      approved_by: "passkey:laptop", approved_at: 1, revoked: false, reached_node: true }] } };
const manifests = [
  { root: "manifests", name: "broken.yaml", valid: false },
  { root: "manifests", name: "docs.yaml", valid: true, agent: "writer", zone: "docs", image: "ghcr.io/example/agent@sha256:ab", hosts: [{ host: "api.example.com", mode: "inspected", why: "GET /v1/**" }] },
  { root: "examples", name: "fetch.yaml", valid: true, program: "fetch", zone: "jobs", image: null, image_error: "not pinned by digest", hosts: [{ host: "git.example", mode: "spliced" }] },
];
const audit = [{ seq: 1, ts: NOW - 60, kind: "run.started", run: "run_a", body: {} }, { seq: 2, ts: NOW - 30, kind: "run.started", run: "run_x", body: {} },
  { seq: 3, ts: NOW - 10, kind: "something.new", run: "run_a", body: {} }];
const base = { now: NOW, tenant: "t0", pending: [], manifests, decided: [], audit, passkeys: [], health: { nodes: [] } };

async function check(engine) {
  const browser = await pw[engine].launch();
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  const problems = [];
  page.on("pageerror", e => problems.push("error: " + (e.stack || e.message).split("\n").slice(0, 3).join(" ")));
  page.on("console", m => { if (m.type() === "error") problems.push("console: " + m.text()); });
  let state = { ...base, runs: [A, X, P] };
  const begun = [];
  await page.route("**/api/**", async route => {
    const r = route.request(), p = new URL(r.url()).pathname;
    const body = r.postData() ? JSON.parse(r.postData()) : null;
    const reply = (v, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(v) });
    if (p === "/api/me") return reply({ who: { state: "operator", credential: "AbCd" } });
    if (p === "/api/state") return reply(state);
    if (p.endsWith("/authority")) return reply(authority);
    if (p === "/api/action/begin") {
      begun.push(body);
      return reply({ action: { v: 1, ...body }, publicKey: { challenge: "Y2g", rpId: "localhost", allowCredentials: [] }, expires_in_ms: 120000 });
    }
    if (p === "/api/push") return reply({ public_key: "BAEC", devices: [], min_interval_secs: 30 });
    return reply({});
  });
  // One whole poll that starts after the state was set: if the page's own (every 2 s) is in flight,
  // after it ends.
  const poll = () => page.evaluate(async () => { while (polling) await new Promise(r => setTimeout(r, 20)); await refresh(); });
  const rowText = id => page.locator(`#runs .run:has(a[href="#agent/${id}"])`).innerText();
  try {
    await page.goto(url + "#agents");
    await page.waitForSelector("#runs .run");
    // A run's row: who, where, state, when, its id, a link to its page; a program run says so.
    assert.deepStrictEqual(await page.$$eval("#runs .run .run-name", as => as.map(a => a.textContent)), ["builder", "builder", "program run"]);
    const x = (await page.locator("#runs .run").nth(1).textContent());
    assert.ok(x.startsWith("builder · zone zfinished") && x.includes("started 2 h ago") && x.includes("ended 60 min ago") && x.includes("run_x") && x.includes("What it can reach"), x);
    assert.ok((await rowText("run_a")).includes("working"));
    // An unchanged row is the same element after a poll; a change (a request now waiting) makes taps
    // wait a moment, as on the request cards.
    await page.evaluate(() => { document.querySelector('#runs .run').__mark = 1; });
    await poll();
    assert.ok(await page.evaluate(() => document.querySelector('#runs .run').__mark === 1), "an unchanged row is kept across a poll");
    await page.waitForTimeout(900);
    state = { ...state, pending: [{ id: "q", run: "run_a", risk: "R1ReadScoped", method: "GET", host: "h", path: "/", created_at: NOW, identity: {}, attribution: [] }] };
    await poll();
    assert.ok((await rowText("run_a")).includes("waiting for you"));
    assert.strictEqual(await page.evaluate(() => settled()), false, "taps wait after the list changed");
    assert.ok(await page.evaluate(() => document.querySelector('#runs .run').__mark === 1), "the row is updated in place");
    // A live session only for a running ACP agent; a remote session only at an https URL.
    state = { ...base, runs: [run("run_l", { acp: true }), run("run_d", { acp: true, status: "exited" }), run("run_r", { remote_url: "https://claude.ai/code/x" }), run("run_j", { remote_url: "javascript:alert(1)" })] };
    await poll();
    assert.strictEqual(await page.locator('#runs a.session[href="/session?run=run_l"]').count(), 1);
    assert.strictEqual(await page.locator("#runs a.session").count(), 2, "one live session and one remote session");
    assert.strictEqual(await page.locator('#runs a[href^="javascript"]').count(), 0);
    state = { ...base, runs: [] };
    await poll();
    assert.strictEqual((await page.locator("#runs").innerText()).trim(), "No runs yet.");

    // An agent's page: its head, with Stop for a running agent that has an identity; Stop names it.
    state = { ...base, runs: [A, X, { ...run("run_h"), agent: HOSTILE }] };
    await poll();
    await page.click('#runs a.run-name[href="#agent/run_a"]');
    await page.waitForSelector("#agent-head h2.run-name");
    assert.strictEqual(await page.locator("#agent-head .run-name").textContent(), "builder");
    await page.click("#agent-head button.deny");
    assert.ok((await page.locator("#runform-title").textContent()).includes("Stop builder (run run_a)"));
    await page.click("#runform-cancel");
    // What it can reach leads the page; the token is under Details; every string is text.
    await page.waitForSelector("#detail-body h4");
    const text = await page.locator("#detail-body").textContent();
    assert.ok(text.startsWith("Can reachread api.example.com  /v1/**from its zone's rules"), text);
    assert.ok(text.includes(HOSTILE) && text.includes("block 0 · zone") && text.includes("approved by passkey:laptop"), text);
    assert.ok(text.includes("docs.example/guide/ and every path under it"), text);
    assert.ok(text.includes("allowed by run_p (a parent agent)"), text);
    assert.ok(text.includes("ci.example  /jobs/**") && text.includes("including requests that can't be undone"), text);
    assert.ok(!text.includes("you allowed"), text);
    assert.ok(text.includes("reads an encoded slash (%2F) as / in path part 1"), text);
    assert.ok(text.includes("never api.example.com  /v1/admin/**forbidden by its zone's rules, even if you allow it"), text);
    assert.strictEqual(await page.locator("#detail-body details").count(), 1, "the token folded under Details");
    assert.strictEqual(await page.locator("#detail-body img").count(), 0, "an agent's markup stays text");
    // Its activity: its own records, newest first, kept across polls.
    assert.deepStrictEqual(await page.$$eval("#agent-log .logline", ls => ls.length), 2);
    await page.evaluate(() => { document.querySelector("#agent-log .logline").__mark = 1; });
    await poll();
    assert.ok(await page.evaluate(() => document.querySelector("#agent-log .logline").__mark === 1), "a record's line is kept across a poll");
    assert.ok((await page.locator("#agent-log .logline").first().textContent()).includes("something.new"));
    // A finished agent has no Stop; an agent's name stays text.
    await page.evaluate(() => { location.hash = "#agent/run_x"; });
    await page.waitForFunction(() => document.querySelector("#agent-head")?.textContent.includes("finished"));
    assert.strictEqual(await page.locator("#agent-head button.deny").count(), 0);
    await page.evaluate(() => { location.hash = "#agent/run_h"; });
    await page.waitForFunction(h => document.querySelector("#agent-head .run-name")?.textContent === h, HOSTILE);
    assert.strictEqual(await page.locator("#agent-head img").count(), 0);
    // A run no longer in the list says so.
    await page.evaluate(() => { location.hash = "#agent/run_gone"; });
    await page.waitForFunction(() => document.querySelector("#agent-head")?.textContent.includes("isn't in the latest list"));

    // Start: the manifests, an invalid one not offered; the first that can start picked; what it reaches.
    await page.evaluate(() => { location.hash = "#agents"; });
    await page.click("#start-open");
    await page.waitForSelector("#start select");
    assert.deepStrictEqual(await page.$$eval("#start option", os => os.map(o => [o.textContent, o.disabled])),
      [["manifests/broken.yaml · invalid", true], ["manifests/docs.yaml · agent writer · zone docs", false], ["examples/fetch.yaml · program fetch · zone jobs", false]]);
    const hosts = () => page.locator("#start > .meta").first().innerText();
    assert.ok((await hosts()).includes("image ghcr.io/example/agent@sha256:ab") && (await hosts()).includes("api.example.com (GET /v1/**)"), await hosts());
    await page.selectOption("#start select", { index: 2 });
    assert.ok((await hosts()).includes("image refused: not pinned by digest") && (await hosts()).includes("git.example (every method and path; not inspected)"), await hosts());
    // What was picked and typed survives a poll; Start asks for exactly that.
    await page.fill("#start textarea", "fetch the nightly");
    await poll();
    assert.strictEqual(await page.inputValue("#start textarea"), "fetch the nightly");
    assert.strictEqual(await page.$eval("#start select", s => s.selectedIndex), 2);
    await page.click("#start button.approve");
    await page.waitForSelector("#confirm:not([hidden])");
    assert.deepStrictEqual(begun.at(-1), { action: "start_run", root: "examples", manifest: "fetch.yaml", task: "fetch the nightly" });
    assert.strictEqual(await page.inputValue("#start textarea"), "");
    await page.waitForTimeout(900);
    await page.click("#confirm-cancel");
    // No manifests: it says where to put one.
    state = { ...base, runs: [A], manifests: [] };
    await poll();
    await page.waitForFunction(() => document.getElementById("start").innerText.includes("No manifests to start"), null, { timeout: 5000 });

    if (problems.length) throw new Error(problems.join("\n  "));
    console.log(`${engine} agents: ok`);
  } finally {
    await browser.close();
  }
}

let failed = 0;
for (const engine of engines) {
  try { await check(engine); } catch (e) { failed++; console.error(`${engine} agents: ${e.stack || e}`); }
}
process.exit(failed ? 1 : 0);

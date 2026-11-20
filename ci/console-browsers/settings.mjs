// Settings' rules, spending limits and servers, and the Inbox's asks to be always allowed, in a real
// browser (#574): drawn by settings.js and inbox.js with lit-html, so these checks moved here from
// the fake DOM of console_ui.js. The API is answered inside the page (page.route), with the state
// each step sets.
//
//   node settings.mjs URL [chromium] [firefox] [webkit]      (ci/console-browsers.sh runs it)
//
// What it holds the page to: a spending limit says what it allows, has used and has left, in plain
// money and plurals, its principal by short name and whole on a tap; Renew asks the server to sign a
// renewal; Revoke asks in the page first, sends nothing until its own button (and not on the second
// tap of a double tap), and Cancel puts the row back; the form issues exactly what was typed; the
// health rows put each alert on a line of its own, the record backup and activity export above the
// nodes with their errors as text; a rented server past its lease says how to release it; an ask to
// be always allowed shows its evidence and offers the narrowest choice first, signed; a rule says
// when it ends, whether it allows what can't be undone, and is revoked with the session alone; and
// unchanged rows are the same elements after a poll.
import assert from "node:assert";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const pw = require("playwright");

const [url, ...wanted] = process.argv.slice(2);
if (!url) { console.error("usage: node settings.mjs URL [chromium] [firefox] [webkit]"); process.exit(2); }
const engines = wanted.length ? wanted : ["chromium", "firefox", "webkit"];

const HOSTILE = "/x<img src=x onerror=alert(1)>";
const NOW = Math.floor(Date.now() / 1000);
const grant = { id: "g-cap1", principal: "spiffe://x/t/t0/op/unix/" + HOSTILE, decided_by: "passkey:laptop", expires_at: NOW + 5000, created_at: 1,
  terms: { plans: ["vc2-1c-2gb"], regions: ["lhr"], hourly_usd: "$0.0500", daily_usd: "$1.0000", nodes: 2 },
  used: { nodes: 1, hourly_usd: "$0.0140", daily_usd: "$0.0200" }, left: { nodes: 1, hourly_usd: "$0.0360", daily_usd: "$0.9800" } };
const ask = { id: "s-1", principal: "spiffe://x/t/t0/z/work/a/worker", zone: "work", run: "run_w", reason: "CI <b>logs</b>",
  rule: { host: "ci.example", methods: ["GET", "POST"], paths: ["/jobs/**"], allow_dangerous: false }, zone_digest: "0123456789abcdef0123",
  evidence: { requests: 3, granted: 2, denied: 1, undecided: 0, runs: 2, days: 1, own_asks: 4, ops: [{ method: "GET", path: "/jobs/1/logs", count: 2, granted: 2 }] },
  beyond: ["methods never asked for: POST"], narrowed: { host: "ci.example", methods: ["GET"], paths: ["/jobs/1/logs"], allow_dangerous: false }, created_at: NOW - 60 };
const rule = { id: "s-2", principal: ask.principal, zone: "work", rule: ask.narrowed, for: "agent", expires_at: null, live: true, decided_by: "passkey:laptop" };
const base = { now: NOW, tenant: "t0", pending: [], runs: [], manifests: [], decided: [], audit: [], passkeys: [], health: { nodes: [] } };

async function check(engine) {
  const browser = await pw[engine].launch();
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  const problems = [];
  page.on("pageerror", e => problems.push("error: " + (e.stack || e.message).split("\n").slice(0, 3).join(" ")));
  page.on("console", m => { if (m.type() === "error") problems.push("console: " + m.text()); });
  let state = { ...base, capacity: [grant] };
  const begun = [], posted = [];
  await page.route("**/api/**", async route => {
    const r = route.request(), p = new URL(r.url()).pathname;
    const body = r.postData() ? JSON.parse(r.postData()) : null;
    const reply = (v, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(v) });
    if (p === "/api/me") return reply({ who: { state: "operator", credential: "AbCd" } });
    if (p === "/api/state") return reply(state);
    if (p === "/api/action/begin") {
      begun.push(body);
      return reply({ action: { v: 1, ...body, standing: body.id, grant: body.id }, publicKey: { challenge: "Y2g", rpId: "localhost", allowCredentials: [] }, expires_in_ms: 120000 });
    }
    if (p === "/api/capacity/revoke" || p === "/api/standing/revoke") { posted.push([p, body]); return reply({ ok: "revoked" }); }
    if (p === "/api/push") return reply({ public_key: "BAEC", devices: [], min_interval_secs: 30 });
    return reply({});
  });
  const poll = () => page.evaluate(async () => { while (polling) await new Promise(r => setTimeout(r, 20)); await refresh(); });
  const settle = () => page.waitForTimeout(900);
  const cancelSheet = async () => { await page.waitForSelector("#confirm:not([hidden])"); await settle(); await page.click("#confirm-cancel"); await page.waitForSelector("#confirm", { state: "hidden" }); };
  try {
    await page.goto(url);
    await page.waitForSelector("#pending");
    await page.evaluate(() => { location.hash = "#settings"; });
    await page.waitForSelector("#capacity .cap");

    // A spending limit (#639): in lines, plain money, plurals, the principal by its short name (here
    // one with a slash in it, shown whole) and as text.
    const cap = page.locator("#capacity .cap").first();
    const capText = await cap.textContent();
    for (const want of ["g-cap1", "Allows: 2 nodes at once of vc2-1c-2gb in lhr, up to $0.05/h and $1.00 a day", "Used today: 1 node, $0.014/h, $0.02",
      "Left today: 1 node, $0.036/h, $0.98", "Ends ", "granted by passkey:laptop"]) assert.ok(capText.includes(want), want + " in " + capText);
    assert.ok(capText.startsWith(grant.principal), capText);
    assert.strictEqual(await page.locator("#capacity img").count(), 0, "a principal stays text");
    // Renew is signed.
    await settle();
    await cap.locator("button", { hasText: "Renew" }).click();
    assert.deepStrictEqual([begun.at(-1).action, begun.at(-1).id, begun.at(-1).ttl_secs], ["capacity_renew", "g-cap1", 28800]);
    await cancelSheet();
    // Revoke asks first; nothing is sent until its own button; Cancel puts the row back.
    const btn = label => cap.locator("button", { hasText: new RegExp("^" + label + "$") });
    await settle();
    await btn("Revoke…").click();
    assert.ok((await cap.textContent()).includes("Revoke capacity grant g-cap1?"));
    assert.strictEqual(posted.length, 0, "nothing sent on the first tap");
    await btn("Cancel").click();
    assert.ok(await btn("Renew").count() && !(await cap.textContent()).includes("Revoke capacity grant"), "Cancel restores the row");
    await settle();
    await btn("Revoke…").click();
    await btn("Revoke").click();
    assert.strictEqual(posted.length, 0, "a tap just after the question appeared is ignored");
    await settle();
    await btn("Revoke").click();
    await page.waitForFunction(() => true);
    await page.waitForTimeout(200);
    assert.deepStrictEqual(posted, [["/api/capacity/revoke", { id: "g-cap1" }]]);

    // The form: seven fields, kept across polls, issuing exactly what was typed.
    await page.locator("#capacity-form").evaluate(f => { f.closest("details").open = true; });
    const inputs = page.locator("#capacity-form input");
    assert.strictEqual(await inputs.count(), 7);
    const values = ["unix/alex", "vc2-1c-2gb", "lhr", "0.05", "1", "2", "4"];
    for (let i = 0; i < 7; i++) await inputs.nth(i).fill(values[i]);
    await poll();
    assert.strictEqual(await inputs.nth(0).inputValue(), "unix/alex", "what was typed survives a poll");
    await settle();
    await page.locator("#capacity-form button", { hasText: "Grant" }).click();
    const gb = begun.at(-1);
    assert.deepStrictEqual([gb.action, gb.principal, gb.plans, gb.regions, gb.max_hourly_usd, gb.max_daily_usd, gb.nodes, gb.ttl_secs],
      ["capacity_grant", "unix/alex", "vc2-1c-2gb", "lhr", "0.05", "1", 2, 14400]);
    await cancelSheet();

    // Health: an alert is a line under its node's row (B7).
    state = { ...base, health: { nodes: [{ node: "n1", summary: "ok", received_ms: 1, alerts: ["disk 91% full"] }] } };
    await poll();
    assert.deepStrictEqual(await page.$$eval("#health > .hrow > *", es => es.map(e => [e.className, e.textContent])).then(x => x.map(([c, t]) => c === "row" ? [c, t.split(" · ")[0]] : [c, t])),
      [["row", "n1ok"], ["blocked", "! disk 91% full"]]);
    // The record backup and the export (#635): a row each above the nodes, lagging and failing ones
    // marked, the last error under its row, as text.
    const nowS = NOW;
    state = { ...base, health: { nodes: [], state_store: {
      stream: { endpoint: "https://s3.example.com", bucket: "b-1", state: "lagging", last_sync_ms: (nowS - 420) * 1000, behind_secs: 420, error: "monitor error: <b>refused</b>", error_ms: (nowS - 5) * 1000 },
      audit: [{ sink: "store", kind: "store", seq: 1180, head: 1204, behind: 24, behind_secs: 400, checkpoint_at: nowS - 900, error: "PUT: refused" },
        { sink: "collector", kind: "otlp", seq: 1204, head: 1204, behind: 0, behind_secs: 0, checkpoint_at: 0, error: null }],
      errors: ["audit-sinks.yaml: bad"] } } };
    await poll();
    const hs = () => page.$$eval("#health > *", es => es.map(e => ({ cls: e.className, text: e.textContent, rows: [...e.children].map(c => ({ cls: c.className, text: c.textContent, second: c.children[1] ? c.children[1].className : null })) })));
    let h = await hs();
    assert.strictEqual(h[0].rows[0].text, "Record backuphttps://s3.example.com (b-1) · ledger lagging · last sync 7 min ago");
    assert.strictEqual(h[0].rows[0].second, "blocked");
    assert.strictEqual(h[0].rows[1].text, "! last error 5 s ago: monitor error: <b>refused</b>", "as text, never markup");
    assert.ok(h[1].rows[0].text.endsWith("24 records behind (oldest 6 min) at 1180 of 1204 · last checkpoint 15 min ago"), h[1].text);
    assert.strictEqual(h[1].rows[0].second, "blocked");
    assert.strictEqual(h[1].rows[1].text, "! last error: PUT: refused");
    assert.strictEqual(h[2].rows[0].text, "Activity export to collectorcaught up at 1204 of 1204 · last checkpoint never");
    assert.strictEqual(h[2].rows.length, 1, "no error, no line");
    assert.strictEqual(h[3].text, "! audit-sinks.yaml: bad");
    assert.strictEqual(h[4].cls, "empty", "then the nodes");
    assert.strictEqual(await page.locator("#health b").count(), 0);
    // Streaming: no mark, and an error from before the last sync isn't shown; one since is.
    const streaming = error_ms => ({ ...base, health: { nodes: [], state_store: {
      stream: { endpoint: "https://s3.example.com", bucket: "b-1", state: "streaming", last_sync_ms: (nowS - 2) * 1000, behind_secs: 2, error: "old trouble", error_ms }, audit: [], errors: [] } } });
    state = streaming((nowS - 600) * 1000);
    await poll();
    h = await hs();
    assert.strictEqual(h[0].rows[0].second, "");
    assert.ok(h[0].rows[0].text.endsWith("ledger streaming · last sync 2 s ago"), h[0].rows[0].text);
    assert.strictEqual(h[0].rows.length, 1, "an error recovered from isn't shown");
    state = streaming((nowS - 1) * 1000);
    await poll();
    assert.strictEqual((await hs())[0].rows[1].text, "! last error 1 s ago: old trouble", "one after the last sync is");
    // Starting: pending, saying how long it has had no sync.
    state = { ...base, health: { nodes: [], state_store: { stream: { endpoint: "https://s3.example.com", bucket: "b-1", state: "starting", last_sync_ms: null, behind_secs: 12, error: null, error_ms: null }, audit: [], errors: [] } } };
    await poll();
    h = await hs();
    assert.strictEqual(h[0].rows[0].second, "pend");
    assert.ok(h[0].rows[0].text.endsWith("ledger starting · no sync yet in 12 s"));
    // A manual sink behind isn't marked; its command is code.
    state = { ...base, health: { nodes: [], state_store: { stream: null, errors: [], audit: [{ sink: "stdout", kind: "jsonl", seq: 3, head: 9, behind: 6, behind_secs: 4000, checkpoint_at: 0, error: null, manual: true }] } } };
    await poll();
    h = await hs();
    assert.strictEqual(h.length, 2, "the sink's row, then the nodes");
    assert.ok(h[0].rows[0].text.startsWith("Activity export to stdout6 records behind (oldest 66 min) (manual: fed only by wicket audit export)"), h[0].text);
    assert.strictEqual(h[0].rows[0].second, "");
    assert.strictEqual(await page.locator("#health code").textContent(), "wicket audit export");
    // Alerts first, then a stale read says so, then the rows.
    state = { ...base, health: { nodes: [], state_store: { stream: null, errors: [], stale: true, read_ms: (nowS - 400) * 1000, alerts: ["audit sink store: 24 records behind (oldest 6 min)"],
      audit: [{ sink: "store", kind: "store", seq: 1, head: 25, behind: 24, behind_secs: 400, checkpoint_at: 0, error: null, manual: false }] } } };
    await poll();
    h = await hs();
    assert.deepStrictEqual([h[0].text, h[0].cls], ["! audit sink store: 24 records behind (oldest 6 min)", "blocked"]);
    assert.strictEqual(h[1].text, "! not checked for 6 min: these rows may be out of date");
    assert.ok(h[2].text.startsWith("Activity export to store24 records behind"));
    // An error the config alert already quotes is said once; a first read that is overdue says so;
    // the control host's disk after the store's rows.
    state = { ...base, health: { nodes: [], control_disk_pct: 91, state_store: { stream: null, audit: [], stale: true, read_ms: null, not_read_yet: true,
      errors: ["audit-sinks.yaml can't be read: x"], alerts: ["audit-sinks.yaml can't be read: x (for 5 min)"] } } };
    await poll();
    assert.deepStrictEqual((await hs()).map(x => x.text), ["! audit-sinks.yaml can't be read: x (for 5 min)", "! not read yet: the console hasn't managed a first read of the state store",
      "! the control host's disk is 91% full", "No node has reported its health yet."]);

    // A rented server past its lease, still held: how to release it, with Copy.
    state = { ...base, placed: [{ id: "uuid-1", name: "runner", past_lease: true, held_by: "run_h", lease_until: 1 }, { id: "uuid-2", name: "spare", past_lease: false, lease_until: NOW + 3600 }] };
    await poll();
    const placed = await page.locator("#placed").innerText();
    assert.ok(placed.includes("still billing: run run_h holds it") && placed.includes("lease ends"), placed);
    assert.strictEqual(await page.locator("#placed code").textContent(), "wicket node release uuid-1");
    assert.strictEqual(await page.locator("#placed button.copy").count(), 1);

    // An ask to be always allowed (#572), in the Inbox: its evidence, what it allows beyond it, the
    // narrowest choice first and primary, the widest marked; signed from the sheet.
    state = { ...base, standing: { asks: [ask], rules: [rule] } };
    await poll();
    await page.evaluate(() => { location.hash = "#inbox"; });
    await page.waitForSelector("#standing-asks .always");
    const sa = await page.locator("#standing-asks").textContent();
    assert.ok(!sa.includes("Changes data") && !sa.includes("Only reads"), sa);
    for (const want of ["always be allowed to read and send data to", "ci.example/jobs/**", "Methods: GET, POST", "Paths: /jobs/**", "Asked by worker (zone work)", "with this zone definition (0123456789ab",
      "2 granted of 3 blocked request(s) it covers in the last 14 days", "in 2 run(s) on 1 day(s)", "2 × GET /jobs/1/logs (2 granted)", "and 4 ask(s) ahead of its own, not counted as evidence",
      "Wider than what it used: methods never asked for: POST", "Only what it used: methods GET, paths /jobs/1/logs"]) assert.ok(sa.includes(want), want + " in " + sa);
    assert.deepStrictEqual(await page.$$eval("#standing-asks .ladder button", bs => bs.map(b => [b.textContent, b.className])),
      [["Always: only what it used", "approve"], ["Always: as asked", ""], ["Always, for every agent in zone work", "deny"], ["Don't allow", "deny apart"]]);
    assert.strictEqual(await page.locator("#standing-asks b").count(), 0, "an agent's reason stays text");
    await page.evaluate(() => { document.querySelector("#standing-asks .always").__mark = 1; });
    await poll();
    assert.ok(await page.evaluate(() => document.querySelector("#standing-asks .always").__mark === 1), "an unchanged ask is kept across a poll");
    await settle();
    await page.locator("#standing-asks button", { hasText: "Always: only what it used" }).click();
    assert.deepStrictEqual([begun.at(-1).action, begun.at(-1).id, begun.at(-1).for, begun.at(-1).narrow], ["standing_approve", "s-1", "agent", true]);
    await cancelSheet();
    await settle();
    await page.locator("#standing-asks button", { hasText: "Don't allow" }).click();
    assert.deepStrictEqual([begun.at(-1).action, begun.at(-1).id], ["standing_deny", "s-1"]);
    await cancelSheet();

    // A rule: until when, by whom; Renew signed; Revoke with the session after asking.
    await page.evaluate(() => { location.hash = "#settings"; });
    const sr = page.locator("#standing-rules");
    assert.ok((await sr.textContent()).includes("until revoked") && (await sr.textContent()).includes("by passkey:laptop"));
    assert.ok(!(await sr.textContent()).includes("can't be undone"));
    await settle();
    await sr.locator("button", { hasText: "Revoke…" }).click();
    assert.ok((await sr.textContent()).includes("Runs it allows lose it at once."));
    await settle();
    await sr.locator("button", { hasText: /^Revoke$/ }).click();
    await page.waitForTimeout(200);
    assert.deepStrictEqual(posted.at(-1), ["/api/standing/revoke", { id: "s-2" }]);
    // A rule that allows dangerous requests says so on its row.
    state = { ...base, standing: { asks: [], rules: [{ ...rule, rule: { ...rule.rule, allow_dangerous: true } }] } };
    await poll();
    assert.ok((await sr.textContent()).includes("including requests that can't be undone"));
    // Nothing: each list says so.
    state = { ...base };
    await poll();
    assert.ok((await page.locator("#capacity").innerText()).includes("No capacity grants"));
    assert.strictEqual(await page.locator("#capacity code").textContent(), "wicket node create");
    assert.ok((await sr.innerText()).includes("No standing rules"));

    if (problems.length) throw new Error(problems.join("\n  "));
    console.log(`${engine} settings: ok`);
  } finally {
    await browser.close();
  }
}

let failed = 0;
for (const engine of engines) {
  try { await check(engine); } catch (e) { failed++; console.error(`${engine} settings: ${e.stack || e}`); }
}
process.exit(failed ? 1 : 0);

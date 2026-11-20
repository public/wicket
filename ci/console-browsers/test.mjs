// The console in real browsers (#574): what `wicket serve` sends (minified, content-hashed, under
// its CSP and the Trusted Types report-only policy), against the preview's mock API.
//
//   node test.mjs URL [chromium] [firefox] [webkit]      (ci/console-browsers.sh runs it)
//
// For each browser, at a desktop and a phone size: the page loads with no error, no CSP violation and
// no Trusted Types report; the Inbox shows the request cards, and an unchanged card is the same
// element after a poll; every view opens; a choice opens the signing sheet, which Cancel closes; and
// nothing scrolls sideways. A failure names the browser, the size and what broke.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const pw = require("playwright");

const [url, ...wanted] = process.argv.slice(2);
if (!url) { console.error("usage: node test.mjs URL [chromium] [firefox] [webkit]"); process.exit(2); }
const engines = wanted.length ? wanted : ["chromium", "firefox", "webkit"];
const SIZES = [["desktop", { viewport: { width: 1440, height: 900 } }], ["phone", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true }]];
const AGENT = "#agent/run_01JDRELEASEQQQQQQQQQQQQQQQ";

// Collects what the page reports: console errors, uncaught errors, and every securitypolicyviolation
// (the enforced CSP's and the report-only Trusted Types policy's), recorded from before any script.
async function watch(page) {
  const problems = [];
  // WebKit ignores a report-only policy without a `report-to`, and logs that as an error: a note
  // about the header, not a problem of the page's. Chromium and Firefox still report under it.
  const reportOnly = /delivered in report-only mode, but does not specify a 'report-to'/;
  page.on("console", m => { if (m.type() === "error" && !reportOnly.test(m.text())) problems.push("console: " + m.text()); });
  page.on("pageerror", e => problems.push("error: " + e.message));
  await page.addInitScript(() => {
    window.__violations = [];
    document.addEventListener("securitypolicyviolation", e => window.__violations.push(e.effectiveDirective + " " + e.disposition + " " + (e.blockedURI || e.sample || "")));
  });
  return async () => problems.concat((await page.evaluate(() => window.__violations || [])).map(v => "violation: " + v));
}

async function check(engine, name, opts) {
  const browser = await pw[engine].launch();
  const ctx = await browser.newContext(opts);
  const page = await ctx.newPage();
  const seen = await watch(page);
  const fail = msg => { throw new Error(`${engine} ${name}: ${msg}`); };
  try {
    await page.goto(url + "?fixture=full");
    await page.waitForSelector(".req button.approve", { timeout: 15000 });
    const cards = await page.locator("#pending .req").count();
    if (cards < 3) fail(`${cards} request cards, expected the fixture's`);
    // An unchanged card stays the same element across a poll (2 s), so a tap lands where it aimed.
    await page.evaluate(() => { document.querySelector("#pending .req").__mark = 1; });
    await page.waitForTimeout(2600);
    if (!(await page.evaluate(() => !!document.querySelector("#pending .req").__mark))) fail("the first card was replaced by a poll that changed nothing");
    // Every view opens and shows something of its own.
    for (const [hash, sel] of [["#agents", "#runs .run"], [AGENT, "#agent-head"], ["#activity", "#audit"], ["#settings", "#view-settings"], ["#inbox", "#pending .req"]]) {
      await page.evaluate(h => { location.hash = h; }, hash);
      await page.waitForSelector(sel, { state: "visible", timeout: 5000 }).catch(() => fail(`${hash} didn't show ${sel}`));
    }
    // A choice opens the signing sheet with the server's action; Cancel closes it and signs nothing.
    await page.waitForTimeout(900); // taps right after the cards moved are ignored, by design
    await page.locator("#pending .req").first().locator("button.approve").click();
    await page.waitForSelector("#confirm:not([hidden])", { timeout: 5000 }).catch(() => fail("the signing sheet didn't open"));
    const what = (await page.locator("#confirm-what").innerText()).trim();
    if (!what) fail("the signing sheet is empty");
    await page.waitForTimeout(900);
    await page.locator("#confirm-cancel").click();
    await page.waitForSelector("#confirm", { state: "hidden", timeout: 5000 }).catch(() => fail("Cancel didn't close the sheet"));
    const wide = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (wide > 1) fail(`the page scrolls sideways by ${wide} px`);
    const problems = await seen();
    if (problems.length) fail("\n  " + problems.join("\n  "));
    console.log(`${engine} ${name}: ok (${cards} cards)`);
  } finally {
    await browser.close();
  }
}

let failed = 0;
for (const engine of engines) {
  for (const [name, opts] of SIZES) {
    try { await check(engine, name, opts); } catch (e) { failed++; console.error(String(e.message || e)); }
  }
}
process.exit(failed ? 1 : 0);

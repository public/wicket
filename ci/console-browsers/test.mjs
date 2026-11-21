// The console in real browsers (#574): what `wicket serve` sends (minified, content-hashed, under
// its CSP with Trusted Types enforced, #739), against the preview's mock API.
//
//   node test.mjs URL [chromium] [firefox] [webkit]      (ci/console-browsers.sh runs it)
//
// For each browser, at a desktop and a phone size: the page loads with no error, no CSP violation and
// no Trusted Types violation; the Inbox shows the request cards, and an unchanged card is the same
// element after a poll; every view opens; a choice opens the signing sheet, which Cancel closes;
// nothing scrolls sideways; and a raw innerHTML write throws. Then, once per browser, a run's session
// view mounts under the same policy. A failure names the browser, the size and what broke.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const pw = require("playwright");

const [url, ...wanted] = process.argv.slice(2);
if (!url) { console.error("usage: node test.mjs URL [chromium] [firefox] [webkit]"); process.exit(2); }
const engines = wanted.length ? wanted : ["chromium", "firefox", "webkit"];
const SIZES = [["desktop", { viewport: { width: 1440, height: 900 } }], ["phone", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true }]];
const AGENT = "#agent/run_01JDRELEASEQQQQQQQQQQQQQQQ";

// Collects what the page reports: console errors, uncaught errors, and every securitypolicyviolation
// (the CSP's, Trusted Types' included), recorded from before any script.
async function watch(page) {
  const problems = [];
  page.on("console", m => { if (m.type() === "error") problems.push("console: " + m.text()); });
  page.on("pageerror", e => problems.push("error: " + e.message));
  await page.addInitScript(() => {
    window.__violations = [];
    // What navigator.serviceWorker.register is given (#739): a TrustedScriptURL, under Trusted Types.
    // Notifications are "allowed" here without a prompt, so the page's own button gets that far.
    window.__swArgs = [];
    if (navigator.serviceWorker) {
      const register = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = (u, o) => { window.__swArgs.push(window.TrustedScriptURL && u instanceof window.TrustedScriptURL ? "trusted" : typeof u); return register(u, o); };
    }
    if (window.Notification) Notification.requestPermission = async () => "granted";
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
    // Trusted Types are enforced (#739): a string written to an HTML sink throws. Checked last, since
    // the browser reports the attempt. A browser without Trusted Types is named, not failed.
    const tt = await page.evaluate(() => {
      if (!window.trustedTypes) return "none";
      try { document.createElement("div").innerHTML = "<b>x</b>"; return "allowed"; } catch (e) { return e instanceof TypeError ? "throws" : String(e); }
    });
    if (tt !== "throws" && tt !== "none") fail("a raw innerHTML write: " + tt + " (Trusted Types aren't enforced)");
    // Enabling notifications registers the service worker with a TrustedScriptURL from wicket-sw,
    // console.js's policy, which makes nothing but /sw.js: the page's own button, so the call site is
    // what is checked (#739). Then: wicket-sw can't be made a second time, nor a policy the CSP
    // doesn't list.
    // The page offers the button only where push works (console.js's pushSupported: a service worker,
    // PushManager and Notification); elsewhere it says how to get it (WebKit at phone size, here).
    await page.evaluate(() => { location.hash = "#settings"; });
    const push = await page.evaluate(() => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window);
    if (!push) {
      await page.waitForFunction(() => document.getElementById("push").textContent.includes("can't receive notifications here"), null, { timeout: 5000 })
        .catch(() => fail("no push here, and the page doesn't say so"));
      console.log(`${engine} ${name}: no push here, registering not checked`);
    } else {
      await page.locator("#push button", { hasText: "Enable notifications" }).click();
      await page.waitForFunction(() => window.__swArgs.length > 0, null, { timeout: 5000 }).catch(() => fail("Enable notifications didn't register the service worker"));
      const args = await page.evaluate(() => window.__swArgs);
      if (args[0] !== (tt === "none" ? "string" : "trusted")) fail(`navigator.serviceWorker.register was given a ${args[0]}, not a TrustedScriptURL`);
    }
    const policies = await page.evaluate(() => {
      if (!window.trustedTypes) return "ok";
      // The page's own wicket-sw first (it is made on first use), so the duplicate is a second one.
      swUrl();
      for (const name of ["wicket-sw", "not-listed"]) {
        try { window.trustedTypes.createPolicy(name, { createScriptURL: u => u }); return `a policy named ${name} was made`; } catch (e) { /* refused, as it should be */ }
      }
      return "ok";
    });
    if (policies !== "ok") fail(policies);
    if (tt === "none") console.log(`${engine} ${name}: no Trusted Types in this browser`);
    console.log(`${engine} ${name}: ok (${cards} cards)`);
  } finally {
    await browser.close();
  }
}

// A run's session view (#327; a Vue build, when wicket was built with it): it mounts under its own
// CSP, whose only Trusted Types policy is Vue's, with nothing reported, and a raw innerHTML write
// outside Vue throws. (Vue's policy passes any string: ci/session-view.sh keeps v-html out of the view.) The
// mock API has no session endpoint, so what it asks the server for fails; only the policy is checked.
async function session(engine) {
  const browser = await pw[engine].launch();
  try {
    const page = await (await browser.newContext()).newPage();
    const seen = await watch(page);
    const r = await page.goto(url + "session?run=run_01JDRELEASEQQQQQQQQQQQQQQQ");
    if (!r || r.status() !== 200) {
      if (process.env.WICKET_SESSION_VIEW_REQUIRED) throw new Error(`${engine} session: not served (${r && r.status()})`);
      return console.log(`${engine} session: not served by the preview, skipped`);
    }
    await page.waitForFunction(() => document.getElementById("app")?.hasChildNodes(), null, { timeout: 10000 })
      .catch(() => { throw new Error(`${engine} session: nothing mounted on #app`); });
    const built = await page.evaluate(() => !document.body.textContent.includes("no session view"));
    const violations = (await seen()).filter(p => p.startsWith("violation") || p.startsWith("error: Failed to set") || p.includes("TrustedHTML"));
    if (violations.length) throw new Error(`${engine} session:\n  ` + violations.join("\n  "));
    // Its policy is Vue's alone: a string written to an HTML sink outside Vue throws (#739).
    const tt = await page.evaluate(() => {
      if (!window.trustedTypes) return "none";
      try { document.createElement("div").innerHTML = "<b>x</b>"; return "allowed"; } catch (e) { return e instanceof TypeError ? "throws" : String(e); }
    });
    if (tt !== "throws" && tt !== "none") throw new Error(`${engine} session: a raw innerHTML write: ${tt}`);
    // CI builds the view (WICKET_SESSION_VIEW_REQUIRED): the placeholder there means it wasn't.
    if (!built && process.env.WICKET_SESSION_VIEW_REQUIRED) throw new Error(`${engine} session: the placeholder, not the built view`);
    console.log(`${engine} session: ok (${built ? "the built view" : "the placeholder"})`);
  } finally {
    await browser.close();
  }
}

let failed = 0;
for (const engine of engines) {
  try { await session(engine); } catch (e) { failed++; console.error(String(e.message || e)); }
}
for (const engine of engines) {
  for (const [name, opts] of SIZES) {
    try { await check(engine, name, opts); } catch (e) { failed++; console.error(String(e.message || e)); }
  }
}
process.exit(failed ? 1 : 0);

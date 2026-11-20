"use strict";
// Screenshots of the console preview (server.js), for reviewing a change to the console's look.
//
//   node ci/console-preview/shots.js BASE_URL OUT_DIR [SCENARIO...]
//
// Each scenario (default: full empty signedout sheet) at 1440x900 (desktop) and 390x844 (phone,
// deviceScaleFactor 2), in light and dark, full page. "sheet" is the full fixture with the first
// card's approval sheet open. Needs Playwright (preinstalled in CI images and wicket's dev boxes).
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const [base, out, ...want] = process.argv.slice(2);
if (!base || !out) { console.error("usage: shots.js BASE_URL OUT_DIR [SCENARIO...]"); process.exit(2); }
const scenarios = want.length ? want : ["full", "empty", "signedout", "sheet"];
const views = { desktop: { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 }, phone: { viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true } };
const SETTLE_MS = 1200; // past the console's own settle time (800 ms), so buttons are live

(async () => {
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch();
  const errors = [];
  for (const scheme of ["light", "dark"]) {
    for (const [vname, v] of Object.entries(views)) {
      const ctx = await browser.newContext({ ...v, colorScheme: scheme, reducedMotion: "reduce" });
      for (const sc of scenarios) {
        const page = await ctx.newPage();
        page.on("console", m => { if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`${sc}/${vname}/${scheme}: ${m.text()}`); });
        page.on("pageerror", e => errors.push(`${sc}/${vname}/${scheme}: ${e.message}`));
        const fixture = sc === "sheet" ? "full" : sc;
        await page.goto(base + "?fixture=" + fixture, { waitUntil: "load" });
        await page.waitForTimeout(SETTLE_MS);
        const file = path.join(out, `${sc}-${vname}-${scheme}.png`);
        if (sc === "sheet") {
          await page.locator("#pending button.approve").first().click();
          await page.waitForSelector("#confirm:not([hidden])");
          await page.waitForTimeout(300);
          await page.screenshot({ path: file });
        } else {
          await page.screenshot({ path: file, fullPage: true });
        }
        // Wider than the viewport is a horizontal scroll on a phone.
        const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        if (over > 0) errors.push(`${sc}/${vname}/${scheme}: the page is ${over}px wider than the viewport`);
        console.log(file);
        await page.close();
      }
      await ctx.close();
    }
  }
  await browser.close();
  if (errors.length) { console.error(errors.join("\n")); process.exitCode = 1; }
})();

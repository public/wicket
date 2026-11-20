// Calibrates the phone profile's CPU slowdown against a real phone: runs Speedometer 3.0 (from
// browserbench.org) in this machine's Chromium, with no slowdown or with `rate`, and prints its score.
// The rate for a phone is this machine's score divided by the phone's.
//
//   NODE_PATH=$(npm root -g) node speedometer.mjs [rate]
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)("playwright");
const rate = Number(process.argv[2]) || 1;
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const cdp = await page.context().newCDPSession(page);
if (rate > 1) await cdp.send("Emulation.setCPUThrottlingRate", { rate });
await page.goto("https://browserbench.org/Speedometer3.0/?startAutomatically=true", { timeout: 60000 });
await page.waitForFunction(() => { const e = document.querySelector("#result-number"); return e && e.textContent.trim() && document.querySelector("#summary")?.offsetParent !== null; }, null, { timeout: 1_800_000, polling: 2000 });
const score = await page.evaluate(() => document.querySelector("#result-number").textContent.trim() + " " + (document.querySelector("#confidence-number")?.textContent.trim() || ""));
console.log(JSON.stringify({ rate, score }));
await browser.close();

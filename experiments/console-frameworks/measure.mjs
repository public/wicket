// Loads each candidate on a throttled phone profile and measures it the same way.
//
//   node measure.mjs [RUNS] [candidate...]      (default: 7 runs; baseline and every */dist)
//
// Profile, per run, in a fresh browser context (cold cache): 390x844 at DPR 2, Chromium's CPU slowed
// 4x, and the network as Lighthouse's "slow 4G" (150 ms RTT, 1.6 Mbit/s down, 750 kbit/s up).
// For each run:
// - card_ms: from navigation start until the first request card's Allow button is in the page;
// - fcp_ms: first contentful paint;
// - heap_kb: JS heap used after a full GC, once the page has settled (3 s after the first card);
// - dom: element count then;
// - poll_ms: script time per 2 s poll, from Chromium's ScriptDuration over 10 s (5 polls), throttled;
// - kept: whether the first card is still the same DOM node after those polls.
// Results print as a table of medians and are written to results/runtime.json (raw runs in
// results/raw/).
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
// Playwright as installed globally (NODE_PATH=$(npm root -g)): require honours NODE_PATH, import does not.
const { chromium } = createRequire(import.meta.url)("playwright");

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const RUNS = Number(args[0]) || 7;
let names = args.slice(1);
if (!names.length) names = ["baseline", ...fs.readdirSync(here).filter(d => fs.existsSync(path.join(here, d, "dist", "index.html"))).sort()];

const median = xs => { const s = [...xs].sort((a, b) => a - b); return s.length ? s[Math.floor(s.length / 2)] : NaN; };
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function serve(name, port) {
  const p = spawn(process.execPath, [path.join(here, "serve.mjs"), name, String(port)], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise(r => p.stdout.once("data", r));
  return p;
}

async function once(browser, url) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  const errors = [];
  page.on("console", m => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", e => errors.push(e.message));
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("Network.enable");
  await cdp.send("Network.setCacheDisabled", { cacheDisabled: true });
  await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: 150, downloadThroughput: 1.6e6 / 8, uploadThroughput: 750e3 / 8 });
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: 4 });
  await cdp.send("Performance.enable");
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForSelector(".req button.approve", { timeout: 60000 });
  const card_ms = await page.evaluate(() => performance.now());
  const fcp_ms = await page.evaluate(() => (performance.getEntriesByName("first-contentful-paint")[0] || {}).startTime || NaN);
  await sleep(3000);
  await cdp.send("HeapProfiler.collectGarbage");
  const heap = await cdp.send("Runtime.getHeapUsage");
  const dom = await page.evaluate(() => document.getElementsByTagName("*").length);
  await page.evaluate(() => { const c = document.querySelector(".req"); if (c) c.__mark = 1; });
  const m0 = (await cdp.send("Performance.getMetrics")).metrics.find(m => m.name === "ScriptDuration").value;
  await sleep(10000);
  const m1 = (await cdp.send("Performance.getMetrics")).metrics.find(m => m.name === "ScriptDuration").value;
  const kept = await page.evaluate(() => { const c = document.querySelector(".req"); return !!(c && c.__mark); });
  await ctx.close();
  return { card_ms, fcp_ms, heap_kb: heap.usedSize / 1024, dom, poll_ms: ((m1 - m0) * 1000) / 5, kept, errors };
}

const browser = await chromium.launch();
const out = {};
fs.mkdirSync(path.join(here, "results", "raw"), { recursive: true });
let port = 8850;
for (const name of names) {
  const srv = await serve(name, ++port);
  const runs = [];
  try {
    await once(browser, `http://127.0.0.1:${port}/`); // warm the server and the browser binary, not the page's cache
    for (let i = 0; i < RUNS; i++) runs.push(await once(browser, `http://127.0.0.1:${port}/`));
  } finally { srv.kill(); }
  fs.writeFileSync(path.join(here, "results", "raw", name + ".json"), JSON.stringify(runs, null, 1));
  const pick = k => median(runs.map(r => r[k]));
  out[name] = { card_ms: pick("card_ms"), fcp_ms: pick("fcp_ms"), heap_kb: pick("heap_kb"), dom: pick("dom"), poll_ms: pick("poll_ms"),
    kept: runs.every(r => r.kept), errors: [...new Set(runs.flatMap(r => r.errors))] };
  console.error(name, JSON.stringify(out[name]));
}
await browser.close();
fs.writeFileSync(path.join(here, "results", "runtime.json"), JSON.stringify(out, null, 1));
console.log("| candidate | first card (ms) | FCP (ms) | heap (KB) | elements | script per poll (ms) | cards kept | errors |");
console.log("|---|---|---|---|---|---|---|---|");
for (const [n, r] of Object.entries(out)) console.log(`| ${n} | ${Math.round(r.card_ms)} | ${Math.round(r.fcp_ms)} | ${Math.round(r.heap_kb)} | ${r.dom} | ${r.poll_ms.toFixed(1)} | ${r.kept ? "yes" : "NO"} | ${r.errors.length ? r.errors.join("; ") : "none"} |`);

// Do the candidates show the same thing? Each one's three screens, as the visible text a person reads
// (innerText), compared with the first candidate's, line by line. Times are masked: each candidate's
// server starts at its own moment, so "4 min ago" may read "5 min ago" elsewhere. Also compared:
// which buttons, links and disclosures each screen has, by their text.
//
//   node parity.mjs [reference] [candidate...]      (default: preact against every other */dist)
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)("playwright");

const here = path.dirname(fileURLToPath(import.meta.url));
let names = process.argv.slice(2);
if (!names.length) names = ["preact", ...fs.readdirSync(here).filter(d => d !== "preact" && fs.existsSync(path.join(here, d, "dist", "index.html"))).sort()];
const SCREENS = [["inbox", ""], ["agents", "#agents"], ["agent", "#agent/run_01JDRELEASEQQQQQQQQQQQQQQQ"]];
const mask = t => t.replace(/\b\d+ (s|min|h|days?) ago\b/g, "<ago>").replace(/\bin \d+ (s|min|h|days?)\b/g, "<in>")
  .replace(/\bjust now\b/g, "<ago>").replace(/\b([A-Z][a-z]{2} )?\d\d:\d\d\b/g, "<clock>").replace(/\b\d{1,2} [A-Z][a-z]{2} \d\d:\d\d\b/g, "<clock>");

async function grab(browser, name, port) {
  const srv = spawn(process.execPath, [path.join(here, "serve.mjs"), name, String(port)], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise(r => srv.stdout.once("data", r));
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const out = {};
  try {
    for (const [screen, hash] of SCREENS) {
      await page.goto(`http://127.0.0.1:${port}/${hash}`);
      await page.waitForTimeout(1500);
      out[screen] = await page.evaluate(() => {
        const main = document.querySelector("main") || document.body;
        // Open every disclosure, so their contents are compared too.
        for (const d of main.querySelectorAll("details")) d.open = true;
        const controls = [...main.querySelectorAll("button, a, summary")].filter(e => e.checkVisibility()).map(e => e.tagName.toLowerCase() + ": " + e.innerText.trim().replace(/\s+/g, " "));
        return { text: main.innerText, controls };
      });
    }
  } finally { await page.close(); srv.kill(); }
  for (const s of Object.values(out)) { s.text = mask(s.text).split("\n").map(l => l.trim()).filter(Boolean); s.controls = s.controls.map(mask); }
  return out;
}

const browser = await chromium.launch();
let port = 8890;
const ref = await grab(browser, names[0], ++port);
let differ = 0;
for (const name of names.slice(1)) {
  const got = await grab(browser, name, ++port);
  for (const [screen] of SCREENS) {
    for (const k of ["text", "controls"]) {
      const a = ref[screen][k], b = got[screen][k];
      const missing = a.filter(l => !b.includes(l)), extra = b.filter(l => !a.includes(l));
      if (missing.length || extra.length) {
        differ++;
        console.log(`${name} / ${screen} / ${k}: ${missing.length} missing, ${extra.length} extra`);
        for (const l of missing.slice(0, 8)) console.log("   - " + l.slice(0, 140));
        for (const l of extra.slice(0, 8)) console.log("   + " + l.slice(0, 140));
      }
    }
  }
  if (!differ) console.log(`${name}: same as ${names[0]}`);
}
await browser.close();
process.exitCode = differ ? 1 : 0;

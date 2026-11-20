// Every measure of every candidate in one table: results/all.md and results/all.json.
//
//   node combine.mjs
//
// Reads what the other scripts wrote: results/runtime.json and results/raw/ (measure.mjs, throttled),
// results/runtime-unthrottled.json and results/raw-unthrottled/ (UNTHROTTLED=1 measure.mjs),
// results/static.md (static.sh) and results/complexity.json (complexity.mjs). The no-build variants
// have no package to install, so their sizes are measured here: each file the browser loads, gzipped
// on its own, summed. Their code is their built twin's (`lit`, `vanilla`), so they share its code
// measures.
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const R = p => path.join(here, "results", p);
const json = p => JSON.parse(fs.readFileSync(R(p), "utf8"));
const gz = f => zlib.gzipSync(fs.readFileSync(f), { level: 9 }).length;

const runtime = json("runtime.json"), fast = json("runtime-unthrottled.json"), cx = json("complexity.json");
const range = (dir, n) => {
  const f = R(path.join(dir, n + ".json"));
  if (!fs.existsSync(f)) return null;
  const c = JSON.parse(fs.readFileSync(f, "utf8")).map(r => r.card_ms);
  return [Math.round(Math.min(...c)), Math.round(Math.max(...c))];
};
// static.sh's table, by candidate.
const stat = {};
for (const l of fs.readFileSync(R("static.md"), "utf8").split("\n").slice(2)) {
  const c = l.split("|").map(x => x.trim());
  if (c.length < 10) continue;
  const name = c[1].startsWith("baseline") ? "baseline" : c[1];
  const [, all, runtimePkgs] = /^(\d+) \((\d+)\)$/.exec(c[4]) || [];
  stat[name] = { js: +c[2], css: +c[3], pkgs: +all, shipped: +runtimePkgs, node_modules: c[6], build_s: c[7], same: c[8] };
}
// The reference: the console that serve.mjs served for it, on this checkout, as it is today.
{
  const st = path.join(here, "../../crates/wicket-cli/src/serve/static");
  stat.baseline = { js: gz(path.join(st, "console.js")), css: gz(path.join(st, "console.css")), pkgs: 0, shipped: 0, node_modules: "0", build_s: "0 (none)", same: "yes (no build)" };
}
for (const n of ["lit-nobuild", "vanilla-nobuild"]) {
  const files = [];
  (function list(d) { for (const f of fs.readdirSync(d)) { const p = path.join(d, f); fs.statSync(p).isDirectory() ? list(p) : files.push(p); } })(path.join(here, n, "dist"));
  stat[n] = {
    js: files.filter(f => f.endsWith(".js")).reduce((s, f) => s + gz(f), 0), css: gz(path.join(here, n, "dist", "app.css")),
    pkgs: 0, shipped: n === "lit-nobuild" ? 1 : 0, node_modules: "0", build_s: "0 (none)", same: "yes (no build)",
  };
}
const label = {
  "baseline": "today's console on main (reference)", "vanilla": "plain JS, esbuild", "vanilla-nobuild": "plain JS, no build",
  "lit": "Lit (lit-html), Vite", "lit-esbuild": "Lit (lit-html), esbuild", "lit-nobuild": "Lit (lit-html), no build (4 files committed)",
  "preact": "Preact, Vite", "preact-esbuild": "Preact, esbuild", "solid": "Solid, Vite (Babel)", "solid-h": "Solid, esbuild (no Babel)",
  "svelte": "Svelte, Vite", "vue": "Vue, Vite",
};
// Dropped from the comparison by the operator after the first results (2026-11-20): about 0.5 s
// slower to the first card on a slow phone, the two largest downloads, and each needs its compiler.
// Their numbers stay in runtime.md and static.md.
const DROPPED = new Set(["svelte", "vue"]);
const nodeBuild = n => !["baseline", "vanilla-nobuild", "lit-nobuild"].includes(n);
const code = n => cx[{ "vanilla-nobuild": "vanilla", "lit-nobuild": "lit", "lit-esbuild": "lit", "preact-esbuild": "preact", "solid-h": "solid" }[n] || n];

const rows = Object.keys(runtime).filter(n => label[n] && !DROPPED.has(n)).map(n => {
  const t = runtime[n], u = fast[n] || {}, s = stat[n] || {}, c = code(n) || {};
  return {
    candidate: label[n], id: n,
    card_ms: Math.round(t.card_ms), card_range: range("raw", n), fcp_ms: Math.round(t.fcp_ms), poll_ms: +t.poll_ms.toFixed(1),
    heap_kb: Math.round(t.heap_kb), dom: t.dom, kept: t.kept, errors: (t.errors || []).length,
    fast_card_ms: u.card_ms === undefined ? null : Math.round(u.card_ms), fast_fcp_ms: u.fcp_ms === undefined ? null : Math.round(u.fcp_ms),
    js_gzip: s.js, css_gzip: s.css, pkgs: s.pkgs, shipped: s.shipped, node_modules: s.node_modules, build_s: s.build_s, same_bytes: s.same,
    node_build: nodeBuild(n),
    lines: n === "baseline" ? null : c.lines, size: c.size ?? null, branches: c.branches ?? null, worst: c.worst ?? null,
    writes: c.writes ?? null, dom_calls: c.dom ?? null,
  };
}).sort((a, b) => a.card_ms - b.card_ms);

fs.writeFileSync(R("all.json"), JSON.stringify(rows, null, 1));
const v = x => x === null || x === undefined ? "–" : x;
const head = ["candidate", "first card, phone (ms)", "range of 7", "first paint, phone (ms)", "script per poll, phone (ms)", "JS heap (KB)", "elements",
  "first card, desktop (ms)", "JS gzip (B)", "CSS gzip (B)", "npm packages (shipped)", "node_modules", "clean build (s)", "Node needed to build",
  "size (nodes)", "branches", "worst unit", "writes by hand", "DOM calls"];
const out = ["| " + head.join(" | ") + " |", "|" + head.map(() => "---").join("|") + "|"];
for (const r of rows) out.push("| " + [r.candidate, r.card_ms, r.card_range ? r.card_range.join("–") : "–", r.fcp_ms, r.poll_ms, r.heap_kb, r.dom,
  v(r.fast_card_ms), v(r.js_gzip), v(r.css_gzip), r.pkgs === undefined ? "–" : `${r.pkgs} (${r.shipped})`, v(r.node_modules), v(r.build_s),
  r.node_build ? "yes" : "no", v(r.size), v(r.branches), v(r.worst), v(r.writes), v(r.dom_calls)].join(" | ") + " |");
fs.writeFileSync(R("all.md"), out.join("\n") + "\n");
console.log(out.join("\n"));

// The same production treatment as the framework builds: one bundle, minified, ES2022, no source map.
// esbuild only (no framework, no plugin); the page and its CSS are copied, the CSS minified too.
import * as esbuild from "esbuild";
import fs from "node:fs";
fs.rmSync("dist", { recursive: true, force: true });
await esbuild.build({ entryPoints: ["src/app.js"], bundle: true, minify: true, target: "es2022", format: "iife", outfile: "dist/app.js", legalComments: "none" });
fs.copyFileSync("index.html", "dist/index.html");

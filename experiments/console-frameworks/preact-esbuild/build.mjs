// ../preact's source, unchanged, built with esbuild alone: one bundle, minified, ES2022, no source map.
import * as esbuild from "esbuild";
import fs from "node:fs";
fs.rmSync("dist", { recursive: true, force: true });
await esbuild.build({ entryPoints: ["src/main.jsx"], bundle: true, minify: true, target: "es2022", format: "esm", outfile: "dist/app.js",
  legalComments: "none", jsx: "automatic", jsxImportSource: "preact" });
fs.writeFileSync("dist/index.html", '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n<title>wicket</title>\n<link rel="stylesheet" href="/app.css">\n<script type="module" src="/app.js"></script>\n</head>\n<body>\n</body>\n</html>\n');

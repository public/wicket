// esbuild only: no Vite, no Babel, no Solid compiler. esbuild turns the JSX into h(tag, props, ...children)
// calls to solid-js/h, so reactivity comes from the functions written in src/main.jsx.
import * as esbuild from "esbuild";
import fs from "node:fs";
fs.rmSync("dist", { recursive: true, force: true });
const common = { bundle: true, minify: true, target: "es2022", legalComments: "none", logLevel: "warning" };
await esbuild.build({ ...common, entryPoints: ["src/main.jsx"], outfile: "dist/app.js", format: "esm",
  jsx: "transform", jsxFactory: "h", jsxFragment: "h.Fragment" });
await esbuild.build({ ...common, entryPoints: ["../shared/console.css"], outfile: "dist/app.css" });
fs.copyFileSync("index.html", "dist/index.html");

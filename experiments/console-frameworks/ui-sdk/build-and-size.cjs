// Bundles @ui-sdk/web's dialog, tabs and toast with esbuild (minified, ES2022) into dist/app.js and
// prints each one's size, gzipped. Then `node check.cjs` loads them under the console's CSP.
const esbuild = require("esbuild"), zlib = require("zlib"), fs = require("fs");
(async () => {
  fs.mkdirSync("dist", { recursive: true });
  for (const [n, code] of [["dialog+tabs+toast", fs.readFileSync("app.js", "utf8")], ["dialog", `import "@ui-sdk/web/dialog"`], ["tabs", `import "@ui-sdk/web/tabs"`], ["toast", `import "@ui-sdk/web/toast"`]]) {
    const r = await esbuild.build({ stdin: { contents: code, resolveDir: __dirname }, bundle: true, minify: true, format: "iife", target: "es2022", write: false, legalComments: "none" });
    const b = r.outputFiles[0].contents;
    console.log(n.padEnd(20), "minified", b.length, "gzip", zlib.gzipSync(b, { level: 9 }).length);
    if (n === "dialog+tabs+toast") fs.writeFileSync("dist/app.js", b);
  }
  console.log("web.css gzip", zlib.gzipSync(fs.readFileSync(require.resolve("@ui-sdk/core/web.css")), { level: 9 }).length);
})();

// Serves one prototype's dist/ (or the plain-JS console itself, "baseline") against the console
// preview's mock API, with the console's CSP.
//
//   node serve.mjs <dir|baseline> [port]
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = createRequire(import.meta.url)(path.join(here, "../../ci/console-preview/fixture.js"));
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
  "manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const [which, portArg] = process.argv.slice(2);
const port = Number(portArg || 8800);
const T0 = Date.now();
const STATIC = path.join(here, "../../crates/wicket-cli/src/serve/static");
const types = { ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".html": "text/html; charset=utf-8", ".svg": "image/svg+xml" };

function file(res, f) {
  if (!fs.existsSync(f)) { res.writeHead(404, { "content-security-policy": CSP }); return res.end("not found"); }
  res.writeHead(200, { "content-type": types[path.extname(f)] || "application/octet-stream", "content-security-policy": CSP, "cache-control": "no-store" });
  res.end(fs.readFileSync(f));
}
const json = (res, v) => { res.writeHead(200, { "content-type": "application/json", "content-security-policy": CSP, "cache-control": "no-store" }); res.end(JSON.stringify(v)); };

http.createServer((req, res) => {
  const p = new URL(req.url, "http://x").pathname;
  if (p === "/api/me") return json(res, { who: { state: "operator", credential: "AbCd" } });
  // Timestamps fixed at the server's start, as a ledger's are; only `now` moves.
  if (p === "/api/state") return json(res, { ...fx.state(T0), now: Math.floor(Date.now() / 1000) });
  if (p === "/api/push") return json(res, fx.push);
  if (p === "/api/policy") return json(res, fx.policy);
  const m = /^\/api\/runs\/([^/]+)\/authority$/.exec(p);
  if (m) return json(res, fx.authority(decodeURIComponent(m[1])));
  if (which === "baseline") {
    if (p === "/" || p === "/index.html") {
      const html = fs.readFileSync(path.join(STATIC, "console.html"), "utf8").replace("{{css}}", "/static/console.css").replace("{{js}}", "/static/console.js")
        .replace(/ integrity="\{\{(css|js)_sri\}\}"/g, "");
      res.writeHead(200, { "content-type": types[".html"], "content-security-policy": CSP, "cache-control": "no-store" });
      return res.end(html);
    }
    return file(res, path.join(STATIC, path.basename(p)));
  }
  const dist = path.resolve(here, which, "dist");
  if (p === "/" || p === "/index.html") return file(res, path.join(dist, "index.html"));
  return file(res, path.join(dist, path.normalize(p).replace(/^(\.\.[/\\])+/, "")));
}).listen(port, "127.0.0.1", () => console.log(`${which} on http://127.0.0.1:${port}/`));

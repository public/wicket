"use strict";
// A preview of the console (crates/wicket-cli/src/serve/static) against a mock of its JSON API,
// with made-up data (fixture.js). For looking at the page, not for testing wicket: nothing here is
// signed or checked, and every action "succeeds".
//
//   node ci/console-preview/server.js [PORT] [--assets DIR]
//
// With --assets, it serves the console as `wicket serve` sends it, from what `wicket dev
// console-assets DIR` wrote: the page, its minified, content-hashed files and the same security
// headers (headers.json), so the browser tests (ci/console-browsers.sh) check what ships. Without
// it, the source files, read fresh on each load.
//
// The scenario is a cookie, set from the page's query: /?fixture=full (the default), empty,
// signedout, bootstrap, stale (every poll fails, after a first good one) or expired (the next poll
// answers 401). The console's own CSP is sent, so an inline style or script shows as a violation.
const http = require("http");
const fs = require("fs");
const path = require("path");
const fx = require("./fixture.js");

const STATIC = path.join(__dirname, "../../crates/wicket-cli/src/serve/static");
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
  "manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; " +
  "require-trusted-types-for 'script'; trusted-types lit-html vue";
const args = process.argv.slice(2);
const ai = args.indexOf("--assets");
const ASSETS = ai >= 0 ? path.resolve(args.splice(ai, 2)[1]) : null;
const port = Number(args[0] || process.env.PORT || 8790);
// The security headers: as wicket sends them with --assets; otherwise the CSP, kept equal to
// serve/web.rs's by hand.
const HEADERS = ASSETS ? JSON.parse(fs.readFileSync(path.join(ASSETS, "headers.json"), "utf8")) : { "content-security-policy": CSP };
const T0 = Date.now();

const types = { ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".webmanifest": "application/manifest+json" };
// The served path of a page and of the service worker are fixed; everything else under /static/ is
// named by hash in the dump, and its type is its extension's.
const cookie = req => Object.fromEntries((req.headers.cookie || "").split(/;\s*/).filter(Boolean).map(c => c.split("=")));
const polls = new Map();

// With --assets, a file's Brotli copy (`<file>.br`, as wicket dev console-assets writes it) to a
// browser that accepts `br`, as wicket sends it (#574).
function sendFile(req, res, type, f) {
  const accepts = /(^|,)\s*(br|\*)\s*(;\s*q=(?!0(\.0+)?\s*(,|$))[\d.]+)?\s*(,|$)/i.test(req.headers["accept-encoding"] || "");
  if (ASSETS && accepts && fs.existsSync(f + ".br")) return send(res, 200, type, fs.readFileSync(f + ".br"), { "content-encoding": "br", vary: "accept-encoding" });
  return send(res, 200, type, fs.readFileSync(f), ASSETS && fs.existsSync(f + ".br") ? { vary: "accept-encoding" } : undefined);
}

function page(req, res) {
  if (ASSETS) return sendFile(req, res, "text/html; charset=utf-8", path.join(ASSETS, "index.html"));
  // As serve/web.rs builds it, without the content hashes (the files are read fresh on each load).
  const html = fs.readFileSync(path.join(STATIC, "console.html"), "utf8")
    .replace("{{css}}", "/static/console.css").replace("{{js}}", "/static/console.js")
    // The modules as written (#574); they import lit-html from static/vendor/ themselves.
    .replace("{{modules}}", ["inbox.js", "agents.js", "activity.js"].map(m => '<script type="module" src="/static/' + m + '"></script>').join("\n"))
    // The manifest and icons by their source names (wicket names them by hash).
    .replace("{{manifest}}", "/manifest.webmanifest").replace("{{icon_svg}}", "/static/icon.svg")
    .replace("{{apple_touch_icon}}", "/static/apple-touch-icon.png")
    .replace(/ integrity="\{\{(css|js)_sri\}\}"/g, "");
  send(res, 200, "text/html; charset=utf-8", html);
}
function send(res, status, type, body, extra) {
  res.writeHead(status, { "content-type": type, ...HEADERS, "cache-control": "no-store", ...(extra || {}) });
  res.end(body);
}
const json = (res, v, status) => send(res, status || 200, "application/json", JSON.stringify(v));

// What begin returns: the action as the server would build it, enough for the sheet.
function begin(body, scenario) {
  const s = fx.state(Date.now());
  let a = { ...body };
  if (body.action === "decide") {
    const p = s.pending.find(x => x.id === body.id) || s.pending[0];
    const approve = body.decision !== "deny";
    const uses = p.once_terms.uses === null ? null : body.unlimited ? null : 1;
    const ttl = p.once_terms.uses === null ? p.once_terms.ttl_secs : body.ttl_secs;
    a = { v: 1, action: "decide", tenant: s.tenant, request: p.id, run: p.run, zone: p.zone, method: p.method, host: p.host, path: p.path, risk: p.risk,
      prefix: p.scope_prefix, path_prefix: null, scope: "run", decision: approve ? "approve" : "deny", uses: approve ? uses : null, ttl_secs: approve ? ttl : null,
      agent: p.identity.id, identity_sha256: "ab12", identity_verified: true,
      requested_by: (p.attribution || []).flatMap(x => x.requesters.map(r => r.agent)),
      effect: { v: 1, kind: p.host === "wicket.internal" ? p.method.toLowerCase() : "access", tenant: s.tenant, zone: p.zone, run: p.run, requested_by: [], method: p.method, host: p.host, path: p.path,
        prefix: p.scope_prefix, risk: p.risk, args_sha256: p.args_sha256 || null, terms: approve ? { uses, ttl_secs: ttl } : null },
      effect_sha256: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
      blast: p.scope_prefix && approve ? { widens: ["every path under registry.npmjs.org/@acme-internal/"], examples: ["GET registry.npmjs.org/@acme-internal/secrets-loader"], covered: 14, recent: 20, zone_rules: [] } : null };
    if (p.method === "UPDATE" && approve) a.update = { applies: true, sha256: p.path.slice(6), artifact: "wicket-x86_64-linux", size: 23068672, commit_said: "a1b2c3d", nodes: ["node-ams-02", "local"] };
  }
  if (scenario === "begin-fails") return null;
  return { action: a, publicKey: { challenge: "AAAA", allowCredentials: [] }, expires_in_ms: 120000 };
}

http.createServer((req, res) => {
  const url = new URL(req.url, "http://preview");
  const p = url.pathname;
  let scenario = cookie(req).fixture || "full";
  if (p === "/" || p === "/index.html") {
    const want = url.searchParams.get("fixture");
    if (want) { res.setHeader("set-cookie", "fixture=" + want + "; Path=/; SameSite=Strict"); scenario = want; polls.set(want, 0); }
    return page(req, res);
  }
  // A run's session view (#327), as wicket sends it; only with --assets (it is a separate build).
  if (p === "/session" && ASSETS) return sendFile(req, res, "text/html; charset=utf-8", path.join(ASSETS, "session.html"));
  if (p.startsWith("/static/") || p === "/sw.js" || p === "/manifest.webmanifest") {
    // With --assets, the file at its served path (the dump holds nothing else); else the source, by
    // its path under static/ (the modules import lit-html from static/vendor/).
    const rel = path.normalize(p).replace(/^([/\\]|\.\.[/\\])+/, "");
    const f = ASSETS ? path.join(ASSETS, rel) : path.join(STATIC, rel.replace(/^static[/\\]/, ""));
    if (!fs.existsSync(f)) return send(res, 404, "text/plain", "not found");
    // From source, a console module's `from "lit-html…"` points at the vendored files, as build.rs
    // rewrites it for wicket (#574).
    if (!ASSETS && f.endsWith(".js") && !rel.includes("vendor")) {
      const up = "../".repeat(rel.replace(/^static[/\\]/, "").split(/[/\\]/).length - 1) || "./";
      const js = fs.readFileSync(f, "utf8").replace(/((?:from|import)\s*)(["'])lit-html(\/[^"']*)?\2/g,
        (_, kw, q, sub) => kw + q + up + "vendor/lit-html" + (sub || "/lit-html.js") + q);
      return send(res, 200, types[".js"], js);
    }
    return sendFile(req, res, types[path.extname(f)] || "application/octet-stream", f);
  }
  if (p === "/api/me") {
    if (scenario === "signedout" || (scenario === "expired" && (polls.get(scenario) || 0) > 1)) return json(res, { error: "sign in" }, 401);
    return json(res, { who: scenario === "bootstrap" ? { state: "bootstrap" } : { state: "operator", credential: "AbCd" } });
  }
  if (p === "/api/state") {
    const n = (polls.get(scenario) || 0) + 1; polls.set(scenario, n);
    if (scenario === "stale" && n > 1) return json(res, { error: "bad gateway" }, 502);
    if (scenario === "expired" && n > 1) return json(res, { error: "sign in" }, 401);
    // Timestamps fixed at the server's start, as a ledger's are; only `now` moves.
    return json(res, { ...(scenario === "empty" ? fx.empty(T0) : fx.state(T0)), now: Math.floor(Date.now() / 1000) });
  }
  if (p === "/api/push") return json(res, scenario === "empty" ? { ...fx.push, devices: [] } : fx.push);
  if (p === "/api/policy") return json(res, fx.policy);
  let m;
  if ((m = /^\/api\/runs\/([^/]+)\/authority$/.exec(p))) return json(res, fx.authority(decodeURIComponent(m[1])));
  if ((m = /^\/api\/explain\/(\d+)$/.exec(p))) return json(res, fx.explain(Number(m[1])));
  if ((m = /^\/api\/manifests\/([^/]+)\/([^/]+)$/.exec(p)) && req.method === "GET") return json(res, fx.manifestView(m[1], decodeURIComponent(m[2])));
  if (req.method === "POST") {
    let data = "";
    req.on("data", c => { data += c; });
    req.on("end", () => {
      let body = {};
      try { body = JSON.parse(data || "{}"); } catch (e) { /* empty */ }
      if (p === "/api/action/begin") { const b = begin(body, scenario); return b ? json(res, b) : json(res, { error: "no such request" }, 404); }
      if (p === "/api/manifests/check") return json(res, { valid: true, sha256: "aa", saved_sha256: "bb", diff: { widens: false, widening: [], changes: ["zone.reach[0].methods: + POST"] } });
      return json(res, { ok: "done (preview: nothing was changed)" });
    });
    return;
  }
  send(res, 404, "text/plain", "not found");
}).listen(port, "127.0.0.1", () => console.log("console preview on http://127.0.0.1:" + port + "/"));

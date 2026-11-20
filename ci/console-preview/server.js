"use strict";
// A preview of the console (crates/wicket-cli/src/serve/static) against a mock of its JSON API,
// with made-up data (fixture.js). For looking at the page, not for testing wicket: nothing here is
// signed or checked, and every action "succeeds".
//
//   node ci/console-preview/server.js [PORT]
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
  "manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const port = Number(process.argv[2] || process.env.PORT || 8790);

const types = { ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".webmanifest": "application/manifest+json" };
const cookie = req => Object.fromEntries((req.headers.cookie || "").split(/;\s*/).filter(Boolean).map(c => c.split("=")));
const polls = new Map();

function page(res) {
  // As serve/web.rs builds it, without the content hashes (the files are read fresh on each load).
  const html = fs.readFileSync(path.join(STATIC, "console.html"), "utf8")
    .replace("{{css}}", "/static/console.css").replace("{{js}}", "/static/console.js")
    .replace(/ integrity="\{\{(css|js)_sri\}\}"/g, "");
  send(res, 200, "text/html; charset=utf-8", html);
}
function send(res, status, type, body, extra) {
  res.writeHead(status, { "content-type": type, "content-security-policy": CSP, "cache-control": "no-store", ...(extra || {}) });
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
    return page(res);
  }
  if (p.startsWith("/static/") || p === "/sw.js" || p === "/manifest.webmanifest") {
    const f = path.join(STATIC, path.basename(p));
    if (!fs.existsSync(f)) return send(res, 404, "text/plain", "not found");
    return send(res, 200, types[path.extname(f)] || "application/octet-stream", fs.readFileSync(f));
  }
  if (p === "/api/me") {
    if (scenario === "signedout" || (scenario === "expired" && (polls.get(scenario) || 0) > 1)) return json(res, { error: "sign in" }, 401);
    return json(res, { who: scenario === "bootstrap" ? { state: "bootstrap" } : { state: "operator", credential: "AbCd" } });
  }
  if (p === "/api/state") {
    const n = (polls.get(scenario) || 0) + 1; polls.set(scenario, n);
    if (scenario === "stale" && n > 1) return json(res, { error: "bad gateway" }, 502);
    if (scenario === "expired" && n > 1) return json(res, { error: "sign in" }, 401);
    return json(res, scenario === "empty" ? fx.empty(Date.now()) : fx.state(Date.now()));
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

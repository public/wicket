// Try a built view in a browser against a real console, on the console's own origin (its cookie,
// Origin checks and passkeys all need that), until a view is embedded in the binary:
//
//   wicket serve --listen 127.0.0.1:8788 --origin http://localhost:8787
//   node devproxy/serve.mjs assistant-ui/dist      # or acp-ui/dist
//   open http://localhost:8787/session/?run=<run id>
//
// /session/* is the view's files, under the console's CSP; everything else (the console, its API,
// the ACP WebSocket) goes to the console unchanged, Host included. No dependencies.
import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";

const [dist = "assistant-ui/dist", listen = "8787", upstream = "8788"] = process.argv.slice(2);
const root = path.resolve(dist);
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
  "manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml" };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/session" || url.pathname.startsWith("/session/")) {
    const rel = url.pathname.replace(/^\/session\/?/, "") || "index.html";
    const file = path.join(root, path.normalize(rel));
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, { "content-type": types[path.extname(file)] ?? "application/octet-stream", "content-security-policy": CSP, "x-content-type-options": "nosniff" });
    fs.createReadStream(file).pipe(res);
    return;
  }
  const p = http.request({ host: "127.0.0.1", port: upstream, method: req.method, path: req.url, headers: req.headers }, (r) => {
    res.writeHead(r.statusCode ?? 502, r.headers);
    r.pipe(res);
  });
  p.on("error", () => res.writeHead(502).end("console unreachable"));
  req.pipe(p);
});

// WebSocket upgrades: the raw bytes both ways.
server.on("upgrade", (req, socket, head) => {
  const up = net.connect(Number(upstream), "127.0.0.1", () => {
    const lines = [`${req.method} ${req.url} HTTP/1.1`, ...Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`), "", ""];
    up.write(lines.join("\r\n"));
    up.write(head);
    up.pipe(socket);
    socket.pipe(up);
  });
  up.on("error", () => socket.destroy());
  socket.on("error", () => up.destroy());
});

server.listen(Number(listen), "127.0.0.1", () => console.log(`http://localhost:${listen}/session/?run=<run id>  (console at 127.0.0.1:${upstream})`));

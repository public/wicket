#!/usr/bin/env bash
# The console's session view (#327, web/session): builds its bundle from the committed lockfile, and
# checks what the binary embeds (crates/wicket-cli/build.rs reads it from WICKET_SESSION_VIEW).
#
#   ci/session-view.sh [--test]
#
# Needs Node (>= 22.12, or 20.19+) and npm on PATH; CI installs a pinned, checksum-verified Node.
# Steps:
#   - `npm ci --ignore-scripts` (exact versions with integrity hashes; nothing from a package runs at
#     install), `npm run build` (type-check, then vite) into web/session/dist;
#   - the licences in the lockfile: permissive for what ships (MIT, ISC, BSD, Apache-2.0, 0BSD,
#     BlueOak); build tools may also be MPL-2.0;
#   - the bundle is exactly session.js and session.css (and vite's index.html, not embedded), with
#     no eval (the console's CSP refuses it) and no source maps;
#   - reproducible (#190): node_modules and dist removed, `npm ci` and the build again, the same
#     bytes. The bundle's sha256 is printed (the signed build's log keeps it);
#   - with --test: the view's client against the real endpoint (the ignored endpoint test, under
#     node), and the serve tests with the bundle embedded (WICKET_SESSION_VIEW_REQUIRED).
# Prints the dist directory to use as WICKET_SESSION_VIEW on its last line.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
view=$repo/web/session
test=false
[ "${1:-}" = --test ] && test=true

echo "node $(node --version), npm $(npm --version)" >&2
build() {
  rm -rf "$view/node_modules" "$view/dist" "$view/check-dist"
  (cd "$view" && npm ci --ignore-scripts --no-audit --no-fund >&2 && npm run --silent build >&2)
}
digest() { (cd "$view/dist" && sha256sum session.js session.css); }

build
first=$(digest)

# Licences: every package the lockfile installs. What ships in the bundle (the runtime packages)
# must be permissive; the build tools (dev) may also be MPL-2.0 (lightningcss, vite's CSS minifier).
node -e '
  const lock = require(process.argv[1]);
  const ok = /^(MIT|ISC|0BSD|BSD-2-Clause|BSD-3-Clause|Apache-2\.0|BlueOak-1\.0\.0|\(MIT OR Apache-2\.0\)|MIT OR Apache-2\.0)$/;
  const allowed = (p) => ok.test(String(p.license ?? "")) || (p.dev === true && p.license === "MPL-2.0");
  const bad = Object.entries(lock.packages).filter(([k, p]) => k && !allowed(p));
  if (bad.length) { for (const [k, p] of bad) console.error(`licence: ${k}: ${p.license ?? "none"}`); process.exit(1); }
' "$view/package-lock.json"

# What the binary embeds, and nothing the CSP would refuse.
files=$(cd "$view/dist" && find . -type f | sort | tr '\n' ' ')
[ "$files" = "./index.html ./session.css ./session.js " ] || { echo "unexpected files in dist: $files" >&2; exit 1; }
if grep -qE 'eval\(|new Function|sourceMappingURL' "$view/dist/session.js"; then
  echo "session.js uses eval, new Function or a source map" >&2
  exit 1
fi

# The same bytes from a fresh install.
build
second=$(digest)
if [ "$first" != "$second" ]; then
  printf 'not reproducible:\n%s\n%s\n' "$first" "$second" >&2
  exit 1
fi
echo "session view bundle (reproduced):" >&2
echo "$first" >&2

if $test; then
  (cd "$view" && npm run --silent check:build >&2)
  cd "$repo"
  WICKET_SESSION_VIEW=$view/dist WICKET_SESSION_VIEW_REQUIRED=1 cargo test -p wicket-cli --bin wicket --locked -- serve:: --include-ignored >&2
fi
echo "$view/dist"

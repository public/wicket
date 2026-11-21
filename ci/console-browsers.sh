#!/usr/bin/env bash
# The console in real browsers (#574): builds wicket, writes the console as `wicket serve` sends it
# (`wicket dev console-assets`: minified, content-hashed, under its CSP with Trusted Types enforced),
# serves that against the preview's mock API (ci/console-preview), and runs
# ci/console-browsers/test.mjs (the whole page, and a run's session view), inbox.mjs (the request
# cards, with the API answered in the page) and agents.mjs (the Agents view and an agent's page) in
# each browser named (default: chromium firefox webkit).
# With WICKET_SESSION_VIEW set (ci/session-view.sh prints it), wicket embeds the built session view
# and that is what is checked; WICKET_SESSION_VIEW_REQUIRED=1 fails on the placeholder.
#
#   ci/console-browsers.sh [--install] [chromium] [firefox] [webkit]
#
# --install runs `npm ci` in ci/console-browsers and installs the browsers Playwright needs, with
# their system packages (CI does). Without it, an existing node_modules there is used, else a
# Playwright found on NODE_PATH (`npm root -g`), with the browsers it already has.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
install=
if [ "${1:-}" = "--install" ]; then install=1; shift; fi
browsers=("$@")
[ ${#browsers[@]} -gt 0 ] || browsers=(chromium firefox webkit)

cargo build --locked -q -p wicket-cli
assets=$(mktemp -d)
trap 'rm -rf "$assets"; [ -z "${server:-}" ] || kill "$server" 2>/dev/null || true' EXIT
target/debug/wicket dev console-assets "$assets" >/dev/null

if [ -n "$install" ]; then
  (cd ci/console-browsers && npm ci --ignore-scripts --no-audit --no-fund && npx --no-install playwright install --with-deps "${browsers[@]}")
fi
[ -d ci/console-browsers/node_modules ] || export NODE_PATH=${NODE_PATH:-$(npm root -g)}

port=8797
node ci/console-preview/server.js "$port" --assets "$assets" >/dev/null &
server=$!
for _ in $(seq 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
  sleep 0.1
done
node ci/console-browsers/test.mjs "http://127.0.0.1:$port/" "${browsers[@]}"
# The Inbox's cards, with the API answered in the page (inbox.mjs): the checks that moved from
# console_ui.js's fake DOM when the Inbox moved to lit-html.
node ci/console-browsers/inbox.mjs "http://127.0.0.1:$port/" "${browsers[@]}"
# The Agents view and an agent's page, the same way (agents.mjs).
node ci/console-browsers/agents.mjs "http://127.0.0.1:$port/" "${browsers[@]}"

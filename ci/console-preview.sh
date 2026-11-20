#!/usr/bin/env bash
# A preview of the console web UI (crates/wicket-cli/src/serve/static) against a mock of its JSON API
# with made-up data (ci/console-preview/fixture.js), for looking at a change to the page without a
# wicket installation, passkeys or agents. Nothing is signed: every action "succeeds".
#
#   ci/console-preview.sh [--port N]            serve it, until interrupted
#   ci/console-preview.sh --shots DIR [SCENARIO...]
#                                               screenshots into DIR, then stop
#
# Open http://127.0.0.1:8790/?fixture=NAME, with NAME one of full (the default), empty, signedout,
# bootstrap, stale (the poll fails after the first) or expired (the session ends after the first).
# --shots takes each scenario (default: full empty signedout sheet; sheet is an approval sheet open)
# at 1440x900 and on a 390x844 phone (deviceScaleFactor 2), light and dark, and fails if the page
# logs an error (a CSP violation, say) or scrolls sideways. Needs Node, and Playwright for --shots.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
port=8790 shots=
while [ $# -gt 0 ]; do
  case "$1" in
    --port) port=$2; shift ;;
    --shots) shots=$2; shift; shift; break ;;
    -h | --help) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

if [ -z "$shots" ]; then exec node "$here/console-preview/server.js" "$port"; fi
node "$here/console-preview/server.js" "$port" &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
for _ in $(seq 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
  sleep 0.1
done
NODE_PATH=${NODE_PATH:-$(npm root -g 2>/dev/null || true)} node "$here/console-preview/shots.js" "http://127.0.0.1:$port/" "$shots" "$@"

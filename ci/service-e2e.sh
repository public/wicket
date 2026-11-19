#!/usr/bin/env bash
# Per-node services (#579 step 3), end to end: the npm cache (examples/services/npm-cache) on this
# host's own node, and two program boxes whose zones use it. Needs Docker with runsc, the agent image
# and the internet (registry.npmjs.org). No model credential.
#
#   WICKET=target/debug/wicket ci/service-e2e.sh      (IMAGE=tag for another image)
#
# Checks:
#   - `wicket service add` installs it, and `wicket reconcile` starts its instance on the node once a
#     box there uses it;
#   - the box gets npm_config_registry pointing at the cache, is linked to it (its reach covers the
#     cache's), and `npm install left-pad` succeeds through it;
#   - the cache fetched left-pad from the registry once: a second box's install of it is served from
#     the cache's storage;
#   - the boxes themselves made no request to registry.npmjs.org: the cache did;
#   - a box whose zone doesn't reach what the cache does is not linked without a human.
# Boxes are named svc-*; everything is removed at the end.
set -Eeuo pipefail
trap 'echo "service-e2e.sh: line $LINENO: \"$BASH_COMMAND\" returned $?" >&2' ERR

WICKET=${WICKET:-target/debug/wicket}
WICKET=$(realpath "$WICKET")
cd "$(dirname "$0")/.."
DOCKER=${WICKET_DOCKER:-docker}
export WICKET_HOME=${WICKET_HOME:-$(mktemp -d)}
export WICKET_BOX_PREFIX=svc
work=$(mktemp -d)
W() { "$WICKET" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

stop_pid() { [ -n "${1:-}" ] || return 0; kill "$1" 2>/dev/null || return 0; for _ in $(seq 50); do kill -0 "$1" 2>/dev/null || return 0; sleep 0.1; done; kill -9 "$1" 2>/dev/null || true; }
cleanup() {
  local rc=$?
  set +e
  trap - EXIT
  stop_pid "${rec_pid:-}"
  local c
  for c in $($DOCKER ps -aq --filter name=^svc-run- 2>/dev/null); do $DOCKER rm -f "$c" >/dev/null 2>&1; done
  local p; p=$(head -1 "$WICKET_HOME/local-node/serve/serve.pid" 2>/dev/null) && stop_pid "$p"
  pkill_children() { local k; for k in $(jobs -p); do stop_pid "$k"; done; }
  pkill_children
  chmod -R u+w "$work" "$WICKET_HOME" 2>/dev/null
  rm -rf "$work" "$WICKET_HOME"
  exit "$rc"
}
trap cleanup EXIT

image=${IMAGE:-wicket/claude-code:poc}
cp -r examples/services/npm-cache "$work/npm-cache"
sed -i "s|^program:|program:\n  image: $image|" "$work/npm-cache/manifest.yaml"

# A box that uses the cache: it waits for its link, then installs left-pad through it.
user() { # name, reach (yes|no)
  local reach='reach: [{ host: registry.npmjs.org, methods: [GET, HEAD], paths: ["/**"] }]' wait_for=240
  [ "$2" = yes ] || { reach='reach: []'; wait_for=90; }
  cat >"$work/$1.yaml" <<EOF
task: install left-pad through the node's npm cache
program:
  name: $1
  image: $image
  command:
    - sh
    - -c
    - |
      echo "registry=\$(npm config get registry)"
      for i in \$(seq $wait_for); do curl -sf -o /dev/null http://npm-cache.wicket.internal:4873/-/ping && break; sleep 1; done
      cd /workspace && npm init -y >/dev/null && npm install left-pad --no-audit --no-fund && test -f node_modules/left-pad/package.json && echo installed-left-pad
zone:
  name: $1
  uses: [npm-cache]
  $reach
  limits: { memory: 1g, cpus: 1, timeout: 15m }
EOF
}

# A fresh data directory: its identity issuer first, as every suite's.
W identity init --trust-domain ci.wicket.test >/dev/null
W service add "$work/npm-cache/manifest.yaml" | grep -q "service npm-cache installed" || fail "service add"
W service list | grep -q '^npm-cache ' || fail "service list"
ok "wicket service add installed npm-cache"
# The reconciler, as its service would run it: every 5 s here.
W reconcile --every 5s >"$work/reconcile.log" 2>&1 &
rec_pid=$!

user build-a yes
W run "$work/build-a.yaml" >"$work/a.log" 2>&1 || { cat "$work/a.log"; fail "box A"; }
grep -q "registry=http://npm-cache.wicket.internal:4873/" "$work/a.log" || { cat "$work/a.log"; fail "box A's npm_config_registry"; }
grep -q "npm-cache on node local: linked" "$work/a.log" || { cat "$work/a.log"; fail "box A not linked to the cache"; }
grep -q installed-left-pad "$work/a.log" || { cat "$work/a.log"; fail "box A's npm install"; }
grep -q "service_started .*npm-cache on local" "$work/reconcile.log" || { cat "$work/reconcile.log"; fail "the reconciler didn't start the cache"; }
ok "box A got the cache's registry, was linked to it, and installed left-pad through it"

slog=$(ls "$WICKET_HOME"/services/npm-cache/logs/*.log | head -1)
fetched() { grep -c "registry.npmjs.org/left-pad" "$slog" || true; }
n1=$(fetched)
[ "$n1" -ge 1 ] || { cat "$slog"; fail "the cache never fetched left-pad"; }

user build-b yes
W run "$work/build-b.yaml" >"$work/b.log" 2>&1 || { cat "$work/b.log"; fail "box B"; }
grep -q installed-left-pad "$work/b.log" || { cat "$work/b.log"; fail "box B's npm install"; }
[ "$(fetched)" = "$n1" ] || { cat "$slog"; fail "box B's install went to the registry again ($n1 then $(fetched))"; }
ok "box B's install was served from the cache's storage"

runs=$(sed -n 's/^wicket run \(run_[a-z0-9]*\).*/\1/p' "$work/a.log" "$work/b.log")
for r in $runs; do
  if W audit --tail 5000 | grep "$r" | grep egress | grep -q "registry.npmjs.org"; then fail "box $r reached registry.npmjs.org itself"; fi
done
ok "the boxes made no request to registry.npmjs.org: the cache did"

# Using a service is having its reach: a box that doesn't reach what the cache does isn't linked.
user offline no
W run "$work/offline.yaml" >"$work/o.log" 2>&1 &
off_pid=$!
# While the box runs: its link is a pending request (a run that ends withdraws its requests).
pending_link=
for _ in $(seq 60); do
  if W pending | grep -q "LINK"; then pending_link=1; break; fi
  sleep 1
done
wait "$off_pid" || true
[ -n "$pending_link" ] || { cat "$work/o.log"; fail "the link's request was never pending"; }
grep -q "npm-cache on node local: needs approval" "$work/o.log" || { cat "$work/o.log"; fail "a box without the cache's reach was linked, or not asked for"; }
ok "a box without the cache's reach needs a human to be linked to it"
echo "service-e2e.sh: all checks passed"

#!/usr/bin/env bash
# Links demo (issue #6), end to end with gVisor and the scripted mock model: an agent spawns a
# service box (an HTTP server program), connects to it through wicket, fetches a page from it with its
# own code, and cuts the link. Needs Docker with runsc and an agent image built from this tree's
# images/claude-code (wicket-entry adds the link addresses), e.g.:
#
#   wicket image --tag wicket/claude-code:links      # or: docker build -t wicket/claude-code:links images/claude-code
#   WICKET=target/debug/wicket IMAGE=wicket/claude-code:links examples/links/demo.sh
set -euo pipefail

WICKET=$(realpath "${WICKET:-target/debug/wicket}")
IMAGE=${IMAGE:-wicket/claude-code:links}
cd "$(dirname "$0")"

own_home=
if [ -z "${WICKET_HOME:-}" ]; then WICKET_HOME=$(mktemp -d); own_home=$WICKET_HOME; fi
export WICKET_HOME
work=$(mktemp -d)
trap 'kill "${mock_pid:-}" 2>/dev/null || true; rm -rf "$work" ${own_home:+"$own_home"}' EXIT
# A free port for the mock model (the box is shared; a fixed one could collide).
port=${MOCK_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}
sed "s#http://127.0.0.1:9999#http://127.0.0.1:$port#" demo.yaml >"$work/demo.yaml"

"$WICKET" identity init --trust-domain links.wicket.test >/dev/null
printf 'mock-model-credential' | "$WICKET" secret set mock --hosts 127.0.0.1 >/dev/null
"$WICKET" dev mock-llm --listen "127.0.0.1:$port" --command 'bash /workspace/drive.sh' 2>"$work/mock.log" &
mock_pid=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break; sleep 0.2; done

echo "== wicket run demo.yaml"
run_status=0
"$WICKET" run --image "$IMAGE" --workdir box "$work/demo.yaml" 2>&1 | tee "$work/run.log" || run_status=$?

fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
result=$(sed -n 's/^\[wicket\] result.json: //p' "$work/run.log" | tail -1)
field() { jq -r ".$1 // empty" <<<"$result" 2>/dev/null; }
echo "== result: ${result:-<none>}"

check "wicket run exited 0" '[ "$run_status" = 0 ]'
check "the agent started the service box" 'field spawned | grep -q "^started program web"'
check "a box that exposed nothing is refused" 'field stranger | grep -q "^not linked: no box"'
check "connecting to its own child needs no expose or approval" 'field connected | grep -q "(child)"'
check "the link has a name in the box" 'field addr | grep -q "^web.wicket.internal:8000$"'
check "the name resolves to a link address" 'field resolved | grep -q "^198\.18\.1\."'
check "the agent fetched the service's page over the link" '[ "$(field body)" = hello-from-web ]'
check "a second connection works too" '[ "$(field again)" = hello-from-web ]'
check "the agent sees its link" 'field listed | grep -q "\"status\": \"open\""'
check "unlink closes it" 'field unlinked | grep -q "^closed l-"'
check "after unlink, nothing gets through" '[ "$(field after)" != 200 ]'
check "after unlink, the name is gone" '[ -z "$(field after_resolved)" ]'
check "wicket links shows it closed by the agent" '"$WICKET" links | grep "$(field link)" | grep -q "closed: unlinked by an agent"'
check "the audit log records the link" '"$WICKET" audit --tail 200 | grep -q "link.open" && "$WICKET" audit --tail 200 | grep -q "link.close"'
check "the audit chain verifies" '"$WICKET" audit --verify >/dev/null'

if [ "$fail" != 0 ]; then
  echo "== mock model log"; cat "$work/mock.log"
  for f in "$WICKET_HOME"/runs/*/children/*.log; do [ -f "$f" ] && { echo "== $f"; tail -20 "$f"; }; done
  exit 1
fi
echo "per-connection time over the link: $(field per_conn_ms) ms (10 new connections)"
echo "links demo passed"

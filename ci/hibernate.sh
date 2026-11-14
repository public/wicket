#!/usr/bin/env bash
# Hibernate and wake (#70), end to end: Claude Code agents in gVisor boxes, driven by
# `wicket dev mock-llm`. Needs Docker with runsc and the agent image. No model credential.
#
#   WICKET=target/debug/wicket ci/hibernate.sh      (IMAGE=tag for another image)
#   ci/hibernate.sh --node                           the agents' first runs on an enrolled node (#146):
#                                                    localhost, with its own data directory and
#                                                    `wicket node serve`, the ssh hop replaced by
#                                                    WICKET_NODE_SSH, as ci/node-e2e.sh --local does
#
# Checks:
#   - an agent that asks to hibernate (its hibernate tool) does so after its turn: its box is gone
#     and its state is one bundle;
#   - woken (`wicket wake`), it resumes its own session: the mock model sees the earlier turn;
#   - a file under /tmp, one under $HOME, one in the workspace and one in a durable volume all
#     survive hibernate and wake;
#   - a box with a background process isn't hibernated: it goes on running, never paused (#249);
#   - two concurrent wakes: exactly one wins, and the generation goes up by one;
#   - `wicket say` to a hibernated agent wakes it, with the message as its turn;
#   - the zone's model budget is the agent's over all its activations: a wake continues it, and an
#     agent that has spent it isn't woken (and makes no model call);
#   - the agents' state is sealed at rest: every object in the store is encrypted (#146).
# With --node, the state moves between the node and the control host: it is fetched back to be
# bundled, the node keeps nothing of it, and a wake is bin-packed onto the nodes available (here
# the enrolled node wins the tie with this host's own, as where it last ran).
# Boxes are named hib-*; everything is removed at the end.
set -Eeuo pipefail
# Whatever ends the script early says where and with what status (#158: an exit 5 once, unexplained).
trap 'echo "hibernate.sh: line $LINENO: \"$BASH_COMMAND\" returned $?" >&2' ERR

WICKET=${WICKET:-target/debug/wicket}
WICKET=$(realpath "$WICKET")
on_node=
[ "${1:-}" = --node ] && on_node=1
cd "$(dirname "$0")/.."
DOCKER=${WICKET_DOCKER:-docker}

export WICKET_HOME=${WICKET_HOME:-$(mktemp -d)}
export WICKET_BOX_PREFIX=hib
work=$(mktemp -d)
# Teardown (#158): runs on every exit, keeps the script's own exit status, and can't change it. Each
# step is idempotent and logged if it fails, so a failure here is visible but never becomes the result.
# Under `set -e` a failing command in an EXIT trap used to end the script with that command's status
# (after every check had passed).
step() {
  local what=$1 rc=0
  shift
  "$@" || rc=$?
  [ "$rc" = 0 ] || echo "teardown: $what returned $rc (ignored)" >&2
  return 0
}
stop_pid() { [ -n "${1:-}" ] || return 0; kill "$1" 2>/dev/null || return 0; for _ in $(seq 50); do kill -0 "$1" 2>/dev/null || return 0; sleep 0.1; done; kill -9 "$1" 2>/dev/null || true; }
remove_boxes() { local c; for c in $($DOCKER ps -aq --filter name=^hib-run- 2>/dev/null); do $DOCKER rm -f "$c" >/dev/null 2>&1 || true; done; }
# This host's own node's `serve` (started by wicket, detached) outlives the script otherwise, writing
# into $WICKET_HOME while it is removed.
stop_local_serve() { local p; p=$(head -1 "$WICKET_HOME/local-node/serve/serve.pid" 2>/dev/null) || return 0; tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -q "node serve" || return 0; stop_pid "$p"; }
remove_dirs() { local i; for i in 1 2 3; do chmod -R u+w "$work" "$WICKET_HOME" 2>/dev/null; rm -rf "$work" "$WICKET_HOME" 2>/dev/null && return 0; sleep 1; done; rm -rf "$work" "$WICKET_HOME"; }
cleanup() {
  local rc=$?
  set +e
  trap - EXIT
  step "stopping the mock model" stop_pid "${mock_pid:-}"
  step "stopping the busy run" stop_pid "${busy_pid:-}"
  step "stopping the node's serve" stop_pid "${serve_pid:-}"
  step "stopping this host's node's serve" stop_local_serve
  step "reaping children" wait
  step "removing boxes" remove_boxes
  step "removing the work and data directories" remove_dirs
  exit "$rc"
}
trap cleanup EXIT

"$WICKET" identity init --trust-domain ci.wicket.test >/dev/null
node_args=()
if [ -n "$on_node" ]; then
  nodehome=$work/n   # short: the node's run sockets live under it
  mkdir -p "$nodehome"
  export WICKET_NODE_SSH="env HOME=$nodehome sh -c"
  token=$("$WICKET" node token --name hn1 2>/dev/null)
  # A placeholder host key: with WICKET_NODE_SSH nothing checks it.
  "$WICKET" node enrol wicket@hn1.example.com --token "$token" --hosts example.com \
    --host-key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEggj6FyU//JJDZKykzPImKRPFveTcOK9nWc/L0oCx+k' >"$work/enrol.log" 2>&1
  "$WICKET" node install hn1 --no-service >>"$work/enrol.log" 2>&1
  HOME=$nodehome WICKET_BOX_PREFIX=hib "$nodehome/.local/bin/wicket" node serve >"$work/node.log" 2>&1 &
  serve_pid=$!
  for _ in $(seq 50); do [ -S "$nodehome/.local/share/wicket-node/ctl/ctl.sock" ] && break; sleep 0.2; done
  node_args=(--node hn1)
  noderuns=$nodehome/.local/share/wicket-node/runs
fi
printf 'mock-model-credential' | "$WICKET" secret set mock --hosts 127.0.0.1 >/dev/null
"$WICKET" dev mock-llm --listen 127.0.0.1:9998 --command 'sh /workspace/step.sh' 2>"$work/mock.log" &
mock_pid=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/9998) 2>/dev/null && break; sleep 0.2; done

fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
agent_field() { "$WICKET" agents --json | jq -r --arg n "$1" ".[] | select(.id == \$n) | .$2"; }
result_of() { sed -n 's/^\[wicket\] result.json: //p' "$1" | tail -1; }

# Agent A: writes a file in each writable place on its first turn, reports them on later ones.
mkdir -p "$work/a"
cat > "$work/a/step.sh" <<'STEP'
if [ -f /workspace/turn1 ]; then
  n=$(cat /workspace/turns); echo $((n + 1)) > /workspace/turns
  jq -n --arg tmp "$(cat /tmp/hib-tmp 2>/dev/null)" --arg home "$(cat "$HOME/hib-home" 2>/dev/null)" \
    --arg ws "$(cat /workspace/hib-ws 2>/dev/null)" --arg vol "$(cat /volumes/data/hib-vol 2>/dev/null)" \
    --arg turns "$((n + 1))" '{tmp:$tmp,home:$home,ws:$ws,vol:$vol,turns:$turns}' > /workspace/out/result.json
else
  echo tmp-kept > /tmp/hib-tmp; echo home-kept > "$HOME/hib-home"; echo ws-kept > /workspace/hib-ws
  echo vol-kept > /volumes/data/hib-vol; echo 1 > /workspace/turns; touch /workspace/turn1
  echo '{"status":"first"}' > /workspace/out/result.json
fi
echo "wicket-mock: hibernate"
STEP

echo "== agent A: first run (asks to hibernate after its turn)"
timeout 240 "$WICKET" run ci/hibernate.yaml --workdir "$work/a" "${node_args[@]}" ${IMAGE:+--image "$IMAGE"} >"$work/a1.log" 2>&1 || true
cat "$work/a1.log"
A=$(grep -o "agent agt_[a-z0-9]*" "$work/a1.log" | head -1 | cut -d" " -f2 || true)
check "agent A was registered" '[ -n "$A" ]'
check "A's first run hibernated" 'grep -q "hibernated in" "$work/a1.log"'
check "A is hibernated in the ledger" '[ "$(agent_field "$A" state)" = hibernated ]'
check "A's box is gone" '[ -z "$($DOCKER ps -q --filter name=^hib-run-)" ]'
r1=$(grep -o "run_[a-z0-9]\{26\}" "$work/a1.log" | head -1 || true)
check "A's run dir no longer holds its state" '[ ! -e "$WICKET_HOME/runs/$r1/state" ] && [ ! -e "$WICKET_HOME/runs/$r1/tmp" ] && [ ! -e "$WICKET_HOME/runs/$r1/workspace/hib-ws" ]'
check "A's first result is kept" 'result_of "$work/a1.log" | grep -q first'
if [ -n "$on_node" ]; then
  check "A ran on the node, and its state came back from it" 'grep -q "node hn1 via wicket node serve" "$work/a1.log" && grep -q "fetched the box.s files from its node" "$work/a1.log"'
  check "  and the node kept nothing of it" '[ ! -e "$noderuns/$r1" ]'
fi
gen1=$(agent_field "$A" generation)
check "A's first run spent 3 requests" '[ "$(agent_field "$A" used.requests)" = 3 ]'

echo "== agent A: wicket wake"
timeout 240 "$WICKET" wake "$A" "Run it again, please." ${IMAGE:+} >"$work/a2.log" 2>&1 || true
grep -E '^\[wicket\]|woken' "$work/a2.log" || true
res=$(result_of "$work/a2.log")
echo "   result: $res"
field() { jq -r ".$1 // empty" <<<"$res" 2>/dev/null; }
check "the woken session resumed (--resume)" 'grep -q "session .* resumed" "$work/a2.log"'
if [ -n "$on_node" ]; then
  check "the wake was bin-packed onto the node it last ran on (a tie with this host's)" 'grep -q "placing agent .* on node hn1" "$work/a2.log"'
fi
check "a file under /tmp survived" '[ "$(field tmp)" = tmp-kept ]'
check "a file under \$HOME survived" '[ "$(field home)" = home-kept ]'
check "a file in the workspace survived" '[ "$(field ws)" = ws-kept ]'
check "a file in the durable volume survived" '[ "$(field vol)" = vol-kept ]'
check "the woken turn ran the step (turn 2)" '[ "$(field turns)" = 2 ]'
# The first run's model requests carry 1, 3 and 5 messages; a resumed session's carry the old turn too.
check "the model saw the prior conversation" 'grep -E "end the turn \(([7-9]|[1-9][0-9]) messages" "$work/mock.log" >/dev/null'
check "the operator's text reached the model, after wicket's wake notice" 'grep "the user said:" "$work/mock.log" | grep "woken (wicket wake" | grep -q "Run it again, please."'
check "A hibernated again" '[ "$(agent_field "$A" state)" = hibernated ]'
gen2=$(agent_field "$A" generation)
check "the wake bumped the generation by one" '[ "$gen2" = $((gen1 + 1)) ]'
check "the woken activation's spend continued from 3" '[ "$(agent_field "$A" used.requests)" = 6 ] && [ "$(agent_field "$A" used.output_tokens)" = 120 ]'

echo "== agent A: two wakes at once"
timeout 240 "$WICKET" wake "$A" >"$work/w1.log" 2>&1 & p1=$!
timeout 240 "$WICKET" wake "$A" >"$work/w2.log" 2>&1 & p2=$!
s1=0; s2=0; wait $p1 || s1=$?; wait $p2 || s2=$?
echo "   exits: $s1 $s2"
check "exactly one wake won" '[ $(( (s1 == 0) + (s2 == 0) )) = 1 ] && [ $(( (s1 == 2) + (s2 == 2) )) = 1 ]'
check "the loser was told it lost" 'grep -q "not woken" "$work/w1.log" "$work/w2.log"'
check "the generation went up by exactly one" '[ "$(agent_field "$A" generation)" = $((gen2 + 1)) ]'
check "A hibernated again after the winner's turn" '[ "$(agent_field "$A" state)" = hibernated ]'

echo "== agent A: wicket say wakes it"
"$WICKET" say "$r1" "A message for a sleeping agent." | tee "$work/say.log"
for _ in $(seq 120); do [ "$(agent_field "$A" generation)" = $((gen2 + 2)) ] && [ "$(agent_field "$A" state)" = hibernated ] && break; sleep 1; done
check "say woke it, and it went back to sleep" '[ "$(agent_field "$A" generation)" = $((gen2 + 2)) ] && [ "$(agent_field "$A" state)" = hibernated ]'
check "the message was its turn" 'grep "the user said:" "$work/mock.log" | grep "woken (wicket say" | grep -q "A message for a sleeping agent."'
check "four activations spent the whole budget" '[ "$(agent_field "$A" used.requests)" = 12 ]'
calls=$(grep -c "^mock: /v1/messages" "$work/mock.log" || true)
out=$("$WICKET" say "$A" "One more?" 2>&1 || true); echo "   $out"
check "a spent agent isn't woken" 'grep -q "request budget is spent" <<<"$out"'
"$WICKET" wake "$A" >"$work/w3.log" 2>&1 || true
check "nor by wicket wake, and its generation stays" 'grep -q "request budget is spent" "$work/w3.log" && [ "$(agent_field "$A" generation)" = $((gen2 + 2)) ]'
check "it made no model call" '[ "$(grep -c "^mock: /v1/messages" "$work/mock.log" || true)" = "$calls" ]'

# Agent B: leaves a background process running, so it can't be rebuilt without losing it.
mkdir -p "$work/b"
echo 'nohup sleep 300 >/dev/null 2>&1 & echo "{\"status\":\"busy\"}" > /workspace/out/result.json; echo "wicket-mock: hibernate"' > "$work/b/step.sh"
echo "== agent B: a background process keeps it running"
timeout 240 "$WICKET" run ci/hibernate.yaml --workdir "$work/b" "${node_args[@]}" ${IMAGE:+--image "$IMAGE"} >"$work/b.log" 2>&1 & busy_pid=$!
B=""
for _ in $(seq 90); do
  B=$(grep -o 'agent agt_[a-z0-9]*' "$work/b.log" 2>/dev/null | head -1 | cut -d' ' -f2 || true)
  [ -n "$B" ] && grep -q "not hibernated" "$work/b.log" && break
  sleep 1
done
grep -E '^\[wicket\]' "$work/b.log" || true
check "B was not hibernated" 'grep -q "not hibernated: other processes run in the box" "$work/b.log"'
check "B is active in the ledger, with the reason" '[ "$(agent_field "$B" state)" = active ] && agent_field "$B" note | grep -q sleep'
bbox=$($DOCKER ps -q --filter name=^hib-run- | head -1)
check "B's box runs, not paused (#249)" '[ -n "$bbox" ] && [ "$($DOCKER inspect -f "{{.State.Paused}}" "$bbox")" = false ]'
out=$("$WICKET" hibernate "$B" --wait 30 || true); echo "   $out"
check "wicket hibernate leaves it running too" 'grep -q "goes on running" <<<"$out"'
kill -TERM "$busy_pid" 2>/dev/null || true
wait "$busy_pid" 2>/dev/null || true
check "B's box was stopped with its run" '[ -z "$($DOCKER ps -q --filter name=^hib-run-)" ]'

check "the model never saw the placeholder" '! grep -q "PLACEHOLDER" "$work/mock.log"'
sealed_only() {
  local f n=0
  while IFS= read -r f; do
    case "$f" in "$WICKET_HOME/objects/sealed/"*) ;; *) return 1 ;; esac
    [ "$(head -c 4 "$f")" = WKS1 ] || return 1
    n=$((n + 1))
  done < <(find "$WICKET_HOME/objects" -type f ! -name '.tmp-*')
  [ "$n" -gt 0 ]
}
check "the agents' state is sealed at rest (every object encrypted)" sealed_only
check "the audit chain verifies" '"$WICKET" audit --verify >/dev/null'
"$WICKET" agents

if [ "$fail" != 0 ]; then
  echo "== mock model log"; tail -40 "$work/mock.log"
  for f in a1 a2 w1 w2 b; do echo "== $f.log"; tail -30 "$work/$f.log" 2>/dev/null || true; done
  exit 1
fi
echo "hibernate test passed"

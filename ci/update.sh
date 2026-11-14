#!/usr/bin/env bash
# The self-update test (#162): a control host (development mode) and two local nodes are updated
# from build A to build B and back, while a long-lived agent on this host's own node and another on
# a node keep working, each outcome checked, and everything torn down (on failure too).
#
#   ci/update.sh
#
# Build A is this checkout's binary (WICKET, default target/debug/wicket), its debug info stripped; B and C are A with bytes
# appended (another sha256, the same code), so no second build is needed. Agents are driven by
# `wicket dev mock-llm`: no model credential is used. The nodes are this machine (`wicket node
# serve` run directly, each with its own HOME; the ssh hop replaced by WICKET_NODE_SSH, as
# ci/node-e2e.sh --local does).
#
#   1. refused: an unsigned artifact; an agent's `request_update` only files a request for a human
#      (and the artifact stays refused while that request is pending);
#   2. A → B: a signed release archive (ci/package.sh), on the control host, then n1 (the canary)
#      and n2, with a canary box on B's own image (wicket/claude-code:<B's build id>, built while
#      staging); the agents' boxes stay, are handed over, and take another turn through the new
#      build (model and gateway); a new box with the default image gets B's;
#   3. a manual rollback of all three to A, the agents take another turn, and a new box gets A's
#      image;
#   4. an automatic rollback: the agent's build C, approved by a human, fails an injected health
#      check on the control host and is switched back to A; the approval is used up;
#   5. pruning (#166): a dry run removes nothing; then B, now neither current nor previous on the
#      control host, goes with its image, while A and C stay (and the nodes, A and B, keep both);
#   5b. builds CI signed (#190), from a fake GitHub API: --from-ci, its refusals, and follow
#       (ci/update/from-ci.sh);
#   5c. protocol jumps (#207, ci/update/jump.sh): refused while an enrolled node is left behind,
#      naming it; with every node, the control host and its nodes switch together;
#   6. the audit chain verifies and has every step;
#   7. with the remote nodes revoked, a jump with only this host's own node goes through.
#
# Needs Docker with runsc and the agent image. Env: WICKET, IMAGE (an existing agent image: not
# built, not removed; default: built as wicket/claude-code:upd-$$ and removed), WICKET_DOCKER (e.g.
# "sudo -n docker"), UPD_KEEP=1 (keep the work dir).
# shellcheck disable=SC2016,SC2034  # checks and waits are strings eval'd later, with the variables they name
set -euo pipefail
cd "$(dirname "$0")/.."

bin=$(realpath "${WICKET:-target/debug/wicket}")
DOCKER=${WICKET_DOCKER:-docker}
export WICKET_DOCKER=$DOCKER
# Short: runs' unix sockets live under it.
work=$(mktemp -d /tmp/wupd.XXXXXX)
chmod 755 "$work"
export WICKET_HOME=$work/h WICKET_BOX_PREFIX=upd
HOMEW=$work/u
mkdir -p "$WICKET_HOME" "$HOMEW"
# Build A: the binary under test without its debug info (#219). Every build here is a copy of it, and
# each is copied, hashed, packaged with gzip -9 and sent to two nodes: a debug build is ~500 MB, about
# 115 MB stripped, and packaging it takes a third of the time. What runs is the same code.
A=$work/wicket-a
objcopy --strip-debug "$bin" "$A" 2>/dev/null || cp "$bin" "$A"
# The control host's binary: A until the first update, then whatever `current` is.
W=$A
w() { HOME=$HOMEW "$W" "$@"; }
pids=()
built_image=
IMAGE_TAG=${IMAGE:-}

results=()
fail=0
check() {
  if (set +o pipefail; eval "$2"); then results+=("ok   $1"); echo "ok   $1"; else results+=("FAIL $1"); echo "FAIL $1"; fail=1; fi
}
log() { echo "== $(date +%T) $*"; }
wait_for() { local n=$1; shift; for _ in $(seq "$n"); do (set +o pipefail; eval "$1") && return 0; sleep 1; done; return 1; }

teardown() {
  local status=$?
  set +e
  trap - EXIT INT TERM
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  # The handed-over supervisors and this host's node's serve were started by wicket, not by us.
  for p in $(pgrep -f "$work/" 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
  sleep 1
  for c in $($DOCKER ps -aq --filter name=^upd-run- 2>/dev/null); do $DOCKER rm -f "$c" >/dev/null 2>&1; done
  $DOCKER rm -f "upd-$$-holds-b" >/dev/null 2>&1
  if [ -n "$built_image" ]; then $DOCKER rmi "$built_image" >/dev/null 2>&1; fi
  # Each build's own image, made by the updates (these builds are this test's alone).
  for i in "${A_ID:-}" "${B_ID:-}" "${C_ID:-}" "${D_ID:-}" "${E_ID:-}" "${J_ID:-}" "${K_ID:-}"; do [ -n "$i" ] && $DOCKER rmi "wicket/claude-code:$i" >/dev/null 2>&1; done
  if [ "${UPD_KEEP:-}" = 1 ]; then echo "kept: $work"; else chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"; fi
  echo
  printf '%s\n' "${results[@]}"
  [ "$fail" = 0 ] && [ "$status" = 0 ] && echo "update: all checks passed" || echo "update: FAILED"
  [ "$fail" = 0 ] || exit 1
  exit "$status"
}
trap teardown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
run_id_of() { sed -n 's/^wicket run \(run_[a-z0-9]*\).*/\1/p' "$1" | head -1; }
box_of() { $DOCKER ps -q --filter "label=wicket.run=$1" 2>/dev/null; }
id_of() { sha256sum "$1" | cut -c1-12; }
current() { basename "$(readlink "$1/current")"; }
node_dir() { echo "$work/$1/.local/share/wicket-node"; }
# The version a process runs: from /proc, or for a non-dumpable `node serve` (#152) what it wrote beside
# its pid file (the pid on the first line, the binary on the second).
serve_runs() {
  local e
  e=$(readlink "/proc/$1/exe" 2>/dev/null) || e=$(cat "$WICKET_HOME/local-node/serve/serve.exe" "$work"/n*/.local/share/wicket-node/serve.exe 2>/dev/null \
    | awk -v p="$1" 'NR%2==1 {m=($1==p)} NR%2==0 && m {print; exit}')
  basename "$(dirname "$e")"
}
# A new box with the default image: which image its run got.
new_box_image() {
  local log=$work/newbox-$1.log r
  w run ci/update/canary.yaml >"$log" 2>&1 || true
  r=$(run_id_of "$log")
  w audit --tail 300 | grep run.start | grep "$r" | grep -o '"image":"[^"]*"' | head -1 | cut -d'"' -f4
}

# ---- setup ----
log "setup"
w identity init --trust-domain upd.wicket.test >/dev/null
printf 'mock-model-credential' | w secret set mock --hosts 127.0.0.1 >/dev/null
if [ -z "$IMAGE_TAG" ]; then
  IMAGE_TAG=wicket/claude-code:upd-$$
  log "building the agent image $IMAGE_TAG"
  w image --tag "$IMAGE_TAG" >"$work/image.log" 2>&1 || { tail -30 "$work/image.log"; exit 1; }
  built_image=$IMAGE_TAG
fi
# Builds B and C: A with bytes appended. B ships as a signed release archive, C as an agent's
# unsigned binary.
cp "$A" "$work/wicket" && printf '\nwicket ci/update.sh build B\n' >>"$work/wicket"
B_ID=$(id_of "$work/wicket")
B_ART=$(ci/package.sh "$work/wicket" "$work/dist")
rm "$work/wicket"
cp "$A" "$work/C" && printf '\nwicket ci/update.sh build C\n' >>"$work/C"
A_ID=$(id_of "$A") C_ID=$(id_of "$work/C")
C_SHA=$(sha256sum "$work/C" | cut -d' ' -f1)
echo "   A $A_ID, B $B_ID ($(basename "$B_ART")), C $C_ID"
# The release key: made here, trusted by this installation, signs B.
w self keygen "$work/release.key" >/dev/null
w self trust-key "$work/release.key.pub" >/dev/null
w self sign --key "$work/release.key" "$B_ART" >/dev/null

# Two nodes on this machine, each its own HOME, reached through one ssh stand-in.
cat >"$work/ssh" <<EOF
#!/bin/sh
# WICKET_NODE_SSH for ci/update.sh: \$1 is the node's target (wicket@<name>.example.com).
n=\${1#*@}; n=\${n%%.*}
exec env HOME="$work/\$n" sh -c "\$2"
EOF
chmod +x "$work/ssh"
export WICKET_NODE_SSH="$work/ssh %t"
for n in n1 n2; do
  mkdir -p "$work/$n"
  token=$(w node token --name "$n" 2>/dev/null)
  # A placeholder host key: with WICKET_NODE_SSH nothing checks it.
  w node enrol "wicket@$n.example.com" --token "$token" --hosts example.com \
    --host-key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEggj6FyU//JJDZKykzPImKRPFveTcOK9nWc/L0oCx+k' >>"$work/enrol.log" 2>&1
  w node install "$n" --no-service >>"$work/enrol.log" 2>&1
  HOME=$work/$n "$work/$n/.local/bin/wicket" node serve >"$work/$n.log" 2>&1 &
  pids+=("$!")
  eval "${n}_pid=$!"
  wait_for 60 '[ -S "$(node_dir '"$n"')/ctl/ctl.sock" ]'
done
check "node install stages A as each node's current version" '[ "$(current "$(node_dir n1)/versions")" = "$A_ID" ] && [ "$(serve_runs "$n1_pid")" = "$A_ID" ]'

port=$(free_port)
mock_cmd="[ -f /workspace/drive.sh ] && exec bash /workspace/drive.sh; sleep 500"
w dev mock-llm --listen "127.0.0.1:$port" --command "$mock_cmd" 2>"$work/mock.log" &
pids+=("$!")
wait_for 10 "(exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null"
sed "s#MOCK_PORT#$port#" ci/acceptance/restart.yaml >"$work/agent.yaml"

# The agents: long-lived, one on this host's own node, one on n1. Each turn counts itself and calls
# the gateway (ci/acceptance/restart/drive.sh).
result() {
  cat "$WICKET_HOME/runs/$1/workspace/out/result.json" 2>/dev/null || cat "$(node_dir n1)/runs/$1/workspace/out/result.json" 2>/dev/null || true
}
start_agent() {   # $1: label, then wicket run options
  local label=$1; shift
  mkdir -p "$work/ws-$label" && cp ci/acceptance/restart/drive.sh "$work/ws-$label/"
  w run "$work/agent.yaml" --workdir "$work/ws-$label" --image "$IMAGE_TAG" "$@" >"$work/agent-$label.log" 2>&1 &
  pids+=("$!")
  wait_for 90 '[ -n "$(run_id_of "$work/agent-'"$label"'.log")" ]' || true
  local r; r=$(run_id_of "$work/agent-$label.log")
  wait_for 120 '[ "$(result '"$r"' | jq -r .turn 2>/dev/null)" = 1 ]' || true
  echo "$r"
}
log "two long-lived agents"
r_local=$(start_agent local)
r_node=$(start_agent n1 --node n1)
runs=("$r_local" "$r_node") labels=(local n1)
boxes=("$(box_of "$r_local")" "$(box_of "$r_node")")
echo "   runs: ${runs[*]}; boxes: ${boxes[*]}"
check "both agents took their first turn" '[ "$(result "$r_local" | jq -r .turn)" = 1 ] && [ "$(result "$r_node" | jq -r .turn)" = 1 ]'
turns=1
# Each agent takes one more turn, on the same box, reaching its model and its gateway.
another_turn() {   # $1: what happened
  turns=$((turns + 1))
  local i r res
  for i in "${!runs[@]}"; do
    r=${runs[$i]}
    w say "$r" "Again, $1." >/dev/null 2>&1 || true
    wait_for 180 '[ "$(result '"$r"' | jq -r .turn 2>/dev/null)" = '"$turns"' ]' || true
    res=$(result "$r")
    echo "   ${labels[$i]}: $res"
    check "  after $1, the agent on ${labels[$i]} took turn $turns on the same box, with its gateway" \
      '[ "$(jq -r .turn <<<"$res")" = '"$turns"' ] && [ "$(box_of "$r")" = "${boxes[$i]}" ] && [ "$(jq -r .ping <<<"$res")" = "{}" ] && [ "$(jq -r .whoami_run <<<"$res")" = "$r" ]'
  done
}

# ---- 1. refusals ----
log "1. refused: unsigned, and an agent's own request"
check "an unsigned artifact is refused" '! w self update "$work/C" >"$work/u-unsigned.log" 2>&1 && grep -q "not signed by a release key" "$work/u-unsigned.log"'
echo "$C_SHA" >"$work/ws-asker.sha"
mkdir -p "$work/ws-asker" && cp ci/update/asker.sh "$work/ws-asker/drive.sh" && cp "$work/ws-asker.sha" "$work/ws-asker/sha256"
w run "$work/agent.yaml" --workdir "$work/ws-asker" --image "$IMAGE_TAG" >"$work/agent-asker.log" 2>&1 &
pids+=("$!")
wait_for 90 '[ -n "$(run_id_of "$work/agent-asker.log")" ]' || true
r_asker=$(run_id_of "$work/agent-asker.log")
wait_for 120 '[ -s "$WICKET_HOME/runs/$r_asker/workspace/out/result.json" ]' || true
asked=$(cat "$WICKET_HOME/runs/$r_asker/workspace/out/result.json" 2>/dev/null || true)
echo "   request_update: $(jq -r '.content[0].text' <<<"$asked" 2>/dev/null | cut -c1-160)"
req=$(w pending 2>/dev/null | grep -o 'r-[a-z0-9]*' | head -1 || true)
check "an agent's request_update files an R4 request and updates nothing" \
  'jq -r ".content[0].text" <<<"$asked" | grep -q "needs a human" && w pending | grep -q "UPDATE wicket.internal/self/$C_SHA" && [ "$(current "$WICKET_HOME/versions" 2>/dev/null)" != "$C_ID" ]'
check "while the request is pending, its artifact is still refused" '! w self update "$work/C" >"$work/u-pending.log" 2>&1 && grep -q "no human has approved" "$work/u-pending.log"'

# ---- 2. A -> B ----
log "2. update to B: control host, then n1 (canary) and n2"
# The node agent's model credential, fetched by n1 on its first use (#152): kept in n1's memory.
fetched() { w audit --tail 3000 | grep node.secret_fetch | grep "$r_node" | grep -c '"released":true'; }
fetched_before=$(fetched)
set +e
w self update "$B_ART" --nodes n1,n2 --window 10s --interval 5s --canary ci/update/canary.yaml 2>&1 | tee "$work/u-b.log"
st=${PIPESTATUS[0]}
set -e
W=$WICKET_HOME/versions/current/wicket
local_serve=$(cat "$WICKET_HOME/local-node/serve/serve.pid")
check "the update to B succeeded" '[ "$st" = 0 ]'
check "  the control host runs B, and A is previous" '[ "$(current "$WICKET_HOME/versions")" = "$B_ID" ] && [ "$(basename "$(readlink "$WICKET_HOME/versions/previous")")" = "$A_ID" ]'
check "  this host's node re-executed itself as B (same pid)" '[ "$(serve_runs "$local_serve")" = "$B_ID" ]'
check "  n1 and n2 run B, their serves re-executed in place" '[ "$(current "$(node_dir n1)/versions")" = "$B_ID" ] && [ "$(current "$(node_dir n2)/versions")" = "$B_ID" ] && [ "$(serve_runs "$n1_pid")" = "$B_ID" ] && [ "$(serve_runs "$n2_pid")" = "$B_ID" ]'
check "  the runs were handed over and adopted by B" 'grep -qE "runs: ([0-9]+) handed over, \1 adopted" "$work/u-b.log"'
check "  B's own image was built while staging, and the canary ran on it" '$DOCKER image inspect "wicket/claude-code:$B_ID" >/dev/null 2>&1 && w audit --tail 300 | grep run.start | grep -q "wicket/claude-code:$B_ID"'
check "  a new box with the default image gets B's" '[ "$(new_box_image b)" = "wicket/claude-code:$B_ID" ]'
another_turn "the update to B"
check "  n1's secret cache was handed to its new serve through a memfd, and not fetched again (#152)" \
  'grep -q "cached secret(s) handed over from the previous process" "$work/n1.log" && [ "$fetched_before" -ge 1 ] && [ "$(fetched)" = "$fetched_before" ]'
check "  and n1's data dir holds no copy of it" '! grep -rlsF mock-model-credential "$(node_dir n1)"'

# ---- 3. manual rollback ----
log "3. rollback by hand"
set +e
w self rollback --nodes n1,n2 2>&1 | tee "$work/u-back.log"
st=${PIPESTATUS[0]}
set -e
check "the rollback succeeded" '[ "$st" = 0 ]'
check "  all three run A again" '[ "$(current "$WICKET_HOME/versions")" = "$A_ID" ] && [ "$(current "$(node_dir n1)/versions")" = "$A_ID" ] && [ "$(current "$(node_dir n2)/versions")" = "$A_ID" ] && [ "$(serve_runs "$local_serve")" = "$A_ID" ] && [ "$(serve_runs "$n1_pid")" = "$A_ID" ]'
another_turn "the rollback"
check "  a new box with the default image gets A's again (B's is kept)" '[ "$(new_box_image a)" = "wicket/claude-code:$A_ID" ] && $DOCKER image inspect "wicket/claude-code:$B_ID" >/dev/null 2>&1'

# ---- 4. automatic rollback ----
log "4. an agent's build, approved, fails its health gate: rolled back"
w approve "$req" --yes >"$work/approve.log" 2>&1 || cat "$work/approve.log"
set +e
w self update "$work/C" --window 10s --interval 5s --check 'test "$WICKET_UPDATE_TARGET" != control' 2>&1 | tee "$work/u-c.log"
st=${PIPESTATUS[0]}
set -e
check "the approved build was accepted, failed the injected check, and the update failed" '[ "$st" != 0 ] && grep -q "approved" "$work/u-c.log" && grep -q "rolled back to $A_ID" "$work/u-c.log"'
check "  the control host and its node run A" '[ "$(current "$WICKET_HOME/versions")" = "$A_ID" ] && [ "$(serve_runs "$local_serve")" = "$A_ID" ]'
check "  the approval was used up: C is refused again" '! w self update "$work/C" >"$work/u-c2.log" 2>&1 && grep -q "no human has approved" "$work/u-c2.log"'
another_turn "the automatic rollback"

# ---- 5. prune ----
log "5. prune"
# A stopped container of B's image, this test's own: the box that checked new boxes get B's image is
# cleaned up by now, and `ancestor` matches by image id (and descendants), which isn't this test's alone.
$DOCKER create --name "upd-$$-holds-b" "wicket/claude-code:$B_ID" true >/dev/null
w self prune --nodes n1,n2 --dry-run >"$work/prune-dry.log" 2>&1 || cat "$work/prune-dry.log"
cat "$work/prune-dry.log"
check "a dry run says B would go, keeps its image while a container uses it, and removes nothing" \
  'grep -q "control: would remove 1 version(s) \[$B_ID\]" "$work/prune-dry.log" && grep -q "kept wicket/claude-code:$B_ID (a container uses it)" "$work/prune-dry.log" && [ -d "$WICKET_HOME/versions/$B_ID" ]'
$DOCKER rm -f "upd-$$-holds-b" >/dev/null
# Without it, B's image goes, unless a running box has its id: here the agents' boxes may (every build's
# box image is made like theirs), and prune keeps an image while one does.
b_used=$($DOCKER ps -aq --filter "ancestor=wicket/claude-code:$B_ID")
w self prune --nodes n1,n2 >"$work/prune.log" 2>&1 || cat "$work/prune.log"
cat "$work/prune.log"
check "  prune removes B, and its image unless a box still has its id; A (current) and C (previous) stay" \
  '[ ! -e "$WICKET_HOME/versions/$B_ID" ] && [ -d "$WICKET_HOME/versions/$A_ID" ] && [ -d "$WICKET_HOME/versions/$C_ID" ] && if [ -n "$b_used" ]; then grep -q "kept wicket/claude-code:$B_ID (a container uses it)" "$work/prune.log"; else ! $DOCKER image inspect "wicket/claude-code:$B_ID" >/dev/null 2>&1; fi'
check "  the nodes keep their current and previous" '[ -d "$(node_dir n1)/versions/$A_ID" ] && [ -d "$(node_dir n1)/versions/$B_ID" ] && grep -q "node:n1: removed 0 version" "$work/prune.log"'

# ---- 5b. builds CI signed (#190) ----
. ci/update/from-ci.sh
another_turn "the CI-signed updates"

# ---- 5c. protocol jumps (#207) ----
. ci/update/jump.sh

# ---- 6. audit ----
log "6. audit"
check "wicket audit --verify" 'w audit --verify >"$work/verify.log" 2>&1'
w audit --tail 1000 | grep -oE '"?self\.[a-z_]+' | tr -d '"' | uniq -c | tee "$work/self-audit.txt"
for k in self.update_refused self.staged self.snapshot self.switched self.health self.committed self.rolled_back self.pruned; do
  check "  the audit records $k" 'grep -q " $k$" "$work/self-audit.txt"'
done
check "  an automatic rollback is recorded as one" 'w audit --tail 1000 | grep self.rolled_back | grep -q "\"automatic\":true"'
# The agent that asked stays up until here: revoking it would withdraw its request, and its grants.
for r in "${runs[@]}" "$r_asker"; do w identity revoke "$r" --reason "update test: done" >/dev/null 2>&1 || true; done
for r in "${runs[@]}" "$r_asker"; do wait_for 60 '[ -z "$(box_of "'"$r"'")" ]' || true; done

# ---- 7. a protocol jump with only this host's own node (#207) ----
. ci/update/jump-local.sh

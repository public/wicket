#!/usr/bin/env bash
# Control-plane state off the host (#154), end to end: a control host streams its ledger to an
# S3-compatible store (versitygw, a local S3 gateway) with Litestream, keeps hibernated agents'
# bundles and audit segments there, takes its roots offline, and is then lost; a fresh standby is
# restored from the recovery kit and the store, wakes the agent, runs a box on a node that outlived
# the lost host, streams again, and verifies its audit chain; two more hosts restore from the
# standby's stream and from a point in time before it.
# Needs Docker with runsc and the agent image (as ci/hibernate.sh). No model credential.
#
#   WICKET=target/debug/wicket ci/restore.sh      (IMAGE=tag for another image; KEEP=1 keeps the files)
#
# Checks:
#   - the store takes writes; the ledger streams to it; a hibernated agent's bundle is in it, sealed;
#   - with the roots offline, boxes still start (tokens minted by the certified issuing key), on this
#     host's node and on an enrolled one, and the roots are gone from the host;
#   - after the kit, the enrolled node's feed compacts (a new version the kit doesn't know);
#   - after the stream stops, audited work that reached only the audit export (the RPO gap) comes
#     back: the restore puts those records back in the chain, up to a signed checkpoint;
#   - the control host is lost (its processes killed, its data, keys and vault deleted); the enrolled
#     node isn't;
#   - on the standby: the restored ledger reaches at least where the stream stopped; agents are
#     fenced; nothing can use a root before the roots come back (and none is made); with them, the
#     feeds start new generations the surviving node accepts; the agent wakes with its files; the
#     standby streams as a lineage of its own; `audit --verify --against store:<sink>` passes;
#   - a third host restores from the standby's stream; a fourth restores to a point before the
#     loss (`--at`), and the copies exported after that point are reported as discarded.
# Boxes are named rst-*; the store and Litestream run as containers named after this run; everything
# is removed at the end.
set -euo pipefail

WICKET=${WICKET:-target/debug/wicket}
WICKET=$(realpath "$WICKET")
cd "$(dirname "$0")/.."
DOCKER=${WICKET_DOCKER:-docker}
export WICKET_DOCKER=$DOCKER
# Pinned: the S3 gateway (v1.11.0) and Litestream (v0.5.18).
S3_IMAGE=${S3_IMAGE:-versity/versitygw@sha256:8319a530d08d537426e2f855bae5280709795dc73a3f0c347973ef915d6343c5}
LITESTREAM_IMAGE=${LITESTREAM_IMAGE:-litestream/litestream@sha256:0ba1cdbb2d0be8876e27b1e646dc031309b7e3928e0ed91503ebaa73ff7e2c5d}

export WICKET_BOX_PREFIX=rst
work=$(mktemp -d)
s3name=wicket-rst-s3-$$
homes=(a b c d)
litestream_of() { echo "wicket-litestream-$(printf %s "$work/$1-home" | sha256sum | cut -c1-12)"; }
cleanup() {
  kill "${mock_pid:-}" "${serve_pid:-}" 2>/dev/null || true
  for h in "${homes[@]}"; do kill_home "$work/$h-home" 2>/dev/null || true; $DOCKER rm -f "$(litestream_of "$h")" >/dev/null 2>&1 || true; done
  wait 2>/dev/null || true
  for c in $($DOCKER ps -aq --filter name=^rst-run- 2>/dev/null) $($DOCKER ps -aq --filter "name=^$s3name" 2>/dev/null); do
    $DOCKER rm -f "$c" >/dev/null 2>&1 || true
  done
  if [ -n "${KEEP:-}" ]; then echo "kept: $work"; return; fi
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# Every process of one installation (by WICKET_HOME in its environment): what "losing the host" kills.
kill_home() {
  local h=$1 p
  for p in $(ls /proc | grep -E '^[0-9]+$'); do
    [ "$p" = $$ ] && continue
    if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null | grep -qx "WICKET_HOME=$h"; then kill -9 "$p" 2>/dev/null || true; fi
  done
}

fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
agent_field() { local -n h=$1; "${h[@]}" "$WICKET" agents --json | jq -r --arg n "$2" ".[] | select(.id == \$n) | .$3"; }
result_of() { sed -n 's/^\[wicket\] result.json: //p' "$1" | tail -1; }
head_seq() { local -n h=$1; "${h[@]}" "$WICKET" audit --tail 1 | awk '{print $1}'; }
restored_head() { sed -n 's/.*its audit chain verifies, up to record \([0-9]*\).*/\1/p' "$1"; }
cert_version() { python3 -I -c 'import base64,json,sys; p=open(sys.argv[1]).read().split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"=="))["version"])' "$1"; }
mock() { local -n h=$1; "${h[@]}" "$WICKET" dev mock-llm --listen 127.0.0.1:9997 --command 'sh /workspace/step.sh' 2>"$work/mock-$1.log" & mock_pid=$!
  for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/9997) 2>/dev/null && break; sleep 0.2; done; }
stop_stream() { kill "$repl_pid" 2>/dev/null || true; wait "$repl_pid" 2>/dev/null || true
  # (Its container, named after the data directory, outlives the wicket process that started it.)
  $DOCKER rm -f "$(litestream_of "$1")" >/dev/null 2>&1 || true; }

# ---- the store: versitygw, keys made for this run ----
port=$(free_port)
access=rst$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
secret=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
mkdir -p "$work/s3/wicket-rst"   # the bucket: a directory of the gateway's posix backend
$DOCKER run -d --name "$s3name" --network host --user "$(id -u):$(id -g)" -v "$work/s3:/data" \
  -e ROOT_ACCESS_KEY="$access" -e ROOT_SECRET_KEY="$secret" "$S3_IMAGE" --port "127.0.0.1:$port" posix /data >/dev/null
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break; sleep 0.2; done

# ---- the hosts: each its own data directory (keys under it) and $HOME (the vault) ----
HA=(env WICKET_HOME="$work/a-home" HOME="$work/a-user")
HB=(env WICKET_HOME="$work/b-home" HOME="$work/b-user")
HC=(env WICKET_HOME="$work/c-home" HOME="$work/c-user")
HD=(env WICKET_HOME="$work/d-home" HOME="$work/d-user")
for h in "${homes[@]}"; do mkdir -p "$work/$h-home" "$work/$h-user"; done
"${HA[@]}" "$WICKET" identity init --trust-domain ci.wicket.test >/dev/null
printf 'mock-model-credential' | "${HA[@]}" "$WICKET" secret set mock --hosts 127.0.0.1 >/dev/null
printf '%s' "$secret" | "${HA[@]}" "$WICKET" secret set s3-rst --hosts 127.0.0.1 >/dev/null
cat >"$work/a-home/state-store.yaml" <<EOF
s3:
  endpoint: http://127.0.0.1:$port
  bucket: wicket-rst
  prefix: ci/
  access_key_id: $access
  secret: s3-rst
bundles: s3
ledger:
  sync_interval: 1s
  litestream: { image: '$LITESTREAM_IMAGE' }
EOF
printf 'checkpoint_every: 1m\nsinks:\n  - {name: rst, type: store}\n' >"$work/a-home/audit-sinks.yaml"
cat >"$work/prog.yaml" <<'EOF'
task: Say hello.
program:
  name: hello
  command: [sh, -c, "echo rst-hello"]
zone:
  name: rst-hello
  isolation: gvisor
  limits: { memory: 256m, cpus: 1, timeout: 2m }
EOF
prog() { local -n h=$1; shift; timeout 120 "${h[@]}" "$@" "$WICKET" run "$work/prog.yaml" --node rn1 ${IMAGE:+--image "$IMAGE"} 2>&1; }
# Whether the program ran and said hello (its output held first: `grep -q` would cut the run off).
hello() { local out; out=$(prog "$@" || true); grep -q "^\[program\] rst-hello" <<<"$out" || { tail -3 <<<"$out"; return 1; }; }
sed 's#127.0.0.1:9998#127.0.0.1:9997#' ci/hibernate.yaml >"$work/agent.yaml"
# The agent of ci/hibernate.sh: a file in each writable place on its first turn, reported later.
mkdir -p "$work/ws"
cat >"$work/ws/step.sh" <<'STEP'
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
STEP

echo "== the control host: its state store, and an enrolled node"
"${HA[@]}" "$WICKET" state check --probe | tee "$work/check.log"
check "the state store takes writes" 'grep -q "it takes writes" "$work/check.log"'
"${HA[@]}" "$WICKET" state replicate >"$work/replicate-a.log" 2>&1 &
repl_pid=$!
mock HA
# A node on this machine, as ci/hibernate.sh --node enrols one: its own home, the ssh hop replaced.
nodehome=$work/n
mkdir -p "$nodehome"
export WICKET_NODE_SSH="env HOME=$nodehome sh -c"
token=$("${HA[@]}" "$WICKET" node token --name rn1 2>/dev/null)
"${HA[@]}" "$WICKET" node enrol wicket@rn1.example.com --token "$token" --hosts example.com \
  --host-key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEggj6FyU//JJDZKykzPImKRPFveTcOK9nWc/L0oCx+k' >"$work/enrol.log" 2>&1
"${HA[@]}" "$WICKET" node install rn1 --no-service >>"$work/enrol.log" 2>&1
HOME=$nodehome "$nodehome/.local/bin/wicket" node serve >"$work/node.log" 2>&1 &
serve_pid=$!
for _ in $(seq 50); do [ -S "$nodehome/.local/share/wicket-node/ctl/ctl.sock" ] && break; sleep 0.2; done
check "a box runs on the enrolled node" 'hello HA'

echo "== the control host: an agent's first run (hibernates after its turn)"
timeout 240 "${HA[@]}" "$WICKET" run "$work/agent.yaml" --workdir "$work/ws" ${IMAGE:+--image "$IMAGE"} >"$work/a1.log" 2>&1 || true
A=$(grep -o "agent agt_[a-z0-9]*" "$work/a1.log" | head -1 | cut -d" " -f2 || true)
check "the agent hibernated" '[ -n "$A" ] && [ "$(agent_field HA "$A" state)" = hibernated ]'
sealed=$(find "$work/s3/wicket-rst/ci/sealed" -type f 2>/dev/null | wc -l)
echo "   $sealed sealed object(s) in the store"
check "  its bundle is in the state store, sealed, and not on the host" '[ "$sealed" -gt 0 ] && [ -z "$(find "$work/a-home/objects" -type f 2>/dev/null)" ]'
gen1=$(agent_field HA "$A" generation)
sleep 2
t_first=$(date -u +%Y-%m-%dT%H:%M:%SZ)   # the point the fourth host restores to
sleep 2

echo "== the control host: its roots go offline"
"${HA[@]}" "$WICKET" keys roots-offline --to "$work/roots" --days 30 | tee "$work/roots.log"
check "the roots are off the host, their public halves kept" '[ ! -e "$work/a-home/identity/feed-root.key" ] && [ ! -e "$work/a-home/identity/authz-root.key" ] && [ -s "$work/a-home/identity/authz-root.pub" ] && [ -s "$work/roots/authz-root.key" ]'
timeout 240 "${HA[@]}" "$WICKET" wake "$A" "Again, with the roots offline." >"$work/a2.log" 2>&1 || true
res=$(result_of "$work/a2.log")
check "  a box still starts and works: the wake ran its turn (tokens from the issuing key)" '[ "$(jq -r .turns <<<"$res" 2>/dev/null)" = 2 ]'
check "  and the agent hibernated again" '[ "$(agent_field HA "$A" state)" = hibernated ]'
check "  and a box runs on the enrolled node" 'hello HA'
check "  and no root was made again" '[ ! -e "$work/a-home/identity/feed-root.key" ] && [ ! -e "$work/a-home/identity/authz-root.key" ]'
gen=$(agent_field HA "$A" generation)

echo "== the control host: the recovery kit, and its last minutes"
"${HA[@]}" "$WICKET" state kit --out "$work/kit.tar" | tee "$work/kit.log"
check "the kit holds no root" '! tar -tf "$work/kit.tar" | grep -q -- "-root.key"'
mkdir -p "$work/kit-x" && tar -xf "$work/kit.tar" -C "$work/kit-x" data/nodes/rn1/feed/cert.jws
v_kit=$(cert_version "$work/kit-x/data/nodes/rn1/feed/cert.jws")
# The node's feed compacts after the kit (the roots at hand): a version the kit doesn't have.
prog HA WICKET_ROOTS="$work/roots" WICKET_FEED_COMPACT_BYTES=1 >/dev/null || true
v_now=$(cert_version "$work/a-home/nodes/rn1/feed/cert.jws")
echo "   the node's feed: version $v_kit in the kit, $v_now now"
check "the enrolled node's feed moved past the kit's version" '[ "$v_now" -gt "$v_kit" ]'
"${HA[@]}" "$WICKET" audit export --once --checkpoint >/dev/null
stop_head=$(head_seq HA)
# Let the stream catch up, then stop it: what follows reaches only the audit export.
sleep 3
stop_stream a
"${HA[@]}" "$WICKET" state kit --out "$work/kit-after-stream.tar" >/dev/null   # an audited act (state.kit)
gap_seq=$(head_seq HA)
"${HA[@]}" "$WICKET" audit export --once --checkpoint >/dev/null
echo "   the stream stopped after record $stop_head; record $gap_seq reached only the audit export"

echo "== the control host is lost"
kill "$mock_pid" 2>/dev/null || true
kill_home "$work/a-home"
sleep 1
rm -rf "$work/a-home" "$work/a-user" "$work/kit-after-stream.tar"
check "nothing of the control host is left, and its enrolled node still serves" '[ ! -e "$work/a-home" ] && [ -z "$($DOCKER ps -q --filter name=^rst-run-)" ] && kill -0 "$serve_pid"'

echo "== the standby: restored"
"${HB[@]}" "$WICKET" state restore --kit "$work/kit.tar" | tee "$work/restore-b.log"
b_head=$(restored_head "$work/restore-b.log")
check "the ledger came back from the store, its chain verified, at least where the stream stopped" '[ -n "$b_head" ] && [ "$b_head" -ge "$stop_head" ]'
check "  and the records only the export had are back in the chain" 'grep -q "audit record(s) the store had beyond" "$work/restore-b.log" && "${HB[@]}" "$WICKET" audit --tail 400 | grep -q "^ *$gap_seq .*state.kit"'
check "  and its agents are fenced" 'grep -q "agent(s) fenced" "$work/restore-b.log" && [ "$(agent_field HB "$A" generation)" -ge $((gen + 1000)) ]'
out=$(prog HB || true)
tail -2 <<<"$out"
check "before the roots come back, a box needing a feed's new generation is refused, naming WICKET_ROOTS" 'grep -q WICKET_ROOTS <<<"$out" && ! grep -q "^\[program\] rst-hello" <<<"$out"'
check "  and no root was made" '[ -z "$(ls "$work/b-home/identity" | grep -- "-root.key")" ]'
"${HB[@]}" "$WICKET" keys certify --roots "$work/roots" | tee "$work/certify.log"
check "the roots, brought back for a moment, renew the certificates and start each feed's new generation" 'grep -q "started a new generation" "$work/certify.log"'
v_b=$(cert_version "$work/b-home/nodes/rn1/feed/cert.jws")
check "  the node's past every version it saw ($v_b > $v_now), and it runs a box from the standby" '[ "$v_b" -gt "$v_now" ] && hello HB'
"${HB[@]}" "$WICKET" reconcile >"$work/reconcile.log" 2>&1 || cat "$work/reconcile.log"

echo "== the standby: the agent wakes"
mock HB
timeout 240 "${HB[@]}" "$WICKET" wake "$A" "You were restored." >"$work/b1.log" 2>&1 || true
res=$(result_of "$work/b1.log")
echo "   result: $res"
field() { jq -r ".$1 // empty" <<<"$res" 2>/dev/null; }
check "the woken session resumed" 'grep -q "session .* resumed" "$work/b1.log"'
check "  with every file it had: /tmp, \$HOME, the workspace and its durable volume" '[ "$(field tmp)" = tmp-kept ] && [ "$(field home)" = home-kept ] && [ "$(field ws)" = ws-kept ] && [ "$(field vol)" = vol-kept ]'
# The workspace's turn counter continues from the lost host's 2 (the standby's own mock model may
# have the step run more than once in its turn).
check "  and its turn continued the workspace's count past the lost host's 2" '[ "$(field turns)" -ge 3 ] 2>/dev/null'

echo "== the standby: streams as a lineage of its own, and its audit chain"
"${HB[@]}" "$WICKET" state replicate >"$work/replicate-b.log" 2>&1 &
repl_pid=$!
sleep 4
"${HB[@]}" "$WICKET" state kit --out "$work/kit-b.tar" >/dev/null   # audited work on the standby
"${HB[@]}" "$WICKET" audit export --once --checkpoint >/dev/null
b_now=$(head_seq HB)
sleep 3
stop_stream b
check "the standby streamed, as a new lineage" 'grep -q "streaming .* as lineage" "$work/replicate-b.log" && ! grep -q "level=ERROR" "$work/replicate-b.log"'
"${HB[@]}" "$WICKET" audit --verify --against store:rst | tee "$work/verify-b.log"
check "audit --verify --against the store's copies passes" 'grep -q "audit chain OK" "$work/verify-b.log" && grep -q "against the exported copies: [1-9][0-9]* signed checkpoint(s) and [1-9][0-9]* record(s) match" "$work/verify-b.log"'
check "  and the restore is in it" '"${HB[@]}" "$WICKET" audit --tail 400 | grep -q state.restored'

echo "== a third host: restored from the standby's stream"
"${HC[@]}" "$WICKET" state restore --kit "$work/kit.tar" | tee "$work/restore-c.log"
lineage_b=$(sed -n 's/.* as lineage \([a-z0-9]*\).*/\1/p' "$work/replicate-b.log" | head -1)
c_head=$(restored_head "$work/restore-c.log")
check "it came from the standby's lineage, at least as far as the standby had got" 'grep -q "from lineage $lineage_b" "$work/restore-c.log" && [ "$c_head" -ge "$b_now" ]'
check "  and the lost host's lineage refuses to stream again (another host took over)" '! "${HB[@]}" "$WICKET" state replicate >"$work/replicate-b2.log" 2>&1 && grep -q "another control host restored" "$work/replicate-b2.log"'

echo "== a fourth host: restored to a point before the loss (--at $t_first)"
"${HD[@]}" "$WICKET" state restore --kit "$work/kit.tar" --at "$t_first" | tee "$work/restore-d.log"
check "it has the agent as it was then, fenced" '[ "$(agent_field HD "$A" generation)" = $((gen1 + 1000)) ]'
"${HD[@]}" "$WICKET" audit --verify --against store:rst | tee "$work/verify-d.log"
check "  and audit --verify --against passes, reporting what came after as discarded" 'grep -q "against the exported copies" "$work/verify-d.log" && grep -q "which discarded them" "$work/verify-d.log"'

echo
[ "$fail" = 0 ] && echo "restore: all checks passed" || echo "restore: FAILED"
exit "$fail"

#!/usr/bin/env bash
# Control-plane state off the host (#154), end to end: a control host streams its ledger to an
# S3-compatible store (versitygw, a local S3 gateway) with Litestream, keeps hibernated agents'
# bundles and audit segments there, takes its roots offline, and is then lost; a fresh standby is
# restored from the recovery kit and the store, wakes the agent, and verifies its audit chain.
# Needs Docker with runsc and the agent image (as ci/hibernate.sh). No model credential.
#
#   WICKET=target/debug/wicket ci/restore.sh      (IMAGE=tag for another image)
#
# Checks:
#   - the store takes writes (`wicket state check`); the ledger streams to it;
#   - a hibernated agent's bundle is in the store, sealed, and nothing of it on the host;
#   - with the roots offline, boxes still start (tokens minted by the certified issuing key), and
#     the roots are gone from the host;
#   - after the ledger's stream stops, audited work that reached only the audit export (the RPO gap)
#     comes back: the standby's restore puts those records back in the chain;
#   - the control host is lost (its processes killed, its data, keys and vault deleted);
#   - on the standby: the restore, the roots' certify (each node feed's new generation), a wake of
#     the agent that resumes its session with its files, fenced past any generation the lost host
#     could have handed out, and `audit --verify --against store:<sink>`.
# Boxes are named rst-*; the store and Litestream run as containers named after this run; everything
# is removed at the end.
set -euo pipefail

WICKET=${WICKET:-target/debug/wicket}
WICKET=$(realpath "$WICKET")
cd "$(dirname "$0")/.."
DOCKER=${WICKET_DOCKER:-docker}
export WICKET_DOCKER=$DOCKER
# Pinned: the S3 gateway and Litestream (v0.5.18).
S3_IMAGE=${S3_IMAGE:-versity/versitygw@sha256:8319a530d08d537426e2f855bae5280709795dc73a3f0c347973ef915d6343c5}
LITESTREAM_IMAGE=${LITESTREAM_IMAGE:-litestream/litestream@sha256:0ba1cdbb2d0be8876e27b1e646dc031309b7e3928e0ed91503ebaa73ff7e2c5d}

export WICKET_BOX_PREFIX=rst
work=$(mktemp -d)
s3name=wicket-rst-s3-$$
cleanup() {
  kill "${mock_pid:-}" "${repl_pid:-}" 2>/dev/null || true
  kill_home "$work/a-home" 2>/dev/null || true
  kill_home "$work/b-home" 2>/dev/null || true
  wait 2>/dev/null || true
  for h in a-home b-home; do $DOCKER rm -f "wicket-litestream-$(printf %s "$work/$h" | sha256sum | cut -c1-12)" >/dev/null 2>&1 || true; done
  for c in $($DOCKER ps -aq --filter name=^rst-run- 2>/dev/null) $($DOCKER ps -aq --filter "name=^$s3name" 2>/dev/null); do
    $DOCKER rm -f "$c" >/dev/null 2>&1 || true
  done
  # The store's files were written by its container.
  [ -d "$work/s3" ] && [ -z "${KEEP:-}" ] && $DOCKER run --rm -v "$work:/w" --entrypoint /bin/sh "$S3_IMAGE" -c 'rm -rf /w/s3' >/dev/null 2>&1 || true
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

# ---- the store: versitygw, keys made for this run ----
port=$(free_port)
access=rst$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
secret=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
mkdir -p "$work/s3/wicket-rst"   # the bucket: a directory of the gateway's posix backend
chmod -R 0777 "$work/s3"
$DOCKER run -d --name "$s3name" --network host -v "$work/s3:/data" -e ROOT_ACCESS_KEY="$access" -e ROOT_SECRET_KEY="$secret" \
  "$S3_IMAGE" --port "127.0.0.1:$port" posix /data >/dev/null
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break; sleep 0.2; done

# ---- the control host ----
# Each host: its own data directory (keys under it) and its own $HOME (the vault).
HA=(env WICKET_HOME="$work/a-home" HOME="$work/a-user")
HB=(env WICKET_HOME="$work/b-home" HOME="$work/b-user")
mkdir -p "$work/a-home" "$work/a-user" "$work/b-home" "$work/b-user"
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

echo "== the control host: its state store"
"${HA[@]}" "$WICKET" state check | tee "$work/check.log"
check "the state store takes writes" 'grep -q "it takes writes" "$work/check.log"'
"${HA[@]}" "$WICKET" state replicate >"$work/replicate.log" 2>&1 &
repl_pid=$!
"${HA[@]}" "$WICKET" dev mock-llm --listen 127.0.0.1:9997 --command 'sh /workspace/step.sh' 2>"$work/mock.log" &
mock_pid=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/9997) 2>/dev/null && break; sleep 0.2; done
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

echo "== the control host: an agent's first run (hibernates after its turn)"
timeout 240 "${HA[@]}" "$WICKET" run "$work/agent.yaml" --workdir "$work/ws" ${IMAGE:+--image "$IMAGE"} >"$work/a1.log" 2>&1 || true
A=$(grep -o "agent agt_[a-z0-9]*" "$work/a1.log" | head -1 | cut -d" " -f2 || true)
check "the agent hibernated" '[ -n "$A" ] && [ "$(agent_field HA "$A" state)" = hibernated ]'
sealed=$(find "$work/s3/wicket-rst/ci/sealed" -type f 2>/dev/null | wc -l)
echo "   $sealed sealed object(s) in the store"
check "  its bundle is in the state store, sealed, and not on the host" '[ "$sealed" -gt 0 ] && [ -z "$(find "$work/a-home/objects" -type f 2>/dev/null)" ]'

echo "== the control host: its roots go offline"
"${HA[@]}" "$WICKET" keys roots-offline --to "$work/roots" --days 30 | tee "$work/roots.log"
check "the roots are off the host, their public halves kept" '[ ! -e "$work/a-home/identity/feed-root.key" ] && [ ! -e "$work/a-home/identity/authz-root.key" ] && [ -s "$work/a-home/identity/authz-root.pub" ] && [ -s "$work/roots/authz-root.key" ]'
timeout 240 "${HA[@]}" "$WICKET" wake "$A" "Again, with the roots offline." >"$work/a2.log" 2>&1 || true
res=$(result_of "$work/a2.log")
check "  a box still starts and works: the wake ran its turn (tokens from the issuing key)" '[ "$(jq -r .turns <<<"$res" 2>/dev/null)" = 2 ]'
check "  and the agent hibernated again" '[ "$(agent_field HA "$A" state)" = hibernated ]'
gen=$(agent_field HA "$A" generation)

echo "== the control host: the recovery kit, and its last minutes"
"${HA[@]}" "$WICKET" state kit --out "$work/kit.tar" | tee "$work/kit.log"
check "the kit holds no root" '! tar -tf "$work/kit.tar" | grep -q -- "-root.key"'
"${HA[@]}" "$WICKET" audit export --once --checkpoint >/dev/null
# Let the stream catch up, then stop it: what follows reaches only the audit export.
sleep 3
kill "$repl_pid" 2>/dev/null || true
wait "$repl_pid" 2>/dev/null || true
# (Its container, named after the data directory, outlives the wicket process that started it.)
$DOCKER rm -f "wicket-litestream-$(printf %s "$work/a-home" | sha256sum | cut -c1-12)" >/dev/null 2>&1 || true
"${HA[@]}" "$WICKET" state kit --out "$work/kit-after-stream.tar" >/dev/null   # an audited act (state.kit)
gap_seq=$("${HA[@]}" "$WICKET" audit --tail 1 | awk '{print $1}')
"${HA[@]}" "$WICKET" audit export --once --checkpoint >/dev/null
echo "   the stream stopped; record $gap_seq reached only the audit export"

echo "== the control host is lost"
kill "$mock_pid" 2>/dev/null || true
kill_home "$work/a-home"
sleep 1
rm -rf "$work/a-home" "$work/a-user" "$work/kit-after-stream.tar"
check "nothing of the control host is left" '[ ! -e "$work/a-home" ] && [ -z "$($DOCKER ps -q --filter name=^rst-run-)" ]'

echo "== the standby: restored"
"${HB[@]}" "$WICKET" state restore --kit "$work/kit.tar" | tee "$work/restore.log"
check "the ledger came back from the store, its chain verified" 'grep -q "the ledger is restored: its audit chain verifies" "$work/restore.log"'
check "  and the records only the export had are back in the chain" 'grep -q "audit record(s) the store had beyond" "$work/restore.log" && "${HB[@]}" "$WICKET" audit --tail 400 | grep -q "^ *$gap_seq .*state.kit"'
check "  and its agents are fenced" 'grep -q "agent(s) fenced" "$work/restore.log" && [ "$(agent_field HB "$A" generation)" -ge $((gen + 1000)) ]'
WICKET_ROOTS="$work/roots" "${HB[@]}" "$WICKET" keys certify | tee "$work/certify.log"
check "the roots, brought back for a moment, renew the certificates and start each feed's new generation" 'grep -q "started a new generation" "$work/certify.log"'
"${HB[@]}" "$WICKET" reconcile >"$work/reconcile.log" 2>&1 || cat "$work/reconcile.log"
"${HB[@]}" "$WICKET" dev mock-llm --listen 127.0.0.1:9997 --command 'sh /workspace/step.sh' 2>"$work/mock-b.log" &
mock_pid=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/9997) 2>/dev/null && break; sleep 0.2; done

echo "== the standby: the agent wakes"
timeout 240 "${HB[@]}" "$WICKET" wake "$A" "You were restored." >"$work/b1.log" 2>&1 || true
grep -E '^\[wicket\]' "$work/b1.log" | head -20 || true
res=$(result_of "$work/b1.log")
echo "   result: $res"
field() { jq -r ".$1 // empty" <<<"$res" 2>/dev/null; }
check "the woken session resumed" 'grep -q "session .* resumed" "$work/b1.log"'
check "  with every file it had: /tmp, \$HOME, the workspace and its durable volume" '[ "$(field tmp)" = tmp-kept ] && [ "$(field home)" = home-kept ] && [ "$(field ws)" = ws-kept ] && [ "$(field vol)" = vol-kept ]'
# The workspace's turn counter continues from the lost host's 2 (the standby's own mock model may
# have the step run more than once in its turn).
check "  and its turn continued the workspace's count past the lost host's 2" '[ "$(field turns)" -ge 3 ] 2>/dev/null'

echo "== the standby: its audit chain"
"${HB[@]}" "$WICKET" audit export --once --checkpoint >/dev/null
"${HB[@]}" "$WICKET" audit --verify --against store:rst | tee "$work/verify.log"
check "audit --verify --against the store's copies passes" 'grep -q "audit chain OK" "$work/verify.log" && grep -q "against the exported copies: [1-9][0-9]* signed checkpoint(s) and [1-9][0-9]* record(s) match" "$work/verify.log"'
check "  and the restore is in it" '"${HB[@]}" "$WICKET" audit --tail 400 | grep -q state.restored'

echo
[ "$fail" = 0 ] && echo "restore: all checks passed" || echo "restore: FAILED"
exit "$fail"

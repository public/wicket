# shellcheck shell=bash disable=SC2154  # sourced by ci/acceptance.sh, which sets work, mode, nodes, datadir
# The multi-host part of ci/acceptance.sh (sourced by it; uses its helpers and variables).
#
# An agent asks for a machine of its own (request_capacity), a human approves the lease, the
# reconciler acquires the node through placement, and the agent starts a box there (spawn with
# placement {lease}), and links to it: the agent's box, on the control host's own node, fetches a page
# from the box on the other node across the link, relayed by the control host over both nodes'
# channels (#146). Then the node e2e flow (ci/node-e2e.sh) runs against the same node. Revoking the
# agent ends the lease; one reconcile pass gives the node back (on Vultr: destroys it), no tagged
# machine remains, and the lease records what the node billed.
#
#   local: the static backend, with localhost as an enrolled node (`wicket node serve` run directly
#          with its own data dir; the ssh hop replaced by WICKET_NODE_SSH, as ci/node-e2e.sh --local
#          does). Nothing costs money.
#   vultr: `backend: vultr`, the cheapest plan that fits 1 vCPU and 1 GiB, at most $0.02 an hour,
#          in an envelope of $0.05 an hour and $0.05 in total (owner tag wicket-owner-acc.wicket.test). The agent image is loaded onto the node over its pinned ssh.

NODE=acc-n1
node_ssh_target=wicket@acc-n1.example.com

node_local_setup() {
  nodehome=$work/n   # short: the node's run sockets live under it too
  mkdir -p "$nodehome"
  export WICKET_NODE_SSH="env HOME=$nodehome sh -c"
  local token
  token=$(wroot node token --name "$NODE" 2>/dev/null)
  # A placeholder host key: with WICKET_NODE_SSH nothing checks it.
  wroot node enrol "$node_ssh_target" --token "$token" --hosts example.com \
    --host-key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEggj6FyU//JJDZKykzPImKRPFveTcOK9nWc/L0oCx+k' >"$work/enrol.log" 2>&1
  wroot node install "$NODE" --no-service >>"$work/enrol.log" 2>&1
  HOME=$nodehome "$nodehome/.local/bin/wicket" node serve >"$work/node-serve.log" 2>&1 &
  node_serve_pid=$!
  pids+=("$node_serve_pid")
  wait_for 90 '[ -S "$nodehome/.local/share/wicket-node/ctl/ctl.sock" ]'
  cat >"$WICKET_HOME/placement.yaml" <<EOF
owner: acc.wicket.test
backend: static
max_hourly_usd: '0.05'
max_total_usd: '0.05'
static_hosts:
  - name: $NODE
    ssh_target: $node_ssh_target
    capacity: { vcpus: 2, memory_mib: 2048 }
    isolation: gvisor
install_static: false
EOF
}

node_local_teardown() {
  if [ -n "${node_serve_pid:-}" ]; then kill "$node_serve_pid" 2>/dev/null; fi
  # Boxes `node serve` started run on this Docker, labelled with their runs.
  local r
  for r in $(all_descendants); do for c in $(box_of "$r"); do $DOCKER rm -f "$c" >/dev/null 2>&1; done; done
}

node_vultr_setup() {
  : "${ACC_VULTR_SSH_KEY_ID:?the id of an ssh key in the Vultr account}" "${ACC_VULTR_SSH_KEY:?its private half on this host}"
  # ACC_VULTR_API_KEY_FILE: link the key into this run's vault by reference (never copied).
  if [ -n "${ACC_VULTR_API_KEY_FILE:-}" ] && ! wroot secret list | grep -q '^vultr-api-key '; then
    wroot secret link vultr-api-key --file "$ACC_VULTR_API_KEY_FILE" --hosts api.vultr.com >/dev/null
  fi
  wroot secret list | grep -q '^vultr-api-key ' || { echo "no vault secret vultr-api-key (wicket secret set vultr-api-key, or ACC_VULTR_API_KEY_FILE)"; exit 1; }
  local f=$WICKET_HOME/placement.yaml
  [ "$mode" = dev ] || f=$work/placement.yaml
  cat >"$f" <<EOF
backend: vultr
owner: acc.wicket.test
max_hourly_usd: '0.05'
max_total_usd: '0.05'
node_hosts: [example.com]
vultr:
  region: ${ACC_VULTR_REGION:-lhr}
  ssh_key_ids: [$ACC_VULTR_SSH_KEY_ID]
  ssh_key: $ACC_VULTR_SSH_KEY
EOF
  [ "$mode" = dev ] || sudo -n install -o wicket -g wicket -m 0600 "$f" "$datadir/placement.yaml"
}

# On any exit: end our lease and destroy its machine, and say so loudly if that fails.
vultr_teardown() {
  [ -n "${cap_run:-}" ] || return 0
  wroot identity revoke "$cap_run" --reason "acceptance teardown" >/dev/null 2>&1
  [ -n "${lease:-}" ] && wroot lease release "$lease" >/dev/null 2>&1
  wroot reconcile >/dev/null 2>&1
  if wroot place list --owner acc.wicket.test 2>/dev/null | grep -q "^0 node(s) tagged"; then
    echo "teardown: no tagged Vultr machine remains"
  else
    ACC_KEEP=1   # keep the ledger: it is how this machine is found and released
    echo "!!!! TEARDOWN: a Vultr machine tagged for this test may remain, and it bills by the hour. Now:"
    echo "!!!!   WICKET_HOME=${WICKET_HOME:-$datadir} wicket place list --owner acc.wicket.test"
    echo "!!!!   WICKET_HOME=${WICKET_HOME:-$datadir} wicket place release --owner acc.wicket.test <instance id>"
    wroot place list --owner acc.wicket.test 2>&1 | sed 's/^/!!!! /'
  fi
  if [ "$mode" = installed ]; then sudo -n rm -f "$datadir/placement.yaml"; fi
}

# The agent image, onto the node (a fresh Vultr node has Docker but no image).
node_vultr_image() {
  local row target pin
  row=$(w node list | awk -v n="$1" '$1==n')
  target=$(awk '{print $3}' <<<"$row")
  pin=${WICKET_HOME:-$datadir}/nodes/$1/known_hosts
  $DOCKER save "$IMAGE_TAG" | ssh -i "$ACC_VULTR_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$pin" \
    -o GlobalKnownHostsFile=/dev/null -o "HostKeyAlias=wicket-node-$1" "$target" docker load
}

multihost() {
  log "multi-host ($nodes): a lease, a box on the node, the node e2e flow, then revoke"
  if [ "$nodes" = local ]; then node_local_setup; else node_vultr_setup; fi
  cap_ws=$(workdir cap)
  HOME=$HOMEW "$W" run "$(manifest cap)" --workdir "$cap_ws" --image "$IMAGE_TAG" >"$work/cap.log" 2>&1 &
  cap_pid=$!
  pids+=("$cap_pid")
  wait_for 60 '[ -n "$(run_id_of "$work/cap.log")" ]' || true
  cap_run=$(run_id_of "$work/cap.log")
  our_runs+=("$cap_run")
  cres() { data "runs/$cap_run/workspace/out/result.json" 2>/dev/null; }
  cf() { cres | jq -r ".$1 // empty" 2>/dev/null; }

  # Approve the lease (the approval runs a reconcile pass, which acquires the node), then let the
  # agent go on once the node has the image.
  local deadline=$((SECONDS + ${ACC_NODE_WAIT:-900})) approved="" released=""
  while [ $SECONDS -lt $deadline ] && [ "$(cf done)" != 1 ] && kill -0 "$cap_pid" 2>/dev/null; do
    if [ -z "$approved" ]; then
      rid=$(w pending 2>/dev/null | grep -E "^r-[a-z0-9]+ +CAPACITY .* run $cap_run " | awk '{print $1}' | head -1 || true)
      if [ -n "$rid" ]; then
        log "approving lease request $rid"
        wroot approve "$rid" >"$work/lease-approve.log" 2>&1 || cat "$work/lease-approve.log"
        approved=1
      fi
    fi
    if [ -z "$released" ] && [ -n "$(cf ready)" ]; then
      lease=$(cf lease)
      node_name=$(cf ready | grep -o "is node [a-z0-9-]*" | awk '{print $3}' || true)
      if [ "$nodes" = vultr ]; then
        log "loading the agent image onto $node_name"
        node_vultr_image "$node_name" >"$work/image-load.log" 2>&1 || cat "$work/image-load.log"
      fi
      : >"$work/go"
      if [ "$mode" = dev ]; then touch "$WICKET_HOME/runs/$cap_run/workspace/out/go"; else sudo -n touch "$datadir/runs/$cap_run/workspace/out/go"; fi
      released=1
    fi
    sleep 2
  done
  echo "   result: $(cres)"
  check "the agent asked for capacity and got a lease" 'cf asked | grep -q "^requested: lease l-"'
  check "  a human approved it, and the node was ready" 'cf ready | grep -q "^ready: lease"'
  check "a box started on the node (spawn with placement {lease})" 'cf remote | grep -q "^started program remote .* on node"'
  child_log "$cap_run" >"$work/remote.log" 2>/dev/null || true
  wait_for 120 'child_log "$cap_run" | grep -q "acc-remote-done"' || true
  check "  its egress was decided on the node: in reach 200" 'child_log "$cap_run" | grep -q "acc-remote in=200"'
  check "  and out of reach 403" 'child_log "$cap_run" | grep -q "acc-remote .*out=403"'
  # A link across nodes: the agent's box (on the control host's own node) reaches the box on this node.
  echo "   connect to the box on the node: $(cf connect)"
  check "the agent linked to the box on the other node" 'cf connect | grep -q "remote.wicket.internal:8000"'
  check "  and fetched its page across nodes, relayed by the control host" '[ "$(cf connect_fetch)" = acc-remote ]'

  # The node e2e flow, against the same node, once the remote box has ended.
  remote_run=$(cf remote | grep -o 'run_[a-z0-9]*' | head -1 || true)
  wait_for 90 'child_log "$cap_run" | grep -qE "run $remote_run: [a-z]+ in"' || true
  if [ "${ACC_NODE_E2E:-1}" = 1 ] && [ -n "${node_name:-}" ]; then
    log "node e2e flow on $node_name"
    if TMPDIR=$work HOME=$HOMEW WICKET="$W" IMAGE="$IMAGE_TAG" WICKET_E2E_SSH_KEY="${ACC_VULTR_SSH_KEY:-}" \
      NODE_LOG=$( [ "$nodes" = local ] && echo "$work/node-serve.log" ) timeout 600 ci/node-e2e.sh "$node_name" >"$work/node-e2e.log" 2>&1; then e2e=0; else e2e=$?; fi
    grep -E '^(ok|FAIL) ' "$work/node-e2e.log" | sed 's/^/   node-e2e: /' || true
    if [ "$e2e" != 0 ]; then tail -n 25 "$work/node-e2e.log" | sed 's/^/   node-e2e log: /'; fi
    check "the node e2e flow passed (ci/node-e2e.sh $node_name)" '[ "$e2e" = 0 ]'
  fi

  log "revoking the agent that holds the lease"
  wroot identity revoke "$cap_run" --reason "acceptance: revoke the lease holder" >/dev/null 2>&1 || true
  wait_for 60 '! kill -0 "$cap_pid" 2>/dev/null' || true
  wroot reconcile >"$work/rec-lease.log" 2>&1 || cat "$work/rec-lease.log"
  cat "$work/rec-lease.log"
  lrow=$(w lease list | awk -v l="${lease:-none}" '$1==l' || true)
  echo "   lease: $lrow"
  check "revoking ended the lease" 'grep -qE "ended|released|revoked" <<<"$lrow"'
  check "  and the lease records what its node billed" 'grep -q "billed [$][0-9]" <<<"$lrow"'
  billed=$(grep -o 'billed \$[0-9.]*' <<<"$lrow" || true)
  if [ "$nodes" = vultr ]; then
    check "  no tagged machine remains (wicket place list)" 'wroot place list --owner acc.wicket.test 2>/dev/null | grep -q "^0 node(s) tagged"'
    echo "   Vultr: the lease ${billed:-billed ?}; compare with the account's billing for this instance"
  else
    check "  no box remains on the node" '[ -z "$(for r in $(all_descendants); do box_of "$r"; done)" ]'
  fi
  results+=("info lease ${lease:-?} on node ${node_name:-?}: ${billed:-billed ?}")
}

# A node on its own (#152, #153), --nodes local: an agent's box on acc-n1 calls the model (its node
# fetches the credential on first use and keeps it in memory only) and its egress every 5 s. Its
# control channel is cut for 165 s, longer than the old 150 s offline window: the box keeps working,
# model calls included, and an out-of-reach request is queued on the node. 90 s in, the node's
# `serve` restarts: its cache is gone, so model calls fail clearly while plain egress goes on; on
# reconnect the credential is fetched again. Then its secret is removed from the vault: the node
# drops it within seconds and model calls stop. At its authority's end (5 min from the run's start)
# the node stops the box.
offline_flow() {
  log "a node on its own: a 165 s partition, a serve restart in it, the box stopped at its authority's end"
  local value=mock-model-credential
  printf '%s' "$value" | wroot secret set mock-offline --hosts 127.0.0.1 >/dev/null
  local ws; ws=$(workdir offline)
  HOME=$HOMEW "$W" run "$(manifest offline)" --workdir "$ws" --image "$IMAGE_TAG" --node "$NODE" >"$work/offline.log" 2>&1 &
  local run_pid=$!
  pids+=("$run_pid")
  wait_for 90 '[ -n "$(run_id_of "$work/offline.log")" ]' || true
  local r; r=$(run_id_of "$work/offline.log")
  our_runs+=("$r")
  local nd=$nodehome/.local/share/wicket-node
  local olog=$nd/runs/$r/workspace/out/offline.log
  wait_for 120 'grep -q "model=200" "$olog" 2>/dev/null' || true
  check "  the box on $NODE calls the model from its node" 'grep -q "model=200" "$olog"'
  check "  the credential is on no disk: not in the node's data dir, nor under /tmp" \
    '! grep -rlsF "$value" "$nd" && ! timeout 60 grep -rlsF --exclude-dir="$(basename "$work")" "$value" /tmp'
  check "  the node fetched it once, for this run, and the control host audited it" \
    '[ "$(w audit --tail 2000 | grep node.secret_fetch | grep -c "$r")" -ge 1 ] && [ "$(w audit --tail 2000 | grep node.secret_fetched | grep -c "$r")" -eq 1 ]'
  log "cutting $r's control channel"
  mv "$nd/ctl/ctl.sock" "$nd/ctl/ctl.sock.off"
  local t_cut; t_cut=$(date +%s%3N)
  kill_tree() { local c; for c in $(pgrep -P "$1"); do kill_tree "$c"; done; kill "$1" 2>/dev/null || true; }
  local c; for c in $(pgrep -P "$run_pid"); do kill_tree "$c"; done
  sleep 90
  log "restarting acc-n1's serve while cut off: its secret cache goes with it"
  kill "$node_serve_pid" 2>/dev/null || true
  wait "$node_serve_pid" 2>/dev/null || true
  HOME=$nodehome "$nodehome/.local/bin/wicket" node serve >>"$work/node-serve.log" 2>&1 &
  node_serve_pid=$!
  pids+=("$node_serve_pid")
  local t_rs; t_rs=$(date +%s%3N)
  wait_for 90 '[ -S "$nd/ctl/ctl.sock" ]' || true
  # The new serve made a fresh socket: keep the box's control host out until the cut ends.
  mv "$nd/ctl/ctl.sock" "$nd/ctl/ctl.sock.off" 2>/dev/null || true
  # The wake fence (#153): its box may still run on the cut-off node, so it isn't woken elsewhere.
  w wake "$r" >"$work/wake-cut.log" 2>&1 || true
  sleep 75
  local t_restore; t_restore=$(date +%s%3N)
  mv "$nd/ctl/ctl.sock.off" "$nd/ctl/ctl.sock"
  log "restored after $(( (t_restore - t_cut) / 1000 )) s"
  span() { awk -v a="$1" -v b="$2" -v k="$3" '$1>=a && $1<b && $0 ~ k' "$olog" | wc -l; }
  echo "   before the restart: $(span "$t_cut" "$t_rs" model=200:) model calls ok, $(span "$t_cut" "$t_rs" ' write=') lines;" \
    "after it: $(span $((t_rs + 5000)) "$t_restore" model=503:credential) refused for want of the credential, $(span $((t_rs + 5000)) "$t_restore" 'write=') lines"
  check "  cut off, the box kept calling the model and writing (until the restart)" \
    '[ "$(span "$t_cut" "$t_rs" model=200:)" -ge 12 ] && [ "$(span "$t_cut" "$t_rs" " write=[0-9]+:- ")" -ge 12 ]'
  check "  after the restart, still cut off: model calls fail clearly, plain egress goes on past 155 s" \
    '[ "$(span $((t_rs + 5000)) "$t_restore" model=503:credential)" -ge 5 ] && [ "$(span $((t_cut + 155000)) "$t_restore" " write=[0-9]+:- ")" -ge 1 ]'
  check "  a wake while cut off is refused: the box may still run there, until its authority ends" \
    'grep -q "can.t be woken yet" "$work/wake-cut.log" && grep -q "may still be running on node $NODE" "$work/wake-cut.log" && grep -q "can be woken from" "$work/wake-cut.log"'
  check "  an out-of-reach request was queued on the node while it was cut off" '[ "$(span "$t_cut" "$t_restore" ":queued")" -ge 1 ]'
  wait_for 40 '[ "$(span "$t_restore" 99999999999999 model=200:)" -ge 1 ]' || true
  check "  reconnected, the credential is fetched again and model calls work" '[ "$(span "$t_restore" 99999999999999 model=200:)" -ge 1 ]'
  check "  and the miss while cut off is in the node's audit, shipped on reconnect" 'w audit --tail 3000 | grep node.secret_unavailable | grep -q "$r"'
  wait_for 20 '! grep -q "q-" "$nd/asks.json" 2>/dev/null' || true
  check "  and the queued ask was delivered to the control host" '! grep -q "q-" "$nd/asks.json" && w pending | grep -q "example.com/out-of-reach"'
  wroot secret rm mock-offline >/dev/null
  local t_rm; t_rm=$(date +%s%3N)
  sleep 20
  check "  a secret removed on the control host is dropped by the node within seconds" \
    '[ "$(span $((t_rm + 10000)) 99999999999999 model=200:)" -eq 0 ] && [ "$(span $((t_rm + 10000)) 99999999999999 model=)" -ge 1 ]'
  # Its authority ends 5 min after the run started: its node stops it then.
  # The node removes the run's directory once the box has ended: keep a copy of its log as it goes.
  local kept=$work/offline-box.log
  wait_for 240 'cp "$olog" "$kept" 2>/dev/null; [ -z "$(box_of "$r")" ]' || true
  local until; until=$(grep -o "$r: its authority expired at [0-9]* ms" "$work/node-serve.log" | grep -o '[0-9]* ms' | grep -o '[0-9]*' | tail -1 || true)
  local last; last=$(tail -1 "$kept" 2>/dev/null | awk '{print $1}' || true)
  echo "   authority ended at ${until:-?} ms; the box's last line $(( (${last:-0} - ${until:-0}) / 1000 )) s from it"
  check "  its node stopped the box when its authority expired" '[ -n "$until" ] && [ -n "$last" ] && [ -z "$(box_of "$r")" ] && [ "$last" -le $((until + 7000)) ]'
  check "  the node's audit records it" 'w audit --tail 2000 | grep -q "node.authority_expired"'
  wait_for 60 '! kill -0 "$run_pid" 2>/dev/null' || true
  check "  and its run ended" '! kill -0 "$run_pid" 2>/dev/null'
  # The node reported the box stopped: the fence is down (what wake says next is about the agent).
  w wake "$r" >"$work/wake-after.log" 2>&1 || true
  check "  once the node reported the box stopped, a wake is no longer fenced" '! grep -q "can.t be woken yet" "$work/wake-after.log" && w audit --tail 3000 | grep agent.wake_refused | grep -q "$r"'
  check "  and still nothing of the credential on disk" '! grep -rlsF "$value" "$nd"'
}

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
#          within money limits of $0.05 an hour and $0.05 in total (owner tag wicket-owner-acc.wicket.test). The agent image is loaded onto the node over its pinned ssh.

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
  if wroot node list --owner acc.wicket.test 2>/dev/null | grep -q "^0 node(s) tagged"; then
    echo "teardown: no tagged Vultr machine remains"
  else
    ACC_KEEP=1   # keep the ledger: it is how this machine is found and released
    echo "!!!! TEARDOWN: a Vultr machine tagged for this test may remain, and it bills by the hour. Now:"
    echo "!!!!   WICKET_HOME=${WICKET_HOME:-$datadir} wicket node list --owner acc.wicket.test"
    echo "!!!!   WICKET_HOME=${WICKET_HOME:-$datadir} wicket node release --owner acc.wicket.test <instance id>"
    wroot node list --owner acc.wicket.test 2>&1 | sed 's/^/!!!! /'
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
  # Delegation across nodes (#252) only with a local node: its boxes reach the mock model on this host.
  if [ "$nodes" = local ]; then : >"$cap_ws/delegate"; fi
  HOME=$HOMEW "$W" run "$(manifest cap)" --workdir "$cap_ws" --image "$IMAGE_TAG" --node local >"$work/cap.log" 2>&1 &
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
  # Delegation across nodes (#252): an agent child on the leased node, continued by name.
  if [ "$nodes" = local ]; then
    echo "   delegate: $(cf helper | head -c 300)"
    check "the agent delegated to an agent child on the other node (spawn with placement {lease})" \
      'cf helper | grep -q "^started agent helper as run run_[a-z0-9]* on node ${node_name:-?}" && cf helper | grep -q "d-"'
    check "  its report on its task came back as a message from its child" \
      '[ "$(cf report1 | jq -r .from.relation)" = "your child" ] && [ "$(cf report1 | jq -r .body.turn)" = 1 ] && cf report1 | jq -r .body.delegation | grep -q "^d-"'
    check "  continue_child gave it another brief on that node" 'cf continued | grep -q "^continued helper (d-[a-z0-9]*) with turn 2"'
    check "  and its report on that one came back too, the same delegation" \
      '[ "$(cf report2 | jq -r .body.turn)" = 2 ] && [ "$(cf report2 | jq -r .body.delegation)" = "$(cf report1 | jq -r .body.delegation)" ]'
    check "  the delegation records both reports" 'cf delegations | grep -q "$(cf report1 | jq -r .body.delegation)"'
  fi

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
    check "  no tagged machine remains (wicket node list)" 'wroot node list --owner acc.wicket.test 2>/dev/null | grep -q "^0 node(s) tagged"'
    echo "   Vultr: the lease ${billed:-billed ?}; compare with the account's billing for this instance"
  else
    check "  no box remains on the node" '[ -z "$(for r in $(all_descendants); do box_of "$r"; done)" ]'
  fi
  results+=("info lease ${lease:-?} on node ${node_name:-?}: ${billed:-billed ?}")
}

# The escape box (#326, ci/acceptance/escape.yaml) on the other node: the same attempts, decided by
# that node's proxies, with the same checks (the canary on this host, which is the node's too when
# the node is local, and the audit the node shipped).
escape_flow() {
  log "a box trying to get out of its reach, on $NODE"
  local ws; ws=$(workdir escape)
  sed -i "s/HOST_IP/${host_ip:-127.0.0.1}/g; s/CANARY_PORT/$canary_port/g" "$ws/escape.sh"
  : >"$work/canary.log"
  HOME=$HOMEW "$W" run "$(manifest escape)" --workdir "$ws" --image "$IMAGE_TAG" --node "$NODE" >"$work/escape-node.log" 2>&1 || true
  local r; r=$(run_id_of "$work/escape-node.log")
  our_runs+=("$r")
  local out; out=$(data "runs/$r/workspace/out/escape.log" 2>/dev/null || cat "$nodehome/.local/share/wicket-node/runs/$r/workspace/out/escape.log" 2>/dev/null || true)
  sed 's/^/   /' <<<"$out"
  check "  on $NODE too: every attempt refused, none ESCAPED" '[ "$(grep -c " blocked " <<<"$out")" -ge 25 ] && ! grep -q " ESCAPED " <<<"$out"'
  check "  and the canary saw no request" '[ ! -s "$work/canary.log" ]'
  check "  and the audit its node shipped allowed nothing but GET example.com/ (and resolved no other name)" '[ -z "$(esc_unexpected "$r")" ] || { esc_unexpected "$r"; false; }'
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
  w node list >"$work/node-list.log" 2>&1 || true
  check "  wicket node list shows what $NODE holds for it: authority, secrets by name, budget slice" \
    'grep -A20 "^$NODE " "$work/node-list.log" | grep "$r" | grep "authority until" | grep "secrets mock-offline" | grep -q "budget slice up to" && ! grep -q "$value" "$work/node-list.log"'
  log "cutting $r's control channel"
  mv "$nd/ctl/ctl.sock" "$nd/ctl/ctl.sock.off"
  local t_cut; t_cut=$(date +%s%3N)
  kill_tree() { local c; for c in $(pgrep -P "$1"); do kill_tree "$c"; done; kill "$1" 2>/dev/null || true; }
  local c; for c in $(pgrep -P "$run_pid"); do kill_tree "$c"; done
  # Decisions at the edge (#164): cut off, the agent calls its gateway (drive.sh's edge_calls).
  sleep 5
  touch "$nd/runs/$r/workspace/edge.go"
  local elog=$nd/runs/$r/workspace/out/edge.log
  wait_for 60 'grep -q "^pending=" "$elog" 2>/dev/null' || true
  cp "$elog" "$work/edge.log" 2>/dev/null || true
  local kid; kid=$(grep -o 'spawn=started program edgekid as run run_[a-z0-9]*' "$elog" 2>/dev/null | grep -o 'run_[a-z0-9]*' || true)
  check "  cut off, its node answers whoami from the box's token" 'grep -q "^whoami=$r|node $NODE" "$elog"'
  check "  cut off, request_access is queued on the node (q-…) for a human" 'grep -q "^access=queued: q-" "$elog" && grep -q "^pending=[1-9]" "$elog"'
  check "  cut off, a narrower child starts on the node, its token attenuated there" \
    '[ -n "$kid" ] && grep -q "within your own" "$elog" && [ -n "$(box_of "$kid")" ] && grep -q "\"run\":\"$kid\".*\"box_path\":\"$r/$kid\"" "$nd/runs/$kid/derived.json"'
  sleep 80
  log "restarting acc-n1's serve while cut off: its secret cache goes with it"
  local old_serve=$node_serve_pid
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
  # So a failure of the checks below explains itself (#236): what the box's model calls got after the
  # restart, and whether the serve that answered them is the new one.
  echo "   serve pid $old_serve → $node_serve_pid (old one $(kill -0 "$old_serve" 2>/dev/null && echo "STILL RUNNING" || echo gone));" \
    "after the restart the box's model calls got: $(awk -v a=$((t_rs + 5000)) -v b="$t_restore" '$1>=a && $1<b' "$olog" \
      | grep -o 'model=[^ ]*' | sort | uniq -c | awk '{printf "%s×%s ", $1, $2}')"
  [ "${ACC_KEEP:-}" = 1 ] && cp "$olog" "$work/offline-box-cut.log" 2>/dev/null
  echo "   before the restart: $(span "$t_cut" "$t_rs" model=200:) model calls ok, $(span "$t_cut" "$t_rs" ' write=') lines;" \
    "after it: $(span $((t_rs + 5000)) "$t_restore" model=503:credential) refused for want of the credential, $(span $((t_rs + 5000)) "$t_restore" 'write=') lines"
  check "  cut off, the box kept calling the model and writing (until the restart)" \
    '[ "$(span "$t_cut" "$t_rs" model=200:)" -ge 12 ] && [ "$(span "$t_cut" "$t_rs" " write=[0-9]+:- ")" -ge 12 ]'
  check "  after the restart, still cut off: model calls fail clearly, plain egress goes on past 155 s" \
    '[ "$(span $((t_rs + 5000)) "$t_restore" model=503:credential)" -ge 5 ] && [ "$(span $((t_cut + 155000)) "$t_restore" " write=[0-9]+:- ")" -ge 1 ]'
  check "  a wake while cut off is refused: the box may still run there, until its authority ends" \
    'grep -q "not woken yet" "$work/wake-cut.log" && grep -q "may still be running on node $NODE" "$work/wake-cut.log" && grep -q "can be woken from" "$work/wake-cut.log"'
  check "  an out-of-reach request was queued on the node while it was cut off" '[ "$(span "$t_cut" "$t_restore" ":queued")" -ge 1 ]'
  wait_for 40 '[ "$(span "$t_restore" 99999999999999 model=200:)" -ge 1 ]' || true
  check "  reconnected, the credential is fetched again and model calls work" '[ "$(span "$t_restore" 99999999999999 model=200:)" -ge 1 ]'
  check "  and the miss while cut off is in the node's audit, shipped on reconnect" 'w audit --tail 3000 | grep node.secret_unavailable | grep -q "$r"'
  wait_for 20 '! grep -q "q-" "$nd/asks.json" 2>/dev/null' || true
  check "  and the queued ask was delivered to the control host" '! grep -q "q-" "$nd/asks.json" && w pending | grep -q "example.com/out-of-reach"'
  check "  and so was request_access's, in the agent's words" 'w pending | grep -A1 "example.com/ahead" | grep -q "asked by the agent"'
  check "  the child kept running through the serve restart (its derived authority kept on the node)" '[ -n "$kid" ] && [ -n "$(box_of "$kid")" ]'
  wait_for 60 'w audit --tail 3000 | grep spawn.adopted | grep -q "${kid:-none}"' || true
  check "  reconnected, the control host checks the child again and takes it over" \
    '[ -n "$kid" ] && w audit --tail 3000 | grep spawn.adopted | grep -q "$kid" && w audit --tail 3000 | grep node.spawned | grep -q "$kid"'
  wait_for 60 '! grep -q "\"${kid:-none}\"" "$nd/edge.json"' || true
  check "  and its run is in the ledger, supervised here, its token now from the feed" \
    '[ -n "$kid" ] && data_ls "runs/$kid/ctl" | grep -qx run.json && ! grep -q "\"$kid\"" "$nd/edge.json"'
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
  check "  once the node reported the box stopped, a wake is no longer fenced" '! grep -q "not woken yet" "$work/wake-after.log" && w audit --tail 3000 | grep agent.wake_refused | grep -q "$r"'
  check "  and still nothing of the credential on disk" '! grep -rlsF "$value" "$nd"'
}

# The agent-to-agent protocol across nodes (#252), --nodes local: msg-b (ci/acceptance/msg-b.yaml)
# on acc-n1 and msg-a (msg-a.yaml) on the control host's own node. msg-a finds msg-b through the
# gateway, messages it and follows the receipt to read; msg-b answers (a reply needs no
# accept_from) and then writes to msg-a unasked, which is refused with a receipt that says why.
# Then a human: `wicket message send` to msg-a, which reads it as its operator's and answers into
# the operator's `wicket message inbox`, with receipts on both sides.
messages_flow() {
  log "messages between boxes on two nodes, and with their operator"
  local wb wa rb ra pb pa
  wb=$(workdir msg-b)
  HOME=$HOMEW "$W" run "$(manifest msg-b)" --workdir "$wb" --image "$IMAGE_TAG" --node "$NODE" >"$work/msg-b.log" 2>&1 &
  pb=$!
  pids+=("$pb")
  wait_for 90 '[ -n "$(run_id_of "$work/msg-b.log")" ]' || true
  rb=$(run_id_of "$work/msg-b.log")
  our_runs+=("$rb")
  local nd=$nodehome/.local/share/wicket-node
  # msg-b's results: on acc-n1 while its box runs, then the copy taken before it is let go.
  bres() { cat "$work/msg-b.json" 2>/dev/null || cat "$nd/runs/$rb/workspace/out/result.json" 2>/dev/null; }
  bf() { bres | jq -r ".$1 // empty" 2>/dev/null; }
  wait_for 120 '[ "$(bf started)" = 1 ]' || true
  wa=$(workdir msg-a)
  HOME=$HOMEW "$W" run "$(manifest msg-a)" --workdir "$wa" --image "$IMAGE_TAG" --node local >"$work/msg-a.log" 2>&1 &
  pa=$!
  pids+=("$pa")
  wait_for 90 '[ -n "$(run_id_of "$work/msg-a.log")" ]' || true
  ra=$(run_id_of "$work/msg-a.log")
  our_runs+=("$ra")
  ares() { data "runs/$ra/workspace/out/result.json" 2>/dev/null; }
  af() { ares | jq -r ".$1 // empty" 2>/dev/null; }
  # Box to box, across the nodes.
  wait_for 300 '[ -n "$(af reply)" ] && [ "$(bf done)" = 1 ]' || true
  # Keep msg-b's results, then let its box end (it waits for out/go): it must be gone before
  # offline_flow cuts acc-n1's channel.
  cat "$nd/runs/$rb/workspace/out/result.json" >"$work/msg-b.json" 2>/dev/null || true
  touch "$nd/runs/$rb/workspace/out/go" 2>/dev/null || true
  echo "   msg-a: $(ares | head -c 1500)"
  echo "   msg-b: $(bres | head -c 1500)"
  check "msg-a, on the control host's node, found msg-b on $NODE through the gateway" \
    '[ "$(af b_entry | jq -r .agent)" = msg-b ] && [ "$(af b_entry | jq -r .may_send_to)" = true ]'
  check "  messaged it, and its receipt says read" 'af sent | grep -q "^sent" && af receipt | grep -q "\"state\": *\"read\""'
  check "  msg-b read it with msg-a verified as the sender, and its reply came back across" \
    '[ "$(bf got | jq -r .from.id)" = "$(af you)" ] && [ "$(af reply | jq -r .from.id)" = "$(af b)" ] && [ "$(af reply | jq -r .in_reply_to)" = "$(af mid)" ] && [ "$(af reply | jq -r .body)" = "pong from msg-b" ]'
  check "  msg-b writing to msg-a unasked is refused, with a receipt that says why" \
    'bf unasked | grep -q "^refused: m-" && bf unasked | grep -q "does not accept messages from you"'
  check "  and the refusal is on the record" '[ -n "$(af you)" ] && w audit --tail 3000 | grep message.refused | grep -q "$(af you)"'
  # The operator: the human who started msg-a is the one it acts for.
  check "msg-a lists the operator it acts for" '[ -n "$(af operator)" ] && [ -n "$(af you)" ] && [ "$(w message principals --json 2>"$work/msg-principals.err" | jq -r --arg a "$(af you)" ".[] | select(.id == \$a) | .relation")" = "acts for you" ]'
  wait_for 120 'data_ls "runs/$ra/workspace/out" | grep -qx await-operator' || true
  w message send "$(af you)" "status, please" --json >"$work/msg-send.json" 2>"$work/msg-send.err" || true
  check "  wicket message send reached msg-a, signed as the operator" '[ "$(jq -r .receipt.state "$work/msg-send.json")" != refused ] && jq -r .id "$work/msg-send.json" | grep -q "^m-"'
  wait_for 120 '[ "$(af done)" = 1 ]' || true
  check "  msg-a read it as its operator's message" \
    '[ "$(af op_msg | jq -r .from.relation)" = "your operator" ] && [ "$(af op_msg | jq -r .from.id)" = "$(af operator)" ] && [ "$(af op_msg | jq -r .body)" = "status, please" ]'
  w message inbox --json >"$work/msg-inbox.json" 2>"$work/msg-inbox.err" || true
  check "  and its answer is in the operator's inbox, verified" \
    'jq -e --arg a "$(af you)" --arg m "$(jq -r .id "$work/msg-send.json")" "map(select(.from == \$a and .in_reply_to == \$m and .body == \"seen, thanks\")) | length == 1" "$work/msg-inbox.json" >/dev/null'
  w message receipts --json >"$work/msg-receipts.json" 2>"$work/msg-receipts.err" || true
  check "  and the operator's receipt says read" \
    'jq -e --arg m "$(jq -r .id "$work/msg-send.json")" "map(select(.message_id == \$m and .state == \"read\")) | length == 1" "$work/msg-receipts.json" >/dev/null'
  # msg-a's own receipt: the operator's read of its message is on the record, for that message id.
  local back; back=$(af op_reply | grep -o 'm-[a-z0-9]*' | head -1 || true)
  check "  and msg-a's receipt for its answer says read, once the operator read it" \
    '[ -n "$back" ] && w audit --tail 3000 | grep message.read | grep -q "\"$back\""'
  # Both runs end, and msg-b's box is gone from acc-n1 before the next flow cuts its channel.
  wait_for 120 '! kill -0 "$pa" 2>/dev/null && ! kill -0 "$pb" 2>/dev/null' || true
  wait_for 60 '[ -z "$(box_of "$rb")" ]' || true
  check "  both runs ended, and msg-b's box is gone from $NODE" '! kill -0 "$pa" 2>/dev/null && ! kill -0 "$pb" 2>/dev/null && [ -z "$(box_of "$rb")" ]'
}

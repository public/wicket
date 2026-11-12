#!/usr/bin/env bash
# The acceptance test for a release (#41): wicket's main flows against the real agent image, gVisor
# and Docker, each outcome checked, a summary at the end, and everything it made torn down (on
# failure too). Agents are driven by `wicket dev mock-llm`: no model credential is used.
#
#   ci/acceptance.sh [--installed] [--nodes local|vultr]
#
#   (default)        development mode: this checkout's binary (WICKET, default target/debug/wicket),
#                    a fresh data dir and vault, boxes named acc-*, its own image tag.
#   --installed      as an operator against an installed system (deploy/install.sh): the `wicket` on
#                    PATH talking to wicketd, privileged steps through `sudo -n wicket` (the host
#                    break-glass), the installation's own data and image unless IMAGE is set. Boxes
#                    are wicketd's (named wicket-*); only the runs this script started are touched.
#   --nodes local    also the multi-host flow, with localhost as the node (the static placement
#                    backend; only the ssh hop is replaced, as in ci/node-e2e.sh --local).
#   --nodes vultr    the multi-host flow on a fresh Vultr node, through placement (`backend: vultr`,
#                    the cheapest plan, `max_total_usd: 0.05`). It SPENDS MONEY: needs ACC_VULTR=yes,
#                    the vault secret vultr-api-key (or ACC_VULTR_API_KEY_FILE, linked by reference),
#                    ACC_VULTR_SSH_KEY_ID and ACC_VULTR_SSH_KEY.
#                    Never run in CI.
#
# Local flows (each a check, or several):
#   - an agent starts (gVisor, no network) and its egress is decided: HTTP/1.1 and HTTP/3, in reach
#     and out of it, a forbidden host that doesn't resolve;
#   - one request is approved and another denied (`wicket approve` / `wicket deny`), and the agent's
#     await_grant and retry see each decision;
#   - `spawn` of a narrower zone starts at once; a wider one with ask_human waits for a human, then
#     starts;
#   - `link` wires two of the agent's boxes, and one fetches a page from the other across it;
#   - revoking the agent's identity stops its whole subtree (children and a grandchild);
#   - an agent hibernates and is woken: its files and its session survive;
#   - an orphaned box (its `wicket run` killed hard) is taken over by `wicket reconcile`, and after
#     it is revoked a dry run has nothing to change;
#   - a control-host restart (#151): every wicket process of the control host killed hard, the boxes
#     on this host's own node and (--nodes local) on the other node survive, reconcile adopts their
#     runs, and their next turns reach the model and the gateway; then each node's `serve` alone is
#     killed and restarted, and the same boxes take one more turn each;
#   - `wicket audit --verify`, and audit export to a JSON-lines sink checked with `--against` (a
#     tampered copy of the export is refused).
#
# Env: WICKET (binary), IMAGE (an existing agent image: not built, not removed), H3GET (a prebuilt
# static ci/h3get), WICKET_DOCKER (e.g. "sudo -n docker"), ACC_KEEP=1 (keep the work dir), ACC_TMP
# (where the work dir goes, default /tmp: keep it short, the runs' unix sockets live under it).
set -euo pipefail
cd "$(dirname "$0")/.."

mode=dev nodes=
while [ $# -gt 0 ]; do
  case "$1" in
    --installed) mode=installed; shift ;;
    --nodes) nodes=${2:?--nodes local|vultr}; shift 2 ;;
    --vultr) nodes=vultr; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
done
case "$nodes" in "" | local | vultr) ;; *) echo "--nodes: local or vultr" >&2; exit 2 ;; esac
if [ "$nodes" = vultr ] && [ "${ACC_VULTR:-}" != yes ]; then
  echo "--nodes vultr creates a billed Vultr instance: set ACC_VULTR=yes to confirm" >&2
  exit 2
fi

DOCKER=${WICKET_DOCKER:-docker}
export WICKET_DOCKER=$DOCKER
# Short: a run's unix sockets live under it, and sun_path holds 107 bytes.
work=$(mktemp -d "${ACC_TMP:-/tmp}/wacc.XXXXXX")
chmod 755 "$work"
if [ ${#work} -gt 24 ]; then echo "$work: too long a path for the runs' sockets (ACC_TMP=/tmp)" >&2; rm -rf "$work"; exit 2; fi
pids=()
our_runs=()
built_image=

if [ "$mode" = dev ]; then
  W=$(realpath "${WICKET:-target/debug/wicket}")
  # A data dir and a vault of our own: the vault is $HOME/.config/wicket/secrets. With --nodes
  # vultr, the operator's own vault, which holds the Vultr API key (the `mock` secret is added to it).
  export WICKET_HOME=$work/home HOME_FOR_WICKET=$work/userhome
  [ "$nodes" = vultr ] && HOME_FOR_WICKET=$HOME
  mkdir -p "$WICKET_HOME" "$HOME_FOR_WICKET"
  export WICKET_BOX_PREFIX=acc
  HOMEW=$HOME_FOR_WICKET
  w() { HOME=$HOME_FOR_WICKET "$W" "$@"; }
  wt() { local t=$1; shift; HOME=$HOME_FOR_WICKET timeout "$t" "$W" "$@"; }
  wroot() { w "$@"; }
  data() { cat "$WICKET_HOME/$1"; }
  data_ls() { ls "$WICKET_HOME/$1" 2>/dev/null; }
  box_filter=(--filter name=^acc-run-)
else
  W=$(command -v wicket) || { echo "--installed: no wicket on PATH" >&2; exit 2; }
  unset WICKET_HOME
  HOMEW=$HOME
  w() { "$W" "$@"; }
  wt() { local t=$1; shift; timeout "$t" "$W" "$@"; }
  wroot() { (cd / && sudo -n "$W" "$@"); }
  # The data is the wicket user's (mode 0700): read through sudo.
  datadir=/var/lib/wicket
  data() { sudo -n cat "$datadir/$1"; }
  data_ls() { sudo -n ls "$datadir/$1" 2>/dev/null; }
  box_filter=(--filter label=wicket=1)
fi
IMAGE_TAG=${IMAGE:-}

# The multi-host flow and its teardown (defined before the EXIT trap can need them).
# shellcheck source=ci/acceptance/nodes.sh
[ -z "$nodes" ] || . ci/acceptance/nodes.sh

# ---- results ----
results=()
fail=0
# Checks and waits run without pipefail: `... | grep -q` may stop reading early, and its writer's
# SIGPIPE isn't a failure.
check() {
  if (set +o pipefail; eval "$2"); then results+=("ok   $1"); echo "ok   $1"; else results+=("FAIL $1"); echo "FAIL $1"; fail=1; fi
}
skip() { results+=("skip $1 ($2)"); echo "skip $1 ($2)"; }
log() { echo "== $(date +%T) $*"; }

# ---- teardown: on every exit ----
our_boxes() {
  # Our boxes: by name prefix in dev mode, by the run label of the runs we started otherwise.
  if [ "$mode" = dev ]; then
    $DOCKER ps -aq "${box_filter[@]}" 2>/dev/null || true
  else
    local r
    for r in "${our_runs[@]}" $(all_descendants); do $DOCKER ps -aq --filter "label=wicket.run=$r" 2>/dev/null || true; done
  fi
}
all_descendants() {
  # Every run started under one of ours (children's spawn records live in their parent's run dir).
  local todo=("${our_runs[@]}") r c
  while [ ${#todo[@]} -gt 0 ]; do
    r=${todo[0]}; todo=("${todo[@]:1}")
    for c in $(data_ls "runs/$r/children" | sed -n 's/^\(run_[a-z0-9]*\)\.yaml$/\1/p'); do echo "$c"; todo+=("$c"); done
  done
}
teardown() {
  local status=$?
  set +e
  trap - EXIT INT TERM
  if [ "$nodes" = vultr ]; then vultr_teardown; fi
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${pids[@]}"; do kill -9 "$p" 2>/dev/null; done
  wait 2>/dev/null
  for c in $(our_boxes); do $DOCKER rm -f "$c" >/dev/null 2>&1; done
  if [ -n "$built_image" ]; then $DOCKER rmi "$built_image" >/dev/null 2>&1; fi
  if [ "$nodes" = local ]; then node_local_teardown; fi
  if [ -n "${sinks_file:-}" ]; then sudo -n rm -f "$sinks_file"; fi
  if [ "${ACC_KEEP:-}" = 1 ]; then
    echo "kept: $work"
  else
    chmod -R u+w "$work" 2>/dev/null
    rm -rf "$work"
  fi
  left=$(our_boxes | wc -l)
  [ "$left" = 0 ] || echo "WARNING: $left box(es) left behind"
  exit "$status"
}
trap teardown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
# Waits up to $1 seconds for the command in $2 to succeed.
wait_for() { local n=$1; shift; for _ in $(seq "$n"); do (set +o pipefail; eval "$1") && return 0; sleep 1; done; return 1; }
run_id_of() { sed -n 's/^wicket run \(run_[a-z0-9]*\).*/\1/p' "$1" | head -1; }
result_of() { sed -n 's/^\[wicket\] result.json: //p' "$1" | tail -1; }
box_of() { $DOCKER ps -q --filter "label=wicket.run=$1" 2>/dev/null; }
manifest() { sed "s#MOCK_PORT#$port#" "ci/acceptance/$1.yaml" >"$work/$1.yaml"; echo "$work/$1.yaml"; }
workdir() { mkdir -p "$work/$1"; cp "ci/acceptance/$1/"* "$work/$1/"; echo "$work/$1"; }

# ---- setup ----
log "setup ($mode mode${nodes:+, nodes: $nodes})"
if [ "$mode" = dev ]; then
  wroot identity init --trust-domain acc.wicket.test >/dev/null
fi
printf 'mock-model-credential' | wroot secret set mock --hosts 127.0.0.1 >/dev/null
if [ -z "$IMAGE_TAG" ]; then
  if [ "$mode" = dev ]; then
    IMAGE_TAG=wicket/claude-code:acc-$$
    log "building the agent image $IMAGE_TAG"
    w image --tag "$IMAGE_TAG" >"$work/image.log" 2>&1 || { tail -30 "$work/image.log"; exit 1; }
    built_image=$IMAGE_TAG
  else
    IMAGE_TAG=wicket/claude-code:poc   # what install.sh built
  fi
fi
# The HTTP/3 client, static so it runs on the image's C library.
if [ -n "${H3GET:-}" ]; then
  cp "$H3GET" "$work/h3get"
else
  cargo build -q --release --locked --target x86_64-unknown-linux-musl --manifest-path ci/h3get/Cargo.toml
  cp ci/h3get/target/x86_64-unknown-linux-musl/release/h3get "$work/h3get"
fi
# Audit export: a JSON-lines sink, fed by every wicket process (checkpoints every minute).
if [ "$mode" = dev ]; then
  printf 'checkpoint_every: 1m\nsinks:\n  - {name: acc, type: jsonl, path: %s}\n' "$work/audit.jsonl" >"$WICKET_HOME/audit-sinks.yaml"
  sink=$work/audit.jsonl
elif [ "${ACC_AUDIT_SINK:-}" = 1 ]; then
  # Opted in (a disposable installation): a sink of our own in the installation's sinks file.
  sudo -n install -d -o wicket -g wicket -m 0700 "$work/sink"
  printf 'checkpoint_every: 1m\nsinks:\n  - {name: acc, type: jsonl, path: %s}\n' "$work/sink/audit.jsonl" \
    | sudo -n install -o wicket -g wicket -m 0600 /dev/stdin "$datadir/audit-sinks.yaml"
  sinks_file=$datadir/audit-sinks.yaml
  sink=$work/audit.jsonl   # a copy, read through sudo (the wicket user's files are 0600)
fi

port=$(free_port)
# Every agent's turn runs one command: its workspace's drive.sh, or, for the lead's child agent (an
# empty workspace), spawn a leaf box and stay up until revoked.
leaf='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"spawn","arguments":{"name":"leaf","kind":"program","zone":{"limits":{"memory":"128m","cpus":1,"timeout":"4m"}},"command":["sleep","3000"]}}}'
mock_cmd="[ -f /workspace/drive.sh ] && exec bash /workspace/drive.sh; curl -s -m 120 http://wicket.internal:8081/ -H 'content-type: application/json' -d '$leaf'; sleep 500"
HOME=$HOMEW "$W" dev mock-llm --listen "127.0.0.1:$port" --command "$mock_cmd" 2>"$work/mock.log" &
pids+=("$!")
wait_for 10 "(exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null"

# ---- 1. an agent: egress, approvals, spawn, link, subtree revoke ----
log "lead agent: egress, approve and deny, spawn, link"
lead_ws=$(workdir lead)
cp "$work/h3get" "$lead_ws/h3get"
HOME=$HOMEW "$W" run "$(manifest lead)" --workdir "$lead_ws" --image "$IMAGE_TAG" >"$work/lead.log" 2>&1 &
lead_pid=$!
pids+=("$lead_pid")
wait_for 60 '[ -n "$(run_id_of "$work/lead.log")" ]' || true
lead=$(run_id_of "$work/lead.log")
our_runs+=("$lead")
check "the lead agent started (run ${lead:-?})" '[ -n "$lead" ]'
lres() { data "runs/$lead/workspace/out/result.json" 2>/dev/null; }
lf() { lres | jq -r ".$1 // empty" 2>/dev/null; }

# Answer the requests the lead waits on, until its steps are done (or 6 minutes).
decided=" "
deadline=$((SECONDS + 360))
while [ $SECONDS -lt $deadline ] && [ "$(lf done)" != 1 ] && kill -0 "$lead_pid" 2>/dev/null; do
  while read -r rid rest; do
    case "$decided" in *" $rid "*) continue ;; esac
    case "$rest" in
      *"example.com/acc-approve"*) wroot approve "$rid" >>"$work/decisions.log" 2>&1 && decided+="$rid " ;;
      *"example.com/acc-deny"*) wroot deny "$rid" >>"$work/decisions.log" 2>&1 && decided+="$rid " ;;
      "SPAWN wicket.internal"*) wroot approve "$rid" >>"$work/decisions.log" 2>&1 && decided+="$rid " ;;
    esac
  done < <(w pending 2>/dev/null | grep -E "^r-[a-z0-9]+ .* run $lead " || true)
  sleep 1
done
echo "   result: $(lres)"

check "the box runs on gVisor" 'lf kernel | grep -qi gvisor'
check "a request in reach gets 200" '[ "$(lf allowed)" = 200 ]'
check "a direct connection (no proxy) fails" '[ -n "$(lf direct)" ] && [ "$(lf direct)" != 200 ]'
check "HTTP/3: a request in reach gets 200" '[ "$(lf h3_allowed)" = 200 ]'
check "HTTP/3: a request out of reach gets the 403 from wicket" '[ "$(lf h3_outside | cut -d: -f1)" = 403 ]'
check "HTTP/3: a forbidden host does not resolve" '[ "$(lf h3_forbidden)" = nxdomain ]'
check "an out-of-reach request became a pending request" '[ -n "$(lf approve_rid)" ] && [ -n "$(lf deny_rid)" ]'
check "wicket approve: the agent's await_grant saw it granted" 'lf approve_wait | grep -q "^granted"'
check "  and its retry got through" '[ -n "$(lf approve_retry)" ] && [ "$(lf approve_retry)" != 403 ] && [ "$(lf approve_retry)" != 000 ]'
check "wicket deny: the agent's await_grant saw it denied" 'lf deny_wait | grep -q "^denied"'
check "  and its retry is still refused" '[ "$(lf deny_retry)" = 403 ]'
check "spawn of a narrower zone starts at once" 'lf narrow | grep -q "^started program narrow .*within your own"'
check "spawn of a wider zone (ask_human) waits for a human" 'lf wide_first | grep -q "^needs human approval: request r-"'
check "  and starts once approved" 'lf wide_wait | grep -q "^granted" && lf wide | grep -q "^started program wide .*approved by a human beyond your own zone"'
check "link wires the two children" 'lf link | grep -q "narrow.wicket.internal:8000"'
# A child's output: its log (the supervisor's lines) and its transcript (a program's own output).
child_log() {
  local c
  for c in $(data_ls "runs/$1/children" | sed -n 's/^\(run_[a-z0-9]*\)\.log$/\1/p'); do
    data "runs/$1/children/$c.log"; data "runs/$c/transcript.jsonl" 2>/dev/null
  done
}
wait_for 90 'child_log "$lead" | grep -q "acc-fetched:"' || true
check "the wide box fetched the narrow box's page across the link" 'child_log "$lead" | grep -q "acc-fetched:acc-hello-from-narrow"'
check "the audit log records the spawn approval and the link" 'w audit --tail 400 | grep -q "spawn.beyond_parent" && w audit --tail 400 | grep -q "link.open"'

# The subtree: lead → narrow, wide, mid → leaf.
subtree=$(all_descendants)
subtree_up() { local r n=0; for r in $(all_descendants); do [ -n "$(box_of "$r")" ] || return 1; n=$((n + 1)); done; [ "$n" -ge 4 ]; }
wait_for 60 subtree_up || true
subtree=$(all_descendants)
running=0
for r in "$lead" $subtree; do [ -n "$(box_of "$r")" ] && running=$((running + 1)); done
check "the lead, its 3 children (one an agent) and a grandchild run (5 boxes)" '[ "$running" = 5 ]'

log "revoking the lead"
wroot identity revoke "$lead" --reason "acceptance: revoke the subtree" >"$work/revoke.log" 2>&1 || cat "$work/revoke.log"
gone() { for r in "$lead" $subtree; do [ -z "$(box_of "$r")" ] || return 1; done; }
wait_for 60 gone || true
check "revoking the lead stopped its whole subtree (no box left)" gone
wait_for 30 '! kill -0 "$lead_pid" 2>/dev/null' || true
check "  and its wicket run ended" '! kill -0 "$lead_pid" 2>/dev/null'
check "  and its identity is revoked" 'w identity show "$lead" 2>&1 | grep -qi revoked'

# ---- 2. hibernate and wake ----
log "hibernate and wake"
hib_ws=$(workdir hib)
wt 300 run "$(manifest hib)" --workdir "$hib_ws" --image "$IMAGE_TAG" >"$work/hib1.log" 2>&1 || true
our_runs+=("$(run_id_of "$work/hib1.log")")
agent=$(grep -o "agent agt_[a-z0-9]*" "$work/hib1.log" | head -1 | cut -d" " -f2 || true)
agent_field() { w agents --json | jq -r --arg n "$agent" ".[] | select(.id == \$n) | .$1"; }
check "the agent hibernated after its turn" '[ -n "$agent" ] && grep -q "hibernated in" "$work/hib1.log" && [ "$(agent_field state)" = hibernated ]'
check "  and its box is gone" '[ -z "$(box_of "${our_runs[-1]}")" ]'
gen1=$(agent_field generation)
wt 300 wake "$agent" "Again, please." >"$work/hib2.log" 2>&1 || true
our_runs+=("$(run_id_of "$work/hib2.log")")
hres=$(result_of "$work/hib2.log")
hf() { jq -r ".$1 // empty" <<<"$hres" 2>/dev/null; }
check "wicket wake resumed its own session" 'grep -q "session .* resumed" "$work/hib2.log"'
check "  its files survived (/tmp, \$HOME, workspace, durable volume)" '[ "$(hf tmp)" = tmp-kept ] && [ "$(hf home)" = home-kept ] && [ "$(hf ws)" = ws-kept ] && [ "$(hf vol)" = vol-kept ]'
# A fresh session's requests carry 2 and 4 messages; the resumed one's carry the earlier turn too.
check "  and the model saw the earlier conversation, then the operator's text" 'grep -qE "finish \(([5-9]|[1-9][0-9]) messages" "$work/mock.log" && grep "the user said:" "$work/mock.log" | grep -q "Again, please."'
check "  and the generation went up by one" '[ "$(agent_field generation)" = $((gen1 + 1)) ]'

# ---- 3. reconcile: an orphaned box ----
# Its supervisor killed hard, the box runs on (on this host's own node); reconcile takes its run over
# instead of ending it (#151), and the run ends when it is revoked.
log "reconcile: a box whose wicket run was killed hard"
HOME=$HOMEW "$W" run "$(manifest orphan)" --image "$IMAGE_TAG" >"$work/orphan.log" 2>&1 &
orphan_pid=$!
pids+=("$orphan_pid")
wait_for 90 'grep -q acc-orphan-up "$work/orphan.log" 2>/dev/null' || true
orphan=$(run_id_of "$work/orphan.log")
our_runs+=("$orphan")
# The supervisor named in the box's owner label (<machine>:<pid>:<start>): this `wicket run` in
# development mode, wicketd's child for it when installed (the client only relays).
wait_for 30 '[ -n "$(box_of "$orphan")" ]' || true
sup=$($DOCKER inspect -f '{{index .Config.Labels "wicket.owner"}}' "$(box_of "$orphan" | head -1)" 2>/dev/null | cut -d: -f2 || true)
echo "   killing the supervisor, pid ${sup:-?}"
if [ "$mode" = dev ]; then kill -9 "$sup" 2>/dev/null || true; else sudo -n kill -9 "$sup" 2>/dev/null || true; fi
kill -9 "$orphan_pid" 2>/dev/null || true
wait "$orphan_pid" 2>/dev/null || true
sleep 2
orphan_box=$(box_of "$orphan")
check "the orphan's box outlives its killed wicket run" '[ -n "$orphan" ] && [ -n "$orphan_box" ]'
wroot reconcile --dry-run >"$work/rec-dry1.log" 2>&1 || true
check "reconcile --dry-run reports taking it over, and changes nothing" 'grep -q "^run_adopted .*$orphan" "$work/rec-dry1.log" && [ "$(box_of "$orphan")" = "$orphan_box" ]'
wroot reconcile >"$work/rec.log" 2>&1 || cat "$work/rec.log"
cat "$work/rec.log"
check "reconcile adopted its run: the same box runs on, supervised again (#151)" 'grep -q "^run_adopted .*$orphan" "$work/rec.log" && [ "$(box_of "$orphan")" = "$orphan_box" ]'
wait_for 30 'w audit --tail 50 | grep -q "run.attach *$orphan"' || true
wroot identity revoke "$orphan" --reason "acceptance: end the adopted orphan" >/dev/null 2>&1 || true
# Its new supervisor stops the box, then records the run's end.
wait_for 60 '[ -z "$(box_of "$orphan")" ] && w audit --tail 200 | grep -E "run\.end" | grep -q "$orphan"' || true
check "  and revoking it stops its box and ends its run" '[ -z "$(box_of "$orphan")" ] && w audit --tail 200 | grep -E "run\.end" | grep -q "$orphan"'
wroot reconcile --dry-run >"$work/rec-dry2.log" 2>&1 || true
check "then a dry run has nothing to change" 'grep -q "^reconcile: 0 change(s)" "$work/rec-dry2.log"'
check "no box of ours is left" '[ -z "$(our_boxes)" ]'

# ---- 3b. a box flooding its output (#151, #160) ----
# A box's output is kept on its node's host only up to its zone's limits.output (Docker's log, rotated),
# and the box's audit records what the host dropped. The control host's transcript is bounded the same
# way (the newest kept, run.output in the audit), and so is what the run shows of a program's output.
# A burst faster than the node reads loses what Docker rotates away unread (keep_newest); output at a
# pace the node keeps up with arrives whole across rotations, each line once. With on_output_full:
# stop, the box is stopped instead.
log "a box flooding its output"
HOME=$HOMEW "$W" run "$(manifest flood)" --image "$IMAGE_TAG" >"$work/flood.log" 2>&1 &
flood_pid=$!
pids+=("$flood_pid")
wait_for 30 '[ -n "$(run_id_of "$work/flood.log")" ]' || true
flood=$(run_id_of "$work/flood.log")
our_runs+=("$flood")
# The control host's transcript: the previous file, then the current one. (What the run shows of a
# program's output stops at limits.output, so the end is looked for here.)
flood_transcript() { data "runs/$flood/transcript.1.jsonl" 2>/dev/null; data "runs/$flood/transcript.jsonl" 2>/dev/null; }
wait_for 120 'flood_transcript | grep -q acc-flood-done' || true
flood_box=$(box_of "$flood" | head -1)
flood_logpath=$($DOCKER inspect -f '{{.LogPath}}' "$flood_box" 2>/dev/null || true)
flood_kept=
[ -z "$flood_logpath" ] || flood_kept=$(sudo -n sh -c 'du -cb "$1"* | tail -1' _ "$flood_logpath" 2>/dev/null | cut -f1 || true)
echo "   20 MB burst, then 3 MB paced; ${flood_kept:-?} bytes kept in the host's log"
check "a flooding box's output kept on the host stays within limits.output (1m)" '[ -n "$flood_kept" ] && [ "$flood_kept" -le $((1100 * 1024)) ]'
wait "$flood_pid" 2>/dev/null || true
# What it keeps of the paced lines (the newest, at least 5,000 of them): consecutive, each once, in
# order, through the last.
seq_ok() { flood_transcript | grep -oE 'acc-seq-[0-9]{8}' | awk 'NR == 1 { first = substr($0, 9) + 0 } { if (substr($0, 9) + 0 != first + NR - 1) bad = 1 } END { exit !(NR >= 5000 && first + NR - 1 == 30000 && !bad) }'; }
check "  and the paced lines it kept arrived whole across rotations: consecutive, each once, in order" seq_ok
flood_tsize=$(flood_transcript | wc -c)
echo "   the control host's transcript: $flood_tsize bytes; the run showed $(wc -c <"$work/flood.log") bytes"
check "the control host's transcript of it stays within limits.output (#160)" '[ "$flood_tsize" -le $((1024 * 1024 + 1024)) ] && [ "$flood_tsize" -ge $((512 * 1024)) ]'
check "  and what the run shows of it stops at limits.output, saying so" '[ "$(wc -c <"$work/flood.log")" -le $((2 * 1024 * 1024)) ] && grep -q "passed limits.output; the rest is only in its transcript" "$work/flood.log"'
run_out() { w audit --tail 400 | grep "$flood" | grep run.output | grep -oE "\"$1\"[^0-9]*[0-9]+" | grep -oE '[0-9]+$' | tail -1; }
echo "   run.output: stdout_bytes $(run_out stdout_bytes), stdout_dropped $(run_out stdout_dropped)"
check "  and run.output records what it dropped" '[ "$(run_out stdout_dropped)" -gt 0 ] && [ "$(( $(run_out stdout_bytes) - $(run_out stdout_dropped) ))" -eq "$flood_tsize" ]'
flood_drop() { w audit --tail 400 | grep "$flood" | grep box.output | grep -oE 'dropped_from_host_at_least[^0-9]*[0-9]+' | grep -oE '[0-9]+$' | tail -1; }
wait_for 30 '[ -n "$(flood_drop)" ]' || true
echo "   box.output: dropped_from_host_at_least $(flood_drop)"
check "  and its audit records the bytes dropped from the host (at least)" '[ "$(flood_drop)" -ge 1000000 ]'
HOME=$HOMEW "$W" run "$(manifest flood-stop)" --image "$IMAGE_TAG" >"$work/flood-stop.log" 2>&1 || true
flood_stop=$(run_id_of "$work/flood-stop.log")
our_runs+=("$flood_stop")
check "with on_output_full: stop, the box is stopped, saying why, and its run ends" 'grep -q "on_output_full: stop" "$work/flood-stop.log" && [ -z "$(box_of "$flood_stop")" ] && w audit --tail 300 | grep -E "run\.end" | grep -q "$flood_stop"'

# ---- 4. multi-host (optional) ----
if [ -n "$nodes" ]; then
  multihost
fi

# ---- 5. a control-host restart (#151) ----
# Every wicket process this test started on the control host is killed hard (the runs' supervisors,
# this host's own node's `serve`), except the mock model (it stands in for the model's upstream) and
# the `serve` of the node acc-n1 (another machine's, in --nodes local). Then one reconcile pass: the
# boxes must still run, the same containers, their runs taken over, and each agent's next turn must
# reach its model and its gateway (MCP's ping and whoami).
# A restart-check run's result: in its run directory here, or on the other node for a box there.
restart_result() {
  data "runs/$1/workspace/out/result.json" 2>/dev/null \
    || cat "${nodehome:-/nonexistent}/.local/share/wicket-node/runs/$1/workspace/out/result.json" 2>/dev/null || true
}
restart_start() {   # $1: label, then wicket run options
  local label=$1; shift
  local ws; ws=$(workdir restart)
  HOME=$HOMEW "$W" run "$(manifest restart)" --workdir "$ws" --image "$IMAGE_TAG" "$@" >"$work/restart-$label.log" 2>&1 &
  pids+=("$!")
  wait_for 90 '[ -n "$(run_id_of "$work/restart-$label.log")" ]' || true
  local r; r=$(run_id_of "$work/restart-$label.log")
  our_runs+=("$r")
  wait_for 120 '[ "$(restart_result '"$r"' | jq -r .turn 2>/dev/null)" = 1 ]' || true
  echo "$r"
}
restart_flow() {
  log "a control-host restart: boxes survive, reconcile adopts their runs"
  local runs=() labels=() boxes=() r l b
  r=$(restart_start local); runs+=("$r"); labels+=(local)
  if [ "$nodes" = local ]; then r=$(restart_start node --node "$NODE"); runs+=("$r"); labels+=("$NODE"); fi
  for r in "${runs[@]}"; do boxes+=("$(box_of "$r")"); done
  echo "   runs: ${runs[*]}; boxes: ${boxes[*]}"
  local killed=0 p
  for p in $(pgrep -f "$W" 2>/dev/null); do
    tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null | grep -qx "WICKET_HOME=$WICKET_HOME" || continue
    case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in *"dev mock-llm"* | *"${nodehome:-/nonexistent}"*) continue ;; esac
    kill -9 "$p" 2>/dev/null && killed=$((killed + 1))
  done
  echo "   killed $killed wicket processes"
  sleep 3
  for i in "${!runs[@]}"; do
    check "  the box on ${labels[$i]} survived the restart" '[ -n "${boxes[$i]}" ] && [ "$(box_of "${runs[$i]}")" = "${boxes[$i]}" ]'
  done
  wroot reconcile >"$work/rec-restart.log" 2>&1 || true
  cat "$work/rec-restart.log"
  for i in "${!runs[@]}"; do
    r=${runs[$i]} l=${labels[$i]}
    check "  reconcile adopted the run on $l" 'grep -q "^run_adopted .*$r" "$work/rec-restart.log"'
    wait_for 60 'grep -q "run.attach\|reconnected" "$WICKET_HOME/runs/'"$r"'/ctl/attach.log" 2>/dev/null' || true
    w say "$r" "Again, after the restart." >/dev/null 2>&1 || true
    wait_for 180 '[ "$(restart_result '"$r"' | jq -r .turn 2>/dev/null)" = 2 ]' || true
    local res; res=$(restart_result "$r")
    echo "   $l: $res"
    check "  its next turn reached the model, on the same box ($l)" '[ "$(jq -r .turn <<<"$res")" = 2 ] && [ "$(box_of "$r")" = "${boxes[$i]}" ]'
    check "  and its gateway: MCP ping and whoami ($l)" '[ "$(jq -r .ping <<<"$res")" = "{}" ] && [ "$(jq -r .whoami_run <<<"$res")" = "$r" ]'
  done
  # Then a node's `serve` alone dies (#151): this host's own is started again by its runs'
  # supervisors; acc-n1's by this script, as its service manager would. Its boxes are adopted, and
  # one `wicket say` is one turn (stdin neither lost nor doubled).
  log "a node's serve restarts alone: its boxes are adopted"
  for p in $(pgrep -f "$W" 2>/dev/null); do
    tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null | grep -qx "WICKET_HOME=$WICKET_HOME" || continue
    case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in *"node serve"*) kill -9 "$p" 2>/dev/null ;; esac
  done
  if [ "$nodes" = local ] && [ -n "${node_serve_pid:-}" ]; then
    kill -9 "$node_serve_pid" 2>/dev/null || true
    sleep 1
    HOME=$nodehome "$nodehome/.local/bin/wicket" node serve >>"$work/node-serve.log" 2>&1 &
    node_serve_pid=$!
    pids+=("$node_serve_pid")
  fi
  sleep 3
  for i in "${!runs[@]}"; do
    r=${runs[$i]} l=${labels[$i]}
    w say "$r" "Once more, after the node restarted." >/dev/null 2>&1 || true
    wait_for 180 '[ "$(restart_result '"$r"' | jq -r .turn 2>/dev/null)" = 3 ]' || true
    sleep 5
    res=$(restart_result "$r")
    echo "   $l: $res"
    check "  after its node's serve restarted, the same box took one more turn, once ($l)" '[ "$(jq -r .turn <<<"$res")" = 3 ] && [ "$(box_of "$r")" = "${boxes[$i]}" ]'
    check "  with its gateway ($l)" '[ "$(jq -r .ping <<<"$res")" = "{}" ] && [ "$(jq -r .whoami_run <<<"$res")" = "$r" ]'
    wroot identity revoke "$r" --reason "acceptance: restart check done" >/dev/null 2>&1 || true
  done
  for r in "${runs[@]}"; do wait_for 60 '[ -z "$(box_of "'"$r"'")" ]' || true; done
  wroot reconcile --dry-run >"$work/rec-restart2.log" 2>&1 || true
  check "  then a dry run has nothing to change" 'grep -q "^reconcile: 0 change(s)" "$work/rec-restart2.log"'
}
if [ "$mode" = dev ]; then restart_flow; else skip "a control-host restart" "dev mode only (installed: wicketd's processes)"; fi

# ---- 3c. an org policy in Cedar (#51) ----
# The installation's org policy forbids one path the zone allows: the box's token, compiled at mint,
# refuses it at the edge. A new version revokes the runs minted under the old one. Development mode
# only (installed, the wicket user would read the policy file from the test's private directory).
if [ "$mode" = dev ]; then
  log "an org policy in Cedar"
  cat >"$work/org.cedar" <<'CEDAR'
permit(principal, action, resource);
forbid(principal, action in [Action::"GET"], resource) when { resource.host == "example.com" && resource.path_matches.contains("/acc-org-no") };
CEDAR
  w policy check "$work/org.cedar" >"$work/policy-check.log" 2>&1 || cat "$work/policy-check.log"
  wroot policy apply "$work/org.cedar" >"$work/policy-apply.log" 2>&1 || cat "$work/policy-apply.log"
  v1=$(sed -n 's/^org policy \([0-9a-f]*\) applied.*/\1/p' "$work/policy-apply.log")
  check "wicket policy apply installs the org policy" '[ -n "$v1" ] && w policy show | grep -q "org policy $v1"'
  HOME=$HOMEW "$W" run "$(manifest org)" --image "$IMAGE_TAG" >"$work/org.log" 2>&1 &
  org_pid=$!
  pids+=("$org_pid")
  wait_for 90 'grep -q acc-org-done "$work/org.log" 2>/dev/null' || true
  org_run=$(run_id_of "$work/org.log")
  our_runs+=("$org_run")
  grep -E "acc-org-(ok|no)=" "$work/org.log" || true
  check "  a path the org policy forbids is refused at the edge, the other one isn't" \
    'grep -q "acc-org-no=403" "$work/org.log" && grep -E -q "acc-org-ok=[0-9]+" "$work/org.log" && ! grep -q "acc-org-ok=403" "$work/org.log"'
  check "  the run is recorded under that version" 'w policy show | grep -q "0 minted under another version"'
  printf '%s\nforbid(principal, action in [Action::"GET"], resource) when { resource.host == "example.com" && resource.path_matches.contains("/acc-org-other") };\n' "$(cat "$work/org.cedar")" >"$work/org2.cedar"
  wroot policy apply "$work/org2.cedar" >"$work/policy-apply2.log" 2>&1 || cat "$work/policy-apply2.log"
  cat "$work/policy-apply2.log"
  check "  a new version revokes the runs minted under the old one" 'grep -q "^revoked $org_run" "$work/policy-apply2.log"'
  wait_for 60 '[ -z "$(box_of "$org_run")" ]' || true
  check "  and their boxes stop" '[ -z "$(box_of "$org_run")" ]'
  wait "$org_pid" 2>/dev/null || true
  rm -f "$WICKET_HOME/policy/org.cedar" "$WICKET_HOME/policy/org-entities.json"
fi

# ---- 6. audit ----
log "audit"
check "wicket audit --verify" 'w audit --verify >"$work/verify.log" 2>&1'
if [ -n "${sink:-}" ]; then
  w audit export --once --checkpoint >"$work/export.log" 2>&1 || cat "$work/export.log"
  [ "$mode" = dev ] || sudo -n cat "$work/sink/audit.jsonl" >"$sink"
  check "audit export wrote records and a signed checkpoint to the JSON-lines sink" '[ -s "$sink" ] && grep -q checkpoint "$sink"'
  check "audit --verify --against the export" 'w audit --verify --against "$sink" >"$work/against.log" 2>&1'
  # A rewritten record in the local chain's copy: the export no longer matches.
  python3 -I - "$sink" "$work/tampered.jsonl" <<'PY'
import json, sys
src, dst = sys.argv[1:]
lines = open(src).read().splitlines()
done = False
with open(dst, "w") as f:
    for line in lines:
        v = json.loads(line)
        if not done and "hash" in v and "checkpoint" not in json.dumps(v.get("type", "")):
            v["hash"] = "0" * len(v["hash"])
            done = True
        f.write(json.dumps(v) + "\n")
PY
  check "  and a tampered export is refused" '! w audit --verify --against "$work/tampered.jsonl" >/dev/null 2>&1'
else
  skip "audit export with --against" "the installation's own sinks; ACC_AUDIT_SINK=1 adds one"
fi

# ---- summary ----
echo
echo "== summary ($mode mode${nodes:+, nodes: $nodes})"
printf '%s\n' "${results[@]}"
n_ok=$(printf '%s\n' "${results[@]}" | grep -c '^ok' || true)
n_fail=$(printf '%s\n' "${results[@]}" | grep -c '^FAIL' || true)
echo "$n_ok ok, $n_fail failed"
if [ "$fail" != 0 ]; then
  echo "== mock model log (tail)"; tail -20 "$work/mock.log"
  for f in lead hib1 hib2 orphan decisions; do [ -f "$work/$f.log" ] && { echo "== $f.log (tail)"; tail -25 "$work/$f.log"; }; done
  exit 1
fi
echo "acceptance passed"

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
#                    the vault secret vultr-api-key, ACC_VULTR_SSH_KEY_ID and ACC_VULTR_SSH_KEY.
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
#   - an orphaned box (its `wicket run` killed hard) is stopped by `wicket reconcile`, and after
#     that a dry run has nothing to change;
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
check "  and the model saw the earlier conversation" 'grep "the user said:" "$work/mock.log" | grep -q "Again, please."'
check "  and the generation went up by one" '[ "$(agent_field generation)" = $((gen1 + 1)) ]'

# ---- 3. reconcile: an orphaned box ----
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
check "the orphan's box outlives its killed wicket run" '[ -n "$orphan" ] && [ -n "$(box_of "$orphan")" ]'
wroot reconcile --dry-run >"$work/rec-dry1.log" 2>&1 || true
check "reconcile --dry-run reports it, and changes nothing" 'grep -q "$orphan" "$work/rec-dry1.log" && [ -n "$(box_of "$orphan")" ]'
wroot reconcile >"$work/rec.log" 2>&1 || cat "$work/rec.log"
cat "$work/rec.log"
check "reconcile stopped the orphaned box" '[ -z "$(box_of "$orphan")" ]'
check "  and ended its run as lost" 'w audit --tail 200 | grep -E "reconcile\.|run\.lost|lost" | grep -q "$orphan"'
wroot reconcile --dry-run >"$work/rec-dry2.log" 2>&1 || true
check "then a dry run has nothing to change" 'grep -q "^reconcile: 0 change(s)" "$work/rec-dry2.log"'
check "no box of ours is left" '[ -z "$(our_boxes)" ]'

# ---- 4. multi-host (optional) ----
if [ -n "$nodes" ]; then
  multihost
fi

# ---- 5. audit ----
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

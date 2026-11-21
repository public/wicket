#!/usr/bin/env bash
# What N idle supervisors cost (#582 step 5; research note 25, §7). Starts N `wicket run` processes,
# each supervising a box that runs until it is killed, on this host's own node, against the stand-in
# Docker (experiments/box-start/fake-engine.py --hold), so the boxes cost nothing and what is
# measured is wicket's own per-run bookkeeping. Once every box runs, it samples for WINDOW seconds:
# each supervisor's CPU (utime + stime), resident memory and threads, the node's CPU, and the writes
# both make (/proc/<pid>/io: write syscalls and bytes that reached storage: the ledger, the feed,
# the run files). Then it SIGKILLs every supervisor and times a reconcile pass adopting them all.
#
#   experiments/supervisor-scale/scale.sh [-n N]... [--window SECS] [--label LABEL]
#
# Needs $WICKET (a release build, `cargo build --release -p wicket-cli`), python3, jq and curl. It
# makes its own WICKET_HOME (a fresh ledger) per N and removes it after. Run it alone on the machine
# (#582: on pc5800, one box, nothing else running): other load shows in every number. One JSON line
# per N goes to logs/scale-<label>-<time>.jsonl, and a table is printed at the end.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
engine="$here/../box-start/fake-engine.py"
ns=() window=60 label=$(hostname)
while [ $# -gt 0 ]; do
  case "$1" in
    -n) ns+=("$2"); shift 2 ;;
    --window) window=$2; shift 2 ;;
    --label) label=$2; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[ ${#ns[@]} -gt 0 ] || ns=(10 100)
WICKET=${WICKET:?set WICKET to a wicket binary (a release build)}
mkdir -p "$here/logs"
out="$here/logs/scale-$label-$(date -u +%Y%m%dT%H%M%SZ).jsonl"
hz=$(getconf CLK_TCK)

# The sum of a /proc field over pids: cpu (ticks), rss (kB), threads, syscw, write_bytes.
sample() {
  local what=$1; shift
  local total=0 v p
  for p in "$@"; do
    case $what in
      cpu) v=$(awk '{ print $14 + $15 }' "/proc/$p/stat" 2>/dev/null || echo 0) ;;
      rss) v=$(awk '/^VmRSS:/ { print $2 }' "/proc/$p/status" 2>/dev/null || echo 0) ;;
      threads) v=$(awk '/^Threads:/ { print $2 }' "/proc/$p/status" 2>/dev/null || echo 0) ;;
      syscw|write_bytes) v=$(awk -v k="$what:" '$1 == k { print $2 }' "/proc/$p/io" 2>/dev/null || echo 0) ;;
    esac
    total=$((total + ${v:-0}))
  done
  echo "$total"
}

for n in "${ns[@]}"; do
  work=$(mktemp -d /tmp/wscale.XXXXXX)
  home="$work/home" sock="$work/docker.sock"
  pids=() engine_pid=
  cleanup() {
    for p in "${pids[@]}"; do kill -9 "$p" 2>/dev/null || true; done
    pkill -9 -f "$home" 2>/dev/null || true
    [ -n "$engine_pid" ] && kill "$engine_pid" 2>/dev/null || true
    rm -rf "$work"
  }
  trap cleanup EXIT
  python3 "$engine" --hold "$sock" >"$work/engine.log" 2>&1 &
  engine_pid=$!
  export WICKET_HOME=$home WICKET_DOCKER="docker -H unix://$sock" RUST_BACKTRACE=0
  unset WICKET_DAEMON_SOCKET
  "$WICKET" identity init --trust-domain scale.test >/dev/null
  cat >"$work/box.yaml" <<YAML
task: Stay up.
program:
  name: scale
  command: [sleep, "86400"]
zone:
  name: scale
  isolation: runc
  limits: { memory: 64m, cpus: 1, timeout: 24h }
YAML
  running() { curl -s --unix-socket "$sock" http://e/_stats | jq -r .running; }
  t0=$(date +%s%N)
  for i in $(seq 1 "$n"); do
    "$WICKET" run "$work/box.yaml" --node local >"$work/run-$i.log" 2>&1 &
    pids+=($!)
    disown $!
  done
  until [ "$(running)" -ge "$n" ]; do
    sleep 0.5
    alive=0; for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null && alive=$((alive + 1)); done
    if [ "$alive" -lt "$n" ]; then
      echo "n=$n: a supervisor exited before its box ran:" >&2
      for p in "${!pids[@]}"; do
        kill -0 "${pids[$p]}" 2>/dev/null || { echo "--- run $((p + 1))" >&2; tail -n 8 "$work/run-$((p + 1)).log" >&2; }
      done
      exit 1
    fi
  done
  started_ms=$(( ($(date +%s%N) - t0) / 1000000 ))
  sleep 5  # let the starts' own work settle
  node_pids=($(pgrep -f "$home/local-node" || true))
  c0=$(sample cpu "${pids[@]}") n0=$(sample cpu "${node_pids[@]}") w0=$(sample syscw "${pids[@]}" "${node_pids[@]}") b0=$(sample write_bytes "${pids[@]}" "${node_pids[@]}")
  sleep "$window"
  c1=$(sample cpu "${pids[@]}") n1=$(sample cpu "${node_pids[@]}") w1=$(sample syscw "${pids[@]}" "${node_pids[@]}") b1=$(sample write_bytes "${pids[@]}" "${node_pids[@]}")
  rss=$(sample rss "${pids[@]}") threads=$(sample threads "${pids[@]}") node_rss=$(sample rss "${node_pids[@]}")
  # Adoption: every supervisor SIGKILLed, then one reconcile pass, until every run has a live
  # supervisor again (an attach process per run) and every box still runs.
  for p in "${pids[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  for p in "${pids[@]}"; do while kill -0 "$p" 2>/dev/null; do sleep 0.05; done; done
  pids=()
  t1=$(date +%s%N)
  "$WICKET" reconcile >"$work/reconcile.log" 2>&1 || true
  # Adopted: an attach process per run, holding for 2 s (one that fails at once doesn't count),
  # with every box still running. Timed to the first moment that holds.
  adopt_ms= held_since=
  for _ in $(seq 1 1500); do
    attached=$(pgrep -fc "$WICKET attach run_" || true)
    if [ "${attached:-0}" -ge "$n" ] && [ "$(running)" -ge "$n" ]; then
      [ -n "$held_since" ] || held_since=$(date +%s%N)
      if [ $(( $(date +%s%N) - held_since )) -ge 2000000000 ]; then adopt_ms=$(( (held_since - t1) / 1000000 )); break; fi
    else
      held_since=
    fi
    sleep 0.1
  done
  [ -n "$adopt_ms" ] || { echo "n=$n: not every run was adopted; reconcile said:" >&2; tail -20 "$work/reconcile.log" >&2; }
  pids=($(pgrep -f "$WICKET attach run_" || true))
  jq -nc --arg label "$label" --argjson n "$n" --argjson window "$window" --argjson hz "$hz" \
    --argjson c "$((c1 - c0))" --argjson nc "$((n1 - n0))" --argjson w "$((w1 - w0))" --argjson b "$((b1 - b0))" \
    --argjson rss "$rss" --argjson threads "$threads" --argjson node_rss "$node_rss" \
    --argjson started_ms "$started_ms" --arg adopt_ms "${adopt_ms:-}" \
    '{label: $label, n: $n, window_s: $window, start_all_ms: $started_ms,
      sup_cpu_ms_per_s_each: ($c / $hz * 1000 / $window / $n), sup_cpu_cores_total: ($c / $hz / $window),
      sup_rss_mib_each: ($rss / 1024 / $n), sup_threads_each: ($threads / $n),
      node_cpu_ms_per_s: ($nc / $hz * 1000 / $window), node_rss_mib: ($node_rss / 1024),
      write_syscalls_per_s: ($w / $window), write_kib_per_s: ($b / 1024 / $window),
      adopt_all_ms: (if $adopt_ms == "" then null else ($adopt_ms | tonumber) end)}' | tee -a "$out"
  cleanup
  trap - EXIT
done
echo
echo "raw: $out"
jq -rs '(["n", "start_all_s", "sup_cpu_ms/s_each", "sup_rss_MiB_each", "threads_each", "node_cpu_ms/s", "writes/s", "write_KiB/s", "adopt_all_s"] | @tsv),
  (.[] | [.n, (.start_all_ms / 1000 * 10 | round / 10), (.sup_cpu_ms_per_s_each * 100 | round / 100), (.sup_rss_mib_each * 10 | round / 10),
          (.sup_threads_each * 10 | round / 10), (.node_cpu_ms_per_s * 10 | round / 10), (.write_syscalls_per_s | round), (.write_kib_per_s | round),
          (if .adopt_all_ms then (.adopt_all_ms / 1000 * 10 | round / 10) else "-" end)] | @tsv)' "$out" | awk -F'\t' '{ for (i = 1; i <= NF; i++) printf "%-18s", $i; print "" }'

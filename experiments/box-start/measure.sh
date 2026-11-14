#!/usr/bin/env bash
# Where a box start's time goes (#287): starts N boxes running a trivial program, on this host's own
# node or on an enrolled one, and prints each span's median (and p90) over them from the timings
# every run keeps in its record (ctl/run.json). Raw spans go to experiments/box-start/logs/.
#
#   experiments/box-start/measure.sh [-n N] [--node NAME] [--image IMAGE] [--isolation gvisor|runc] [--label LABEL]
#
# Needs an installed wicket (or $WICKET), its image built (`wicket image`; on a node, there too),
# jq, and the node's `wicket node serve` running. It sets WICKET_TIMINGS=1, which makes the node time
# runsc's part of `docker run` too, at the cost of one more `docker inspect` per start (in
# node.start.docker.inspect and node.start.total, not in docker.run). The first run is a warm-up
# and is left out of the medians (it may start the local node, page the image in, fill caches).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
n=10 node=local image= isolation=gvisor label=
while [ $# -gt 0 ]; do
  case "$1" in
    -n) n=$2; shift 2 ;;
    --node) node=$2; shift 2 ;;
    --image) image=$2; shift 2 ;;
    --isolation) isolation=$2; shift 2 ;;
    --label) label=$2; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
WICKET=${WICKET:-wicket}
data=${WICKET_HOME:-$HOME/.local/share/wicket}
label=${label:-$node-$isolation}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$here/logs"
out="$here/logs/$label-$(date -u +%Y%m%dT%H%M%SZ).jsonl"

cat >"$work/box.yaml" <<YAML
task: Say hello.
program:
  name: box-start
  command: [sh, -c, "echo box-start-hello"]
zone:
  name: box-start
  isolation: $isolation
  limits: { memory: 256m, cpus: 1, timeout: 2m }
YAML

for i in $(seq 0 "$n"); do
  log="$work/run-$i.log"
  t0=$(date +%s%N)
  WICKET_TIMINGS=1 "$WICKET" run "$work/box.yaml" --node "$node" ${image:+--image "$image"} >"$log" 2>&1 || {
    echo "run $i failed:" >&2; tail -20 "$log" >&2; exit 1; }
  wall_ms=$(( ($(date +%s%N) - t0) / 1000000 ))
  run=$(sed -n 's/^wicket run \(run_[a-z0-9]*\).*/\1/p' "$log" | head -1)
  grep -q 'box-start-hello' "$log" || { echo "run $i ($run) never said hello" >&2; tail -20 "$log" >&2; exit 1; }
  rec="$data/runs/$run/ctl/run.json"
  [ -f "$rec" ] || { echo "run $run has no record at $rec" >&2; exit 1; }
  [ "$i" -eq 0 ] && { echo "warm-up $run: ${wall_ms} ms end to end"; continue; }
  jq -c --arg run "$run" --arg label "$label" --argjson wall "$wall_ms" --arg host "$(hostname)" \
    '{label: $label, host: $host, run: $run, wall_ms: $wall, spans: [.timings[] | {name, at_ms, ms}]}' "$rec" >>"$out"
  echo "run $i/$n $run: ${wall_ms} ms end to end"
done

echo
echo "$label: medians over $n starts (ms; 'at' is when the span began, from the supervisor's start)"
jq -rs '
  def q(p): sort | .[((length * p | ceil) - 1 | if . < 0 then 0 else . end)];
  ([.[].wall_ms] | {name: "wicket run, end to end (wall)", at: 0, med: q(0.5), p90: q(0.9)}) as $wall
  | [.[] | .spans[]] | group_by(.name)
  | map({name: .[0].name, at: ([.[].at_ms] | q(0.5)), med: ([.[].ms] | q(0.5)), p90: ([.[].ms] | q(0.9)), n: length})
  | sort_by(.at) | [$wall] + .
  | (["at", "median", "p90", "span"] | @tsv),
    (.[] | [(.at * 10 | round / 10), (.med * 10 | round / 10), (.p90 * 10 | round / 10), .name] | @tsv)
' "$out" | awk -F'\t' '{ printf "%9s %9s %9s  %s\n", $1, $2, $3, $4 }'
echo
echo "raw: $out"

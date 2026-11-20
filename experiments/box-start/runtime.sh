#!/usr/bin/env bash
# The runtime's part of a box start (#287, step 3): Docker's `Created` to `State.StartedAt`, which is
# what a node records as `docker.run.runtime` (containerd, the shim, and the runtime's create and
# start: for runsc, its sandbox and gofer). It needs only Docker and the runtimes, not wicket, so it
# can run on any node before anything is changed there.
#
#   experiments/box-start/runtime.sh [-n N] [--runtime R]... [--image IMAGE] [--label LABEL]
#
# Starts N detached containers per runtime (plus one warm-up per runtime it leaves out), each
# running `true` with no network, as wicket's boxes are created (`--runtime`, `--network none`),
# waits for it, reads its timestamps with `docker inspect`, removes it, and prints the median and
# p90 per runtime of `runtime` (Created to StartedAt) and `exited` (Created to FinishedAt: until
# `true` has run and exited inside the box, so runsc's boot of the sandboxed process, which
# StartedAt doesn't wait for, is in it). The wall time of `docker run -d` is printed beside it (the CLI's own start
# included, so larger than a node's `docker.run`, which uses the Engine API). Raw numbers go to
# logs/runtime-<label>-<time>.jsonl. Run it alone on the node: other load shows in every number.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
n=20 image=busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662 label=$(hostname) runtimes=()
while [ $# -gt 0 ]; do
  case "$1" in
    -n) n=$2; shift 2 ;;
    --runtime) runtimes+=("$2"); shift 2 ;;
    --image) image=$2; shift 2 ;;
    --label) label=$2; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[ ${#runtimes[@]} -gt 0 ] || runtimes=(runsc runc)
DOCKER=${DOCKER:-docker}
mkdir -p "$here/logs"
out="$here/logs/runtime-$label-$(date -u +%Y%m%dT%H%M%SZ).jsonl"
$DOCKER image inspect "$image" >/dev/null 2>&1 || $DOCKER pull -q "$image" >/dev/null
# RFC 3339 with nanoseconds to Unix nanoseconds.
ns() { date -d "$1" +%s%N; }
for rt in "${runtimes[@]}"; do
  for i in $(seq 0 "$n"); do
    t0=$(date +%s%N)
    id=$($DOCKER run -d --runtime "$rt" --network none "$image" true)
    wall=$(( ($(date +%s%N) - t0) / 1000 ))
    $DOCKER wait "$id" >/dev/null
    read -r created started finished < <($DOCKER inspect -f '{{.Created}} {{.State.StartedAt}} {{.State.FinishedAt}}' "$id")
    $DOCKER rm -f "$id" >/dev/null
    [ "$i" -eq 0 ] && continue
    runtime_us=$(( ($(ns "$started") - $(ns "$created")) / 1000 ))
    exited_us=$(( ($(ns "$finished") - $(ns "$created")) / 1000 ))
    ms() { echo "scale=3; $1/1000" | bc; }
    printf '{"label":"%s","runtime":"%s","runtime_ms":%s,"exited_ms":%s,"run_wall_ms":%s}\n' \
      "$label" "$rt" "$(ms $runtime_us)" "$(ms $exited_us)" "$(ms $wall)" >>"$out"
  done
done
echo "$label: medians over $n starts per runtime (ms)"
jq -rs '
  def q(p): sort | .[((length * p | ceil) - 1 | if . < 0 then 0 else . end)];
  group_by(.runtime) | .[] | [.[0].runtime, ([.[].runtime_ms] | q(0.5)), ([.[].runtime_ms] | q(0.9)), ([.[].exited_ms] | q(0.5)), ([.[].exited_ms] | q(0.9)), ([.[].run_wall_ms] | q(0.5)), ([.[].run_wall_ms] | q(0.9))]
  | @tsv' "$out" | awk -F'\t' 'BEGIN { printf "%-6s %15s %12s %15s %12s %14s %11s\n", "", "runtime median", "runtime p90", "exited median", "exited p90", "run -d median", "run -d p90" }
  { printf "%-6s %15.1f %12.1f %15.1f %12.1f %14.1f %11.1f\n", $1, $2, $3, $4, $5, $6, $7 }'
echo "raw: $out"

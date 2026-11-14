#!/bin/bash
# Where wicket's egress proxy spends its CPU, per workload: perf with call graphs on the real proxy
# (`netbench egress`, wicket_proxy::egress::Egress as `wicket run` starts it), plus CPU-seconds from
# /proc for each workload. Needs the network-overhead harness built (release) and sudo for perf.
#
#   ./profile.sh ../network-overhead/target/release/netbench logs/ [inspect|splice|node]...
#
# For each arm, writes OUT/<arm>-<work>.{cpu.json,top.txt,children.txt}. Shared objects are
# reduced to file names, and nothing machine-specific is kept.
set -euo pipefail
BIN=$(realpath "$1"); OUT=$(realpath "$2"); shift 2
ARMS=("${@:-inspect}")
PORT=${PORT:-18543}; N_KEEP=${N_KEEP:-20000}; N_NEW=${N_NEW:-1000}; N_DL=${N_DL:-5}; FREQ=${FREQ:-999}
mkdir -p "$OUT"; W=$(mktemp -d)
cleanup() { kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; sudo -n rm -rf "$W"; }
trap cleanup EXIT
TCK=$(getconf CLK_TCK)
cpu() { awk -v t="$TCK" '{ print ($14 + $15) / t }' "/proc/$1/stat"; }

"$BIN" origin --listen 127.0.0.1:$PORT --dir "$W" >/dev/null 2>&1 &
until [ -f "$W/origin-ca.der" ]; do sleep 0.1; done

for arm in "${ARMS[@]}"; do
  case $arm in
    inspect) flags=(--inspect) ;;
    splice) flags=() ;;
    node) flags=(--inspect --node) ;;
    *) echo "unknown arm $arm" >&2; exit 2 ;;
  esac
  rm -f "$W/egress.sock" "$W/run-ca.pem"
  "$BIN" egress --listen "unix:$W/egress.sock" --dir "$W" --upstream-port "$PORT" --ledger "$W/ledger-$arm.db" "${flags[@]}" >/dev/null 2>&1 &
  EG=$!
  until [ -S "$W/egress.sock" ] && [ -f "$W/run-ca.pem" ]; do sleep 0.1; done
  probe() { "$BIN" probe --ep "unix:$W/egress.sock" --connect --ca "$W/run-ca.pem" "$@"; }
  probe --work lat_keep --n 500 >/dev/null # warm: leaf minted, pool open
  for work in keep new download; do
    case $work in
      keep) args=(--work lat_keep --n "$N_KEEP"); units=$N_KEEP ;;
      new) args=(--work lat_new --n "$N_NEW"); units=$N_NEW ;;
      download) args=(--work download --size 100000000 --n "$N_DL"); units=$((N_DL * 100)) ;; # MB
    esac
    # Pass 1, unprofiled: CPU-seconds per unit. Pass 2, under perf: where it goes.
    c0=$(cpu "$EG"); t0=$(date +%s.%N)
    probe "${args[@]}" >"$OUT/$arm-$work.client.json"
    c1=$(cpu "$EG"); t1=$(date +%s.%N)
    sudo -n sh -c 'echo $$ >"$1"; exec perf record -q -F "$2" --call-graph dwarf,32768 -o "$3" -p "$4"' \
      sh "$W/perf.pid" "$FREQ" "$W/$arm-$work.data" "$EG" >/dev/null 2>&1 &
    PR=$!; until [ -s "$W/perf.pid" ]; do sleep 0.05; done; sleep 0.5
    probe "${args[@]}" >/dev/null
    sudo -n kill -INT "$(cat "$W/perf.pid")"; rm -f "$W/perf.pid"
    timeout 120 tail --pid="$PR" -f /dev/null || sudo -n kill -KILL "$PR" || true
    python3 -I - "$arm" "$work" "$units" "$c0" "$c1" "$t0" "$t1" >"$OUT/$arm-$work.cpu.json" <<'EOF'
import json, sys
arm, work, units, c0, c1, t0, t1 = sys.argv[1], sys.argv[2], float(sys.argv[3]), *map(float, sys.argv[4:])
unit = "MB" if work == "download" else "request"
print(json.dumps({"arm": arm, "work": work, "cpu_s": round(c1 - c0, 3), "wall_s": round(t1 - t0, 3),
                  "units": units, "unit": unit, "cpu_us_per_unit": round((c1 - c0) / units * 1e6, 1)}))
EOF
    strip() { grep -v '^#' | grep '%' | sed -E 's#/[^ ]*/##g; s/ +$//; s/  +/  /g'; }
    sudo -n perf report -i "$W/$arm-$work.data" --no-children --sort dso,symbol --stdio -g none 2>/dev/null \
      | strip | awk 'NR<=60' >"$OUT/$arm-$work.top.txt"
    sudo -n perf report -i "$W/$arm-$work.data" --children --sort symbol --stdio -g none 2>/dev/null \
      | strip | awk 'NR<=400' >"$OUT/$arm-$work.children.txt"
    sudo -n rm -f "$W/$arm-$work.data"
  done
  kill "$EG"; wait "$EG" 2>/dev/null || true
done

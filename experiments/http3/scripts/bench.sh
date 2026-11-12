#!/bin/bash
# Question 5: cost. Small-request latency (new connection; existing connection) and 100 MB downloads,
# (a) direct: client on the host -> origin over HTTP/3;
# (b) chain: client in a box -> forwarder -> unix socket -> terminator -> origin over HTTP/3,
#     with RT=runsc (gVisor) and RT=runc (to separate gVisor's share).
# CPU: terminator and origin from /proc/PID/stat; the box's whole cgroup (sentry, gofer, client and
# forwarder) from cpu.stat, sampled every 100 ms. Usage: scripts/bench.sh [tag] [extra term flags]
set -u
tag=${1:-default}
shift || true
. "$(dirname "$0")/lib.sh"
start_host "$@"
out=$LOGS/bench-$tag-$RT.jsonl
: > "$out"
SMALL=https://h3.test/small
BIG=https://h3.test/bytes/104857600
CLK=$(getconf CLK_TCK)
note() { echo "{\"event\":\"phase\",\"phase\":\"$1\",\"rt\":\"$RT\",\"tag\":\"$tag\"}" >> "$out"; }
ticks() { awk -v w="$1" -v t="$(cpu_ticks $TERM_PID)" -v o="$(cpu_ticks $ORIGIN_PID)" -v c="$CLK" -v ms="$(date +%s%3N)" 'BEGIN{printf "{\"event\":\"cpu\",\"what\":\"%s\",\"term_s\":%.3f,\"origin_s\":%.3f,\"wall_ms\":%s}\n", w, t/c, o/c, ms}' >> "$out"; }

# Direct baseline (host client, origin CA), once per tag.
if [ "$RT" = runsc ]; then
  D="$BIN get --ca $run/origin-ca.pem --connect h3.test=127.0.0.1:4433 --quiet"
  note direct-new; $D --conns 30 $SMALL >> "$out"
  note direct-reuse; $D --n 300 $SMALL >> "$out"
  note direct-big; ticks before; $D --n ${BIG_N:-3} $BIG >> "$out"; ticks after
fi

# Sample the box's cgroup CPU in the background.
( cid=""
  for _ in $(seq 100); do cid=$(sudo -n docker inspect -f '{{.Id}}' "h3-box-$$" 2>/dev/null) && break; sleep 0.1; done
  f=/sys/fs/cgroup/system.slice/docker-$cid.scope/cpu.stat
  while [ -e "$f" ]; do echo "$(date +%s%3N) $(awk '/^usage_usec/{print $2}' "$f") $(cpu_ticks $TERM_PID) $(cpu_ticks $ORIGIN_PID) $(awk '/^nr_throttled/{print $2}' "$f")"; sleep 0.1; done ) > "$run/cg.txt" 2>/dev/null &
pids+=($!)

ticks box-start
box "
G='/opt/h3spike get --ca /wicket/ca/ca.pem --quiet'
fwdpid=\$(cat /tmp/fwd.pid)
fc() { echo \"{\\\"event\\\":\\\"fwd-cpu\\\",\\\"what\\\":\\\"\$1\\\",\\\"ticks\\\":\$(awk '{print \$14+\$15}' /proc/\$fwdpid/stat),\\\"wall_ms\\\":\$(date +%s%3N)}\"; }
echo '{\"event\":\"phase\",\"phase\":\"chain-new\"}'; \$G --conns 30 $SMALL
echo '{\"event\":\"phase\",\"phase\":\"chain-reuse\"}'; \$G --n 300 $SMALL
echo '{\"event\":\"phase\",\"phase\":\"chain-big\"}'; fc before; \$G --n ${BIG_N:-3} $BIG; fc after
" >> "$out"
ticks box-end
sleep 0.3
python3 - "$run/cg.txt" "$out" <<'EOF'
import json, sys
import os
clk = os.sysconf("SC_CLK_TCK")
rows = [tuple(map(int, l.split())) for l in open(sys.argv[1]) if len(l.split()) == 5]
ev = [json.loads(l) for l in open(sys.argv[2]) if l.startswith("{")]
fc = [e for e in ev if e.get("event") == "fwd-cpu"]
if len(fc) == 2 and rows:
    def at(t):
        return min(rows, key=lambda r: abs(r[0] - t))
    a, b = at(fc[0]["wall_ms"]), at(fc[1]["wall_ms"])
    with open(sys.argv[2], "a") as f:
        f.write(json.dumps({"event": "chain-big-cpu", "box_cgroup_s": (b[1] - a[1]) / 1e6, "term_s": (b[2] - a[2]) / clk,
                            "origin_s": (b[3] - a[3]) / clk, "fwd_s": (fc[1]["ticks"] - fc[0]["ticks"]) / clk,
                            "wall_s": (fc[1]["wall_ms"] - fc[0]["wall_ms"]) / 1e3, "samples": len(rows), "throttled": b[4] - a[4]}) + "\n")
EOF
cp "$run/audit.jsonl" "$LOGS/bench-$tag-$RT-audit.jsonl"
echo "wrote $out"

#!/usr/bin/env bash
# E1/E3/E6-lite: gVisor checkpoint/restore of a wicket-shaped Claude Code box, run with runsc directly
# (Docker's checkpoint needs an experimental daemon and restores only into the same container).
# Same mounts as a wicket box: host UDS sockets (--host-uds=open), --network=none, in-box socat.
#
#   BUNDLE=dir-with-rootfs ROOT=a-woken-root (from e4-resume.sh) SID=session-id WORK=/tmp/x ./e1-checkpoint.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${BUNDLE:?}" "${ROOT:?}" "${SID:?}" "${WORK:?}"
logs=$here/logs; mkdir -p "$logs"
out=$logs/e1.txt; : > "$out"
say() { echo "$*" | tee -a "$out"; }
now() { date +%s.%N; }
since() { echo "$(now) - $1" | bc; }
RUNSC="sudo -n runsc --root $WORK/runsc-root --network=none --host-uds=open"
sudo -n umount "$WORK/runsc-root/null-netns" 2>/dev/null; sudo -n rm -rf "$WORK"; mkdir -p "$WORK/runsc-root"
install -m 0755 "$here/restore-hook.sh" "$BUNDLE/rootfs/usr/local/bin/hib-restore-hook"
printf '127.0.0.1 localhost\n198.18.0.1 wicket.internal\n' > "$ROOT/hosts"
"$here/oci_config.py" "$BUNDLE" "$ROOT" "$(id -u):$(id -g)" -- --resume "$SID"

python3 "$here/mock_llm.py" --listen 127.0.0.1:9972 --log "$logs/e1-mock.jsonl" & mock=$!
sock=""
listen() { [ -z "$sock" ] || kill "$sock" 2>/dev/null || true; rm -f "$ROOT/sock/llm.sock"
  socat UNIX-LISTEN:"$ROOT/sock/llm.sock",fork,mode=777 TCP:127.0.0.1:9972 & sock=$!
  for _ in $(seq 50); do [ -S "$ROOT/sock/llm.sock" ] && break; sleep 0.05; done; }
cleanup() {
  for c in hib-ck hib-ck2; do $RUNSC kill "$c" KILL >/dev/null 2>&1 || true; $RUNSC delete -force "$c" >/dev/null 2>&1 || true; done
  kill $mock "$sock" 2>/dev/null || true
  sudo -n umount "$WORK/runsc-root/null-netns" 2>/dev/null || true
}
trap cleanup EXIT
msg() { python3 -c 'import json,sys; print(json.dumps({"type":"user","message":{"role":"user","content":[{"type":"text","text":sys.argv[1]}]}}))' "$1"; }
results() { grep -ac '"type":"result"' "$1" 2>/dev/null || true; }
# wait_result FILE N TIMEOUT: until FILE holds N result events; prints the seconds it took or "timeout".
wait_result() { local t=$(now) i=0; while [ "$(results "$1")" -lt "$2" ]; do sleep 0.05; i=$((i+1)); [ $i -lt $(($3*20)) ] || { echo timeout; return; }; done; since "$t"; }
clock() { $RUNSC exec "$1" python3 -c 'import time; print("realtime %.2f monotonic %.2f uptime %s" % (time.time(), time.monotonic(), open("/proc/uptime").read().split()[0]))' 2>/dev/null; }
# probe NAME: can a new connection reach the host UDS, through the forwarder (tcp) and directly (uds)?
probe() { $RUNSC exec --user "$(id -u):$(id -g)" "$1" sh -c 'echo "lo=[$(ip -br addr show lo 2>/dev/null | cut -c33-)] $(curl --noproxy "*" -s -m 3 -o /dev/null -w "via-forwarder:%{http_code} " -X POST http://198.18.0.1:8080/v1/messages/count_tokens -d "{}") $(curl -s -m 3 -o /dev/null -w "direct-uds:%{http_code}" --unix-socket /wicket/sock/llm.sock -X POST http://x/v1/messages/count_tokens -d "{}")"' 2>/dev/null; }
# readd NAME: what a restore hook must do; done from the host here.
readd() { local t=$(now); $RUNSC exec --user 0:0 --cap CAP_NET_ADMIN "$1" ip addr add 198.18.0.1/32 dev lo; echo "re-added wicket.internal in $(since "$t") s"; }
statefile() { $RUNSC list 2>/dev/null | awk -v c="$1" '$1==c {print $3; f=1} END {if (!f) print "gone"}'; }

listen
mkfifo "$WORK/in1"; exec 7<>"$WORK/in1"
say "== A: start (runsc run), resume the session, one turn"
t0=$(now)
$RUNSC run --bundle "$BUNDLE" hib-ck < "$WORK/in1" > "$WORK/out1" 2> "$WORK/err1" & runp=$!
msg "HIB-WAKE turn A" >&7
say "start + resume + turn: $(wait_result "$WORK/out1" 1 120) s (from the result wait; box started $(since "$t0") s ago)"
grep -o 'RESUMED[^"]*' "$WORK/out1" | head -1 | sed 's/^/agent said: /' | tee -a "$out"
sleep 2
say "memory (runsc events --stats): $($RUNSC events --stats hib-ck 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]["memory"]["usage"]; print(d.get("usage"), "bytes")' 2>/dev/null || echo n/a)"
say "clock before: $(clock hib-ck)"; hb=$(now)

say "== B: checkpoint, uncompressed (the box stops)"
t0=$(now); $RUNSC checkpoint --image-path "$WORK/img-a" hib-ck 2> "$WORK/ck-a.err"; say "checkpoint: $(since "$t0") s, exit $?"
say "image: $(du -sb "$WORK/img-a" | cut -f1) bytes; files: $(cd "$WORK/img-a" && ls -l | awk 'NR>1{printf "%s=%s ", $9, $5}')"
t0=$(now); zstd -q -3 -T2 -c "$WORK/img-a/pages.img" > "$WORK/pages.zst" 2>/dev/null || true
say "pages.img zstd -3: $(stat -c %s "$WORK/pages.zst" 2>/dev/null) bytes in $(since "$t0") s"
sleep 1; say "runsc run after checkpoint: $(kill -0 $runp 2>/dev/null && echo still-running || { wait $runp; echo "exited $?"; })"
say "stdout tail after checkpoint: $(tail -c 200 "$WORK/out1" | tr '\n' ' ')"

say "== C: sleep 30 s, restart the host listener (new socket inode), restore (background, default)"
sleep 30; listen
mkfifo "$WORK/in2"; exec 8<>"$WORK/in2"
t0=$(now)
$RUNSC restore --image-path "$WORK/img-a" --bundle "$BUNDLE" --detach hib-ck < "$WORK/in2" > "$WORK/out2" 2> "$WORK/err2" || say "restore failed: $(tail -c 300 "$WORK/err2")"
say "restore returned: $(since "$t0") s; state $(statefile hib-ck)"
say "clock after: $(clock hib-ck)  (host seconds since 'clock before': $(since "$hb"))"
say "probe after restore: $(probe hib-ck)"
say "$(readd hib-ck)"; say "probe after re-add: $(probe hib-ck)"
t1=$(now); msg "HIB-WAKE after restore" >&8
say "message on the restore process's stdin -> result: $(wait_result "$WORK/out2" 1 60) s; restore -> result $(since "$t0") s"
say "out2 starts with $(tr -cd '\000' < "$WORK/out2" | wc -c) NUL bytes (the restored stdout fd kept its file offset); out1 still has $(results "$WORK/out1") result"
grep -ao 'RESUMED[^"]*' "$WORK/out2" | tail -1 | sed 's/^/agent said: /' | tee -a "$out"
say "mock requests so far: $(wc -l < "$logs/e1-mock.jsonl")"

say "== D: checkpoint --leave-running, flate-best-speed"
t0=$(now); $RUNSC checkpoint --leave-running --compression=flate-best-speed --image-path "$WORK/img-b" hib-ck 2> "$WORK/ck-b.err" && say "checkpoint (leave-running, flate): $(since "$t0") s, $(du -sb "$WORK/img-b" | cut -f1) bytes, state $(statefile hib-ck)" || say "failed: $(tail -c 300 "$WORK/ck-b.err")"
say "probe after leave-running: $(probe hib-ck)"; probe hib-ck | grep -q 'via-forwarder:200' || say "$(readd hib-ck)"
msg "HIB-WAKE after leave-running" >&8
say "still answers after leave-running: $(wait_result "$WORK/out2" 2 60) s"

say "== E: a request in flight (mock holds it 20 s); checkpoint 3 s in; restore at once (--background=false)"
n_before=$(wc -l < "$logs/e1-mock.jsonl")
msg "HIB-SLOW HIB-WAKE inflight" >&8; sleep 3
t0=$(now); $RUNSC checkpoint --image-path "$WORK/img-c" hib-ck 2> "$WORK/ck-c.err" && say "checkpoint with a request in flight: $(since "$t0") s" || say "checkpoint refused/failed: $(tail -c 300 "$WORK/ck-c.err")"
$RUNSC delete -force hib-ck >/dev/null 2>&1; mkfifo "$WORK/in3"; exec 9<>"$WORK/in3"
t0=$(now)
$RUNSC restore --background=false --image-path "$WORK/img-c" --bundle "$BUNDLE" --detach hib-ck < "$WORK/in3" > "$WORK/out3" 2> "$WORK/err3" || say "restore failed: $(tail -c 300 "$WORK/err3")"
say "restore (--background=false) returned: $(since "$t0") s"; say "$(readd hib-ck)"
r=$(wait_result "$WORK/out3" 1 90)
say "in-flight turn completed after restore: $r s"
say "model requests for the in-flight step: $(tail -n +$((n_before + 1)) "$logs/e1-mock.jsonl" | grep -c '"step": 0') (1 = no retry; the first one's answer hit a closed socket)"
say "out3: $(grep -ao '"subtype":"[a-z_]*"\|API Error[^"]*\|RESUMED[^"]*' "$WORK/out3" | sort | uniq -c | tr '\n' ' ')"

say "== F: double wake: restore img-a a second time as another container while hib-ck runs"
t0=$(now)
mkfifo "$WORK/in4"; exec 6<>"$WORK/in4"
if $RUNSC restore --image-path "$WORK/img-a" --bundle "$BUNDLE" --detach hib-ck2 < "$WORK/in4" > "$WORK/out4" 2> "$WORK/err4"; then
  say "second restore of the same image: ACCEPTED in $(since "$t0") s; states: hib-ck $(statefile hib-ck), hib-ck2 $(statefile hib-ck2)"
  readd hib-ck2 >/dev/null; msg "HIB-WAKE twin" >&6
  say "twin answered: $(wait_result "$WORK/out4" 1 60) s"
  say "both appended to the same transcript (shared bind mount): $(grep -c 'HIB-WAKE twin\|HIB-WAKE inflight' "$ROOT"/state/claude/projects/*/"$SID".jsonl) matching lines"
else
  say "second restore refused: $(tail -c 300 "$WORK/err4")"
fi
say "== G: the same fix as gVisor's restore hook (--save-restore-exec-argv), no host-side re-add"
$RUNSC kill hib-ck2 KILL >/dev/null 2>&1; sleep 0.5; $RUNSC delete -force hib-ck2 >/dev/null 2>&1
t0=$(now); $RUNSC checkpoint --save-restore-exec-argv=/usr/local/bin/hib-restore-hook --image-path "$WORK/img-g" hib-ck 2> "$WORK/ck-g.err" && say "checkpoint with hook: $(since "$t0") s" || say "checkpoint with hook failed: $(tail -c 300 "$WORK/ck-g.err")"
sleep 1; $RUNSC delete -force hib-ck >/dev/null 2>&1; mkfifo "$WORK/in5"; exec 5<>"$WORK/in5"; t0=$(now)
$RUNSC restore --image-path "$WORK/img-g" --bundle "$BUNDLE" --detach hib-ck < "$WORK/in5" > "$WORK/out5" 2> "$WORK/err5" || say "restore failed: $(tail -c 300 "$WORK/err5")"
say "restore returned: $(since "$t0") s; probe: $(probe hib-ck)"
say "hook log: $($RUNSC exec hib-ck cat /tmp/hib-hook.log 2>&1 | tr '\n' ' ')"
msg "HIB-WAKE after hooked restore" >&5; say "turn after hooked restore: $(wait_result "$WORK/out5" 1 60) s"
say "== H1: checkpoint G's box again, without the hook flag, and restore"
$RUNSC checkpoint --image-path "$WORK/img-h" hib-ck 2> "$WORK/ck-h.err"; sleep 1; $RUNSC delete -force hib-ck >/dev/null 2>&1
mkfifo "$WORK/in6"; exec 4<>"$WORK/in6"
$RUNSC restore --image-path "$WORK/img-h" --bundle "$BUNDLE" --detach hib-ck < "$WORK/in6" > "$WORK/out6" 2> "$WORK/err6" || say "restore failed"
say "probe: $(probe hib-ck); hook log: $($RUNSC exec hib-ck cat /tmp/hib-hook.log 2>&1 | tr '\n' ' ')"
say "== H2: restore img-a (no hook) once more, send a message, put the address back only after 40 s"
$RUNSC kill hib-ck KILL >/dev/null 2>&1; sleep 0.5; $RUNSC delete -force hib-ck >/dev/null 2>&1
mkfifo "$WORK/in7"; exec 3<>"$WORK/in7"
$RUNSC restore --image-path "$WORK/img-a" --bundle "$BUNDLE" --detach hib-ck < "$WORK/in7" > "$WORK/out7" 2> "$WORK/err7" || say "restore failed"
msg "HIB-WAKE no address" >&3; sleep 40
say "after 40 s: $(grep -ac '"subtype":"api_retry"' "$WORK/out7") api_retry events, $(results "$WORK/out7") results; delays ms: $(grep -ao '"retry_delay_ms":[0-9]*' "$WORK/out7" | cut -d: -f2 | tr '\n' ' ')"
say "$(readd hib-ck)"; say "turn completed after the late re-add: $(wait_result "$WORK/out7" 1 120) s"
say "image fingerprint: $($RUNSC --version 2>/dev/null | head -1 | sed 's/runsc version //'); cpu features stored: $(sudo -n runsc statefile --get cpu_features "$WORK/img-a/checkpoint.img" 2>/dev/null | tr ',' '\n' | wc -l) flags"
say "done"

#!/usr/bin/env bash
# Idle tier: `docker pause` / `unpause` of a Docker-managed gVisor box (box.sh). Does the session
# answer after unpause, and how long do pause and unpause take?
#   ROOT=a-woken-root SID=session-id WORK=/tmp/x ./e2-pause.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${ROOT:?}" "${SID:?}" "${WORK:?}"
out=$here/logs/e2-pause.txt; : > "$out"
say() { echo "$*" | tee -a "$out"; }
now() { date +%s.%N; }
since() { echo "$(now) - $1" | bc; }
D="sudo -n docker"
sudo -n rm -rf "$WORK"; mkdir -p "$WORK"
python3 "$here/mock_llm.py" --listen 127.0.0.1:9976 --log "$WORK/mock.jsonl" & mock=$!
rm -f "$ROOT/sock/llm.sock"; socat UNIX-LISTEN:"$ROOT/sock/llm.sock",fork,mode=777 TCP:127.0.0.1:9976 2>/dev/null & s=$!
trap 'kill $mock $s 2>/dev/null; $D rm -f hib-pause >/dev/null 2>&1' EXIT
sleep 0.3
msg() { python3 -c 'import json,sys; print(json.dumps({"type":"user","message":{"role":"user","content":[{"type":"text","text":sys.argv[1]}]}}))' "$1"; }
results() { grep -ac '"type":"result"' "$WORK/out" 2>/dev/null || true; }
wait_n() { local t=$(now); for _ in $(seq 1200); do [ "$(results)" -ge "$1" ] && { since "$t"; return; }; sleep 0.05; done; echo timeout; }
mkfifo "$WORK/in"; exec 7<>"$WORK/in"
"$here/box.sh" hib-pause "$ROOT" -- --resume "$SID" < "$WORK/in" > "$WORK/out" 2> "$WORK/err" &
msg "HIB-WAKE before pause" >&7; say "first turn: $(wait_n 1) s"
for hold in 5 60; do
  t0=$(now); $D pause hib-pause >/dev/null; p=$(since "$t0")
  say "pause: $p s; memory while paused: $($D stats --no-stream --format '{{.MemUsage}}' hib-pause)"
  sleep "$hold"
  t0=$(now); $D unpause hib-pause >/dev/null; u=$(since "$t0")
  n=$(( $(results) + 1 ))
  t1=$(now); msg "HIB-WAKE after ${hold}s paused" >&7
  say "paused ${hold} s: unpause $u s; next turn answered in $(wait_n "$n") s"
done
say "api_retry events: $(grep -ac '"subtype":"api_retry"' "$WORK/out")"

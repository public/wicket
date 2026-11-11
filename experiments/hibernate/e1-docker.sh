#!/usr/bin/env bash
# E1 under Docker: can a Docker-managed gVisor box (box.sh) be checkpointed with runsc directly, and
# what does Docker make of it? (`docker checkpoint` itself needs an experimental daemon.)
#   ROOT=a-woken-root SID=session-id WORK=/tmp/x ./e1-docker.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${ROOT:?}" "${SID:?}" "${WORK:?}"
out=$here/logs/e1-docker.txt; : > "$out"
say() { echo "$*" | tee -a "$out"; }
now() { date +%s.%N; }
since() { echo "$(now) - $1" | bc; }
sudo -n rm -rf "$WORK"; mkdir -p "$WORK"
python3 "$here/mock_llm.py" --listen 127.0.0.1:9975 --log "$WORK/mock.jsonl" & mock=$!
rm -f "$ROOT/sock/llm.sock"; socat UNIX-LISTEN:"$ROOT/sock/llm.sock",fork,mode=777 TCP:127.0.0.1:9975 2>/dev/null & s=$!
trap 'kill $mock $s 2>/dev/null; sudo -n docker rm -f hib-dk >/dev/null 2>&1' EXIT
sleep 0.3
mkfifo "$WORK/in"; exec 7<>"$WORK/in"
"$here/box.sh" hib-dk "$ROOT" -- --resume "$SID" < "$WORK/in" > "$WORK/out" 2> "$WORK/err" &
python3 -c 'import json; print(json.dumps({"type":"user","message":{"role":"user","content":[{"type":"text","text":"HIB-WAKE docker"}]}}))' >&7
for _ in $(seq 600); do grep -aq '"type":"result"' "$WORK/out" && break; sleep 0.1; done
say "docker box answered: $(grep -ac '"type":"result"' "$WORK/out") result"
id=$(sudo -n docker inspect -f '{{.Id}}' hib-dk)
# Docker (runc-v2 shim, runtime path runsc) keeps runsc state under runtime-runc/moby.
rroot=""
for r in /run/docker/runtime-runc/moby /run/containerd/runsc/moby /run/docker/runtime-runsc/moby; do
  sudo -n runsc --root "$r" state "$id" >/dev/null 2>&1 && { rroot=$r; break; }
done
[ -n "$rroot" ] || rroot=$(pgrep -a runsc | grep "$id" | grep -o -- '--root[= ][^ ]*' | head -1 | sed 's/--root[= ]//')
say "runsc root used by Docker: ${rroot:-not found}"
[ -n "$rroot" ] || exit 0
t0=$(now)
sudo -n runsc --root "$rroot" checkpoint --image-path "$WORK/img" "$id" > "$WORK/ck.out" 2>&1; rc=$?
say "runsc checkpoint of the Docker container: exit $rc in $(since "$t0") s; $(tail -c 200 "$WORK/ck.out" | tr '\n' ' ')"
sleep 2
say "image bytes: $(sudo -n du -sb "$WORK/img" 2>/dev/null | cut -f1)"
say "docker now says: $(sudo -n docker ps -a --filter name=hib-dk --format '{{.Status}}')"
say "(the box used --rm, so Docker removed it: there is no container left to 'docker start --checkpoint' into)"

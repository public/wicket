#!/bin/bash
# The ci/node-e2e.sh program: once a second, an allowed read, an allowed write, a request out of the
# zone's reach on a host the node terminates, and one on a host it forwards to the control host. Each
# result is "<status>:<x-wicket kind or ->"; lines go to stdout and /workspace/out/status.log.
set -u
end=$(( $(date +%s) + ${1:-120} ))
probe() {
  local h=/tmp/probe.h code
  rm -f "$h"
  code=$(curl -s -m 8 -o /dev/null -D "$h" -w '%{http_code}/%{http_connect}' -X "$1" "$2" 2>/dev/null) || true
  local c=${code%%/*} k=${code##*/}
  [ "$c" = 000 ] && c=$k
  local kind
  kind=$(tr -d '\r' < "$h" 2>/dev/null | awk -F': ' 'tolower($1)=="x-wicket"{k=$2} END{print (k=="" ? "-" : k)}')
  echo "${c:-000}:${kind}"
}
while [ "$(date +%s)" -lt "$end" ]; do
  line="$(date +%s%3N) read=$(probe GET https://example.com/) write=$(probe POST https://example.com/) out=$(probe GET https://example.com/out-of-reach) fwd=$(probe GET https://www.example.org/)"
  echo "$line" | tee -a /workspace/out/status.log
  sleep 1
done
echo '{"status":"done"}' > /workspace/out/result.json

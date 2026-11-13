# The offline check (#152, #153): every 5 s, one model call through the box's model proxy, an
# allowed write to example.com and a request out of the zone's reach, each line timestamped (ms) in
# /workspace/out/offline.log as <status>:<x-wicket kind, or - when wicket let it through>, until
# the box is stopped.
#
# Decisions at the edge (#164): once /workspace/edge.go appears (the test writes it while the box's
# control channel is cut), the agent calls its MCP gateway once: whoami, request_access for a path
# out of reach, a spawn of a narrower program, and pending_requests. Each answer's first line goes
# into /workspace/out/edge.log.
log=/workspace/out/offline.log
edge=/workspace/out/edge.log
gw() {
  curl -s -m 60 http://wicket.internal:8081/ -H 'content-type: application/json' \
    -d "$(jq -nc --arg n "$1" --argjson a "$2" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$n,arguments:$a}}')" \
    | jq -r '.result.content[0].text // .error.message // "no answer"'
}
edge_calls() {
  local who
  who=$(gw whoami '{}')
  echo "whoami=$(jq -r '"\(.run)|\(.decided_on)"' <<<"$who" 2>/dev/null || echo "$who" | head -1)" >>"$edge"
  echo "access=$(gw request_access '{"url":"https://example.com/ahead","reason":"to read ahead while cut off"}' | head -1)" >>"$edge"
  echo "spawn=$(gw spawn '{"name":"edgekid","kind":"program","command":["sleep","400"],"zone":{"limits":{"memory":"128m","cpus":1,"pids":64,"timeout":"3m"}}}' | head -1)" >>"$edge"
  echo "pending=$(gw pending_requests '{}' | grep -c 'q-')" >>"$edge"
}
code() {
  local c
  c=$(curl -s -m 20 -o /dev/null -D /tmp/h -w '%{http_code}' "$@" 2>/dev/null) || c=000
  echo "$c:$(tr -d '\r' </tmp/h 2>/dev/null | awk -F': ' 'tolower($1)=="x-wicket"{k=$2} END{print (k=="" ? "-" : k)}')"
}
while :; do
  if [ -e /workspace/edge.go ] && [ ! -e "$edge" ]; then edge_calls; fi
  m=$(code http://wicket.internal:8080/v1/messages -H 'content-type: application/json' \
    -d '{"model":"claude-mock","max_tokens":16,"messages":[{"role":"user","content":"ping"}]}')
  e=$(code -X POST https://example.com/)
  o=$(code https://example.com/out-of-reach)
  echo "$(date +%s%3N) model=$m write=$e out=$o" >>"$log"
  sleep 5
done

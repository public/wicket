# The offline check (#152, #153): every 5 s, one model call through the box's model proxy, an
# allowed write to example.com and a request out of the zone's reach, each line timestamped (ms) in
# /workspace/out/offline.log as <status>:<x-wicket kind, or - when wicket let it through>, until
# the box is stopped.
log=/workspace/out/offline.log
code() {
  local c
  c=$(curl -s -m 20 -o /dev/null -D /tmp/h -w '%{http_code}' "$@" 2>/dev/null) || c=000
  echo "$c:$(tr -d '\r' </tmp/h 2>/dev/null | awk -F': ' 'tolower($1)=="x-wicket"{k=$2} END{print (k=="" ? "-" : k)}')"
}
while :; do
  m=$(code http://wicket.internal:8080/v1/messages -H 'content-type: application/json' \
    -d '{"model":"claude-mock","max_tokens":16,"messages":[{"role":"user","content":"ping"}]}')
  e=$(code -X POST https://example.com/)
  o=$(code https://example.com/out-of-reach)
  echo "$(date +%s%3N) model=$m write=$e out=$o" >>"$log"
  sleep 5
done

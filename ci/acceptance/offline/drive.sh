# The offline check (#152, #153): every 5 s, one model call through the box's model proxy, an
# allowed write to example.com and a request out of the zone's reach, each line timestamped (ms) in
# /workspace/out/offline.log, until the box is stopped.
log=/workspace/out/offline.log
code() { curl -s -m 20 -o /dev/null -D /tmp/h -w '%{http_code}' "$@" 2>/dev/null || echo 000; }
kind() { tr -d '\r' </tmp/h 2>/dev/null | awk -F': ' 'tolower($1)=="x-wicket"{k=$2} END{print (k=="" ? "-" : k)}'; }
while :; do
  m=$(code http://wicket.internal:8080/v1/messages -H 'content-type: application/json' \
    -d '{"model":"claude-mock","max_tokens":16,"messages":[{"role":"user","content":"ping"}]}')
  e=$(code -X POST https://example.com/)
  o=$(code https://example.com/out-of-reach)
  echo "$(date +%s%3N) model=$m write=$e out=$o:$(kind)" >>"$log"
  sleep 5
done

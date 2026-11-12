#!/bin/bash
# Runs inside the lead agent's box. It calls wicket's MCP gateway (wicket.internal:8081) the way an
# agent's own code would: start a service box, connect to it, use it, cut the link. Every step is
# recorded in /workspace/out/result.json; examples/links/demo.sh checks it from outside.
set -u
gw() {
  curl -s -m 110 http://wicket.internal:8081/ -H 'content-type: application/json' \
    -d "$(jq -nc --arg n "$1" --argjson a "$2" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$n,arguments:$a}}')" \
    | jq -r '.result.content[0].text'
}
# A service: a plain HTTP server in its own box (no network, no reach), listening on its localhost.
spawned=$(gw spawn '{"name":"web","kind":"program","zone":{},"command":["sh","-c","echo hello-from-web > /tmp/index.html && cd /tmp && exec python3 -m http.server 8000 --bind 127.0.0.1"]}')
# A box that isn't ours and exposed nothing: refused.
stranger=$(gw connect '{"box":"run_00000000000000000000000000","port":8000}')
# Our own child is connectable without it exposing anything.
connected=$(gw connect '{"box":"web","port":8000}')
addr=$(grep -o '[a-z0-9-]*\.wicket\.internal:[0-9]*' <<<"$connected" | head -1)
link=$(grep -o 'l-[a-z0-9]*' <<<"$connected" | head -1)
resolved=$(getent hosts "${addr%%:*}" | awk '{print $1}')
body=""
for _ in $(seq 60); do
  body=$(curl -s -m 5 --noproxy '*' "http://$addr/" || true)
  [ -n "$body" ] && break
  sleep 1
done
# A second connection over the same link.
again=$(curl -s -m 5 --noproxy '*' "http://$addr/" || true)
# Per-connection cost: 10 fetches on new connections, in ms each.
t0=$(date +%s%N)
for _ in $(seq 10); do curl -s -m 5 --noproxy '*' -o /dev/null "http://$addr/"; done
per_conn_ms=$(( ($(date +%s%N) - t0) / 10000000 ))
listed=$(gw links '{}')
unlinked=$(gw unlink "$(jq -nc --arg l "$link" '{link:$l}')")
sleep 5
after=$(curl -s -m 5 --noproxy '*' -o /dev/null -w '%{http_code}' "http://$addr/" 2>/dev/null || true)
after_resolved=$(getent hosts "${addr%%:*}" | awk '{print $1}')
jq -n --arg spawned "$spawned" --arg stranger "$stranger" --arg connected "$connected" --arg addr "$addr" \
  --arg resolved "$resolved" --arg body "$body" --arg again "$again" --arg listed "$listed" --arg unlinked "$unlinked" \
  --arg after "$after" --arg after_resolved "$after_resolved" --arg link "$link" --arg per_conn_ms "$per_conn_ms" \
  '{spawned:$spawned,stranger:$stranger,connected:$connected,link:$link,addr:$addr,resolved:$resolved,body:$body,again:$again,listed:$listed,unlinked:$unlinked,after:$after,after_resolved:$after_resolved,per_conn_ms:$per_conn_ms}' \
  > /workspace/out/result.json

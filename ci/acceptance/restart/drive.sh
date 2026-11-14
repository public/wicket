# The restart check: each turn counts itself and calls the gateway twice, MCP's own `ping` (which the
# node answers even without its control host) and `whoami` (decided by the control host, from the
# ledger).
n=$(( $(cat /workspace/turns 2>/dev/null || echo 0) + 1 )); echo $n > /workspace/turns
rpc() { curl -s -m 30 http://wicket.internal:8081/ -H 'content-type: application/json' -d "$1"; }
ping=$(rpc '{"jsonrpc":"2.0","id":1,"method":"ping"}' | jq -c '.result // .error')
who=$(rpc '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' | jq -r '.result.content[0].text' | jq -r '.run // empty' 2>/dev/null)
jq -n --arg n "$n" --arg ping "$ping" --arg who "$who" '{turn:$n,ping:$ping,whoami_run:$who}' > /workspace/out/result.json
# Stays up between turns, for the next one.
echo "wicket-mock: stay"

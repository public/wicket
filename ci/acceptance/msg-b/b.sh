#!/bin/bash
# Runs in msg-b's box, on acc-n1 (ci/acceptance/nodes.sh, messages_flow, #252): waits for msg-a's
# message, answers it (a reply needs no accept_from), then writes to msg-a unasked, which msg-a's
# accept_from doesn't allow: refused, with a receipt that says so.
set -u
out=/workspace/out
r='{}'
put() { r=$(jq -c --arg k "$1" --arg v "$2" '.[$k] = $v' <<<"$r"); printf '%s\n' "$r" >"$out/result.json.new" && mv "$out/result.json.new" "$out/result.json"; }
gw() {
  curl -s -m 320 http://wicket.internal:8081/ -H 'content-type: application/json' \
    -d "$(jq -nc --arg n "$1" --argjson a "$2" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$n,arguments:$a}}')" \
    | jq -r '.result.content[0].text'
}
put started 1
got=$(gw await_message '{"timeout_seconds":300}')
put got "$got"
a=$(jq -r .reply_to <<<"$got" 2>/dev/null)
mid=$(jq -r .message_id <<<"$got" 2>/dev/null)
put replied "$(gw send_message "$(jq -nc --arg a "$a" --arg m "$mid" '{to:$a, body:"pong from msg-b", in_reply_to:$m}')")"
put unasked "$(gw send_message "$(jq -nc --arg a "$a" '{to:$a, body:"unasked"}')")"
put done 1
# Stay up a little, so the script outside reads this box's results before its node removes them.
sleep 60

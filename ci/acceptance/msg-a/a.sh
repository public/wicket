#!/bin/bash
# Runs in msg-a's box, on the control host's own node (ci/acceptance/nodes.sh, messages_flow, #252):
# finds msg-b (on the other node) through the gateway, messages it and follows the receipt, reads
# its reply, then reads a message from its operator (`wicket message send`, outside) and answers
# it. Each step's answer goes to out/result.json for the script outside to check.
set -u
out=/workspace/out
r='{}'
put() { r=$(jq -c --arg k "$1" --arg v "$2" '.[$k] = $v' <<<"$r"); printf '%s\n' "$r" >"$out/result.json.new" && mv "$out/result.json.new" "$out/result.json"; }
gw() {
  curl -s -m 320 http://wicket.internal:8081/ -H 'content-type: application/json' \
    -d "$(jq -nc --arg n "$1" --argjson a "$2" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$n,arguments:$a}}')" \
    | jq -r '.result.content[0].text'
}
# Discovery: msg-b accepts this zone, so it is listed once it has run.
b=
for _ in $(seq 120); do
  p=$(gw principals '{}')
  b=$(jq -r '.principals[] | select(.agent == "msg-b") | .id' <<<"$p" 2>/dev/null | head -1)
  [ -n "$b" ] && [ "$(jq -r --arg b "$b" '.principals[] | select(.id == $b) | .state' <<<"$p")" != offline ] && break
  sleep 2
done
put you "$(jq -r .you <<<"$p")"
put b "$b"
put b_entry "$(jq -c --arg b "$b" '.principals[] | select(.id == $b)' <<<"$p")"
put operator "$(jq -r '.principals[] | select(.relation == "your operator") | .id' <<<"$p" | head -1)"
# A message to a box on the other node, and its receipt until it is read.
sent=$(gw send_message "$(jq -nc --arg b "$b" '{to:$b, body:{hello:"from msg-a"}}')")
put sent "$sent"
mid=$(grep -o 'm-[a-z0-9]*' <<<"$sent" | head -1)
put mid "$mid"
put receipt "$(gw receipts "$(jq -nc --arg m "$mid" '{message_id:$m, timeout_seconds:240}')")"
# msg-b's reply.
put reply "$(gw await_message '{"timeout_seconds":240}')"
# The operator's message, and the answer to it.
: >"$out/await-operator"
op=$(gw await_message '{"timeout_seconds":300}')
put op_msg "$op"
opmid=$(jq -r .message_id <<<"$op" 2>/dev/null)
put op_reply "$(gw send_message "$(jq -nc --arg o "$(jq -r .operator <<<"$r")" --arg m "$opmid" '{to:$o, body:"seen, thanks", in_reply_to:$m}')")"
put done 1

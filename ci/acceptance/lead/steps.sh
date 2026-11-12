#!/bin/bash
# Runs inside the lead agent's box (started by drive.sh), calling wicket's proxy and MCP gateway the
# way an agent's own code would. Each step's outcome goes into /workspace/out/result.json (rewritten
# after every step, so a failure shows how far it got) and a line into steps.log; ci/acceptance.sh
# reads both from outside, answers the requests that wait for a human, and checks the outcomes.
set -u
out=/workspace/out
r='{}'
put() { r=$(jq -c --arg k "$1" --arg v "$2" '.[$k] = $v' <<<"$r"); printf '%s\n' "$r" >"$out/result.json.new" && mv "$out/result.json.new" "$out/result.json"; }
say() { echo "$(date +%s) $*" >>"$out/steps.log"; }
gw() {
  curl -s -m 200 http://wicket.internal:8081/ -H 'content-type: application/json' \
    -d "$(jq -nc --arg n "$1" --argjson a "$2" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$n,arguments:$a}}')" \
    | jq -r '.result.content[0].text'
}
code() { curl -s -m 20 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true; }
rid_of() { grep -o 'r-[a-z0-9]*' <<<"$1" | head -1; }

# Egress, HTTP/1.1 and HTTP/3: in reach, out of it, and a forbidden host.
put kernel "$(cat /proc/version)"
put allowed "$(code https://example.com/)"
put direct "$(curl -s -m 5 --noproxy '*' -o /dev/null -w '%{http_code}' https://example.com/ 2>/dev/null || true)"
put h3_allowed "$(/workspace/h3get https://example.com/ 2>/dev/null || true)"
put h3_outside "$(/workspace/h3get https://www.iana.org/ 2>/dev/null || true)"
put h3_forbidden "$(/workspace/h3get https://forbidden.example.com/ 2>/dev/null || true)"
say "egress done"

# Approve one request and deny another: each is a 403 with a request id, then await_grant.
for which in approve deny; do
  body=$(curl -s -m 20 "https://example.com/acc-$which" 2>/dev/null || true)
  rid=$(jq -r '.request_id // empty' <<<"$body" 2>/dev/null)
  put "${which}_rid" "$rid"
  say "waiting $which $rid"
  put "${which}_wait" "$(gw await_grant "$(jq -nc --arg id "$rid" '{request_id:$id,timeout_seconds:150}')")"
  put "${which}_retry" "$(code "https://example.com/acc-$which")"
done
say "approvals done"

# A narrower zone starts at once: an HTTP server, within the lead's own reach.
lim='{"memory":"256m","cpus":1,"timeout":"6m"}'
put narrow "$(gw spawn "$(jq -nc --argjson l "$lim" '{name:"narrow",kind:"program",
  zone:{reach:[{host:"example.com",methods:["GET"],paths:["/"]}],limits:$l},
  command:["sh","-c","echo acc-hello-from-narrow > /tmp/index.html && cd /tmp && exec python3 -m http.server 8000 --bind 127.0.0.1"]}')")"
say "narrow spawned"

# A wider zone (a host the lead can't reach) waits for a human, then starts. It fetches the narrow
# box's page once a link gives it one, and stays up.
fetch='for i in $(seq 180); do b=$(curl -s -m 5 --noproxy "*" http://narrow.wicket.internal:8000/ 2>/dev/null); if [ -n "$b" ]; then echo "acc-fetched:$b"; break; fi; sleep 1; done; exec sleep 3000'
wide=$(jq -nc --argjson l "$lim" --arg c "$fetch" '{name:"wide",kind:"program",ask_human:true,
  zone:{reach:[{host:"example.com",methods:["GET"],paths:["/"]},{host:"www.iana.org",methods:["GET"],paths:["/"]}],limits:$l},
  command:["sh","-c",$c]}')
first=$(gw spawn "$wide")
put wide_first "$first"
rid=$(rid_of "$first")
put wide_rid "$rid"
say "waiting spawn $rid"
put wide_wait "$(gw await_grant "$(jq -nc --arg id "$rid" '{request_id:$id,timeout_seconds:150}')")"
put wide "$(gw spawn "$wide")"
say "wide spawned"

# link: the wide box gets narrow.wicket.internal:8000 (narrow's reach is within wide's).
# spawn returns before the box is up: retry while it isn't there yet.
for _ in $(seq 30); do
  link=$(gw link '{"from":"wide","to":"narrow","port":8000}')
  case "$link" in linked*) break ;; esac
  sleep 2
done
put link "$link"
say "linked"

# A child agent that starts a box of its own, so the subtree is two levels deep. Its workspace has
# no drive.sh, so the mock model's command (ci/acceptance.sh) spawns the leaf and waits instead.
put mid "$(gw spawn "$(jq -nc --argjson l "$lim" '{name:"mid",kind:"agent",task:"Run the command you are given.",max_children:1,zone:{limits:$l}}')")"
say "mid spawned"
put whoami "$(gw whoami '{}')"
put done 1
say "done"

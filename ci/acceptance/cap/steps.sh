#!/bin/bash
# Runs inside the cap agent's box: ask for a node, wait for it, start a box there, try to link to it.
set -u
out=/workspace/out
r='{}'
put() { r=$(jq -c --arg k "$1" --arg v "$2" '.[$k] = $v' <<<"$r"); printf '%s\n' "$r" >"$out/result.json.new" && mv "$out/result.json.new" "$out/result.json"; }
gw() {
  curl -s -m 960 http://wicket.internal:8081/ -H 'content-type: application/json' \
    -d "$(jq -nc --arg n "$1" --argjson a "$2" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$n,arguments:$a}}')" \
    | jq -r '.result.content[0].text'
}
asked=$(gw request_capacity '{"vcpus":1,"memory_mib":1024,"isolation":"gvisor","duration_minutes":30,"max_hourly_usd":"0.05","reason":"acceptance test: a box on a node"}')
put asked "$asked"
lease=$(grep -o 'l-[a-z0-9]*' <<<"$asked" | head -1)
put lease "$lease"
put ready "$(gw request_capacity "$(jq -nc --arg l "$lease" '{lease:$l,timeout_seconds:900}')")"
# The script outside loads the image onto the node (on Vultr), then says go.
for _ in $(seq 600); do [ -f "$out/go" ] && break; sleep 1; done
probe='i=$(curl -s -m 20 -o /dev/null -w "%{http_code}" https://example.com/); o=$(curl -s -m 20 -o /dev/null -w "%{http_code}" https://example.com/acc-out-of-reach); echo "acc-remote in=$i out=$o"; echo acc-remote-done'
put remote "$(gw spawn "$(jq -nc --arg l "$lease" --arg c "$probe" '{name:"remote",kind:"program",placement:{lease:$l},
  zone:{reach:[{host:"example.com",methods:["GET"],paths:["/"]}],limits:{memory:"256m",cpus:1,timeout:"5m"}},command:["sh","-c",$c]}')")"
sleep 5
put connect "$(gw connect '{"box":"remote","port":8000}')"
put done 1

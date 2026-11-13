# Images pinned by digest (#192): spawn a program from the pinned image by its tag; once
# /workspace/retagged appears (the test moved the tag to another image), ask again by the tag, and
# for the other image by its digest (/workspace/pin-other). Each answer's first line goes to
# /workspace/out/pin.log.
out=/workspace/out/pin.log
name=$(cat /workspace/pin-name)
gw() {
  curl -s -m 120 http://wicket.internal:8081/ -H 'content-type: application/json' \
    -d "$(jq -nc --arg n "$1" --argjson a "$2" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$n,arguments:$a}}')" \
    | jq -r '.result.content[0].text // .error.message // "no answer"' | head -1
}
spawn() {
  gw spawn "$(jq -nc --arg n "$1" --arg i "${2:-$name:a}" '{name:$n,kind:"program",image:$i,command:["sleep","300"],zone:{limits:{memory:"128m",cpus:1,timeout:"5m"}}}')"
}
echo "first=$(spawn first)" >>"$out"
for _ in $(seq 120); do [ -e /workspace/retagged ] && break; sleep 1; done
echo "second=$(spawn second)" >>"$out"
echo "third=$(spawn third "$name@$(cat /workspace/pin-other)")" >>"$out"
sleep 600

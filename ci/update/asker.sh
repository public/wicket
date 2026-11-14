# shellcheck shell=bash
# ci/update.sh: an agent that built a wicket asks for it to be installed (request_update), which only
# files a request for a human. Its sha256 is in /workspace/sha256.
rpc() { curl -s -m 30 http://wicket.internal:8081/ -H 'content-type: application/json' -d "$1"; }
sha=$(cat /workspace/sha256)
args=$(jq -nc --arg sha "$sha" '{name:"request_update",arguments:{sha256:$sha,reason:"ci/update.sh: build C, made in this box"}}')
rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":$args}" | jq -c '.result' > /workspace/out/result.json
echo "wicket-mock: stay"

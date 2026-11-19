#!/bin/bash
# The peer (peer.yaml): a canary on port 8000, exposed; a request and a standing ask of its own left
# pending; and it uses the second service (atk-svc2), so that service's instance runs on the node.
set -u
mkdir -p /workspace/out
python3 -I -m http.server 8000 --bind 127.0.0.1 --directory /workspace/www >/dev/null 2>&1 &
call() { curl -s -m 20 http://wicket.internal:8081/mcp -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$1"; }
call '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"expose","arguments":{"port":8000,"name":"atk-peer"}}}' >/workspace/out/expose.json
call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"request_access","arguments":{"url":"https://example.org/peer","reason":"the peer'"'"'s own request"}}}' >/workspace/out/request.json
call '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_access","arguments":{"url":"https://example.org/peer/","scope":"standing","reason":"the peer'"'"'s own standing ask"}}}' >/workspace/out/standing.json
call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' >/workspace/out/whoami.json
touch /workspace/out/ready
# Until the matrix stops it.
sleep 590

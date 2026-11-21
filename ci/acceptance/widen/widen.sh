#!/bin/bash
# Fetches https://www.example.org/ through the egress proxy, which inspects it: the node's CA must
# cover the host to serve it. Widening the CA takes a moment after the box starts (the connected
# run's next check), so it tries for up to 30 s; the last answer goes to out/widen.log.
mkdir -p /workspace/out
code=000
for _ in $(seq 30); do
  code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' https://www.example.org/ 2>/dev/null) || code=${code:-000}
  [ "$code" = 200 ] && break
  sleep 1
done
echo "www.example.org $code" >/workspace/out/widen.log

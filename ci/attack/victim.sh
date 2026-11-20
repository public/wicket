#!/bin/bash
# The victim (victim.yaml): fetches its service's page through its link, as its users would, and
# keeps what it got for the host to check.
set -u
mkdir -p /workspace/out
for _ in $(seq 60); do
  if curl -s -m 5 --noproxy '*' -o /workspace/out/svc2.body "http://atk-svc2.wicket.internal:4874/" 2>/dev/null && [ -s /workspace/out/svc2.body ]; then
    grep -c atk-svc2 /etc/hosts >/workspace/out/hosts.count
    exit 0
  fi
  sleep 2
done
echo "never reached atk-svc2.wicket.internal:4874" >/workspace/out/svc2.error

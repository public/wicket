#!/usr/bin/env bash
# Session 1: a real `wicket run` (gVisor box, wicket's proxies) driven by mock_llm.py, with the
# workspace mounted in place and one volume. Leaves the run's state/ under $WICKET_HOME/runs/.
#   WICKET=path/to/wicket WS=/path/to/workspace-clone ./session1.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${WICKET:?path to the wicket binary}" "${WS:?workspace directory}"
export WICKET_HOME=${WICKET_HOME:-$(mktemp -d)} WICKET_DOCKER=${WICKET_DOCKER:-"sudo -n docker"}
logs=$here/logs; mkdir -p "$logs"
"$WICKET" identity init --trust-domain hib.wicket.test >/dev/null
printf 'mock-model-credential' | "$WICKET" secret set mock >/dev/null
python3 "$here/mock_llm.py" --listen 127.0.0.1:9971 --log "$logs/session1-mock.jsonl" &
mock=$!; trap 'kill $mock 2>/dev/null || true' EXIT
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/9971) 2>/dev/null && break; sleep 0.1; done
t0=$(date +%s.%N)
"$WICKET" run --workspace-dir "$WS" "$here/session1.yaml" > "$logs/session1-run.log" 2>&1 || echo "wicket run exited $?"
t1=$(date +%s.%N)
echo "session1 wall: $(echo "$t1 - $t0" | bc) s"
echo "WICKET_HOME=$WICKET_HOME"
# Keep ids, the local user name and temp paths out of the committed log.
sed -i -E "s#$WICKET_HOME#\$WICKET_HOME#g; s/run_[0-9a-z]{26}/run_<id>/g; s/acting for [^ ]+ \(/acting for <user> (/" "$logs/session1-run.log"

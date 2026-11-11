#!/usr/bin/env bash
# End-to-end smoke test: one Claude Code agent in a gVisor box, driven by `wicket dev mock-llm`.
# Needs Docker with the runsc runtime, and the agent image (`wicket image`). No model credential.
#
#   WICKET=target/debug/wicket ci/smoke.sh
#
# Checks, from inside the box (the probe the mock model asks the agent to run):
#   - the kernel is gVisor's;
#   - a request in the zone's reach (GET https://example.com/) gets 200 through wicket's proxy;
#   - a request outside it gets wicket's 403;
#   - a direct connection that bypasses the proxy fails (the box has no network);
#   - the box holds no model credential, only a placeholder.
# And outside it: the mock model always saw the injected credential, never the placeholder, and the
# audit chain verifies.
set -euo pipefail

WICKET=${WICKET:-target/debug/wicket}
WICKET=$(realpath "$WICKET")
cd "$(dirname "$0")/.."

export WICKET_HOME=${WICKET_HOME:-$(mktemp -d)}
work=$(mktemp -d)
trap 'kill "${mock_pid:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

# One line of Bash, run by the agent inside the box. Every probe tolerates failure; the checks below
# decide.
probe='v=$(cat /proc/version); d=$(dmesg 2>/dev/null | head -3 | tr "\n" " "); '\
'a=$(curl -s -m 20 -o /dev/null -w "%{http_code}" https://example.com/ || true); '\
'o=$(curl -s -m 20 -o /dev/null -w "%{http_code}" https://www.iana.org/ || true); '\
'n=$(curl -s -m 5 --noproxy "*" -o /dev/null -w "%{http_code}" https://example.com/ 2>/dev/null || true); '\
'c=$(env | grep -iE "^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_CODE_OAUTH_TOKEN)=" | grep -vic placeholder || true); '\
'jq -n --arg v "$v" --arg d "$d" --arg a "$a" --arg o "$o" --arg n "$n" --arg c "$c" '\
'"{version:\$v,dmesg:\$d,allowed:\$a,outside:\$o,direct:\$n,real_credentials:\$c}" > /workspace/out/result.json'

"$WICKET" identity init --trust-domain ci.wicket.test >/dev/null
printf 'mock-model-credential' | "$WICKET" secret set mock >/dev/null

"$WICKET" dev mock-llm --listen 127.0.0.1:9999 --command "$probe" 2>"$work/mock.log" &
mock_pid=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/9999) 2>/dev/null && break; sleep 0.2; done

echo "== wicket run ci/smoke.yaml"
run_status=0
"$WICKET" run ci/smoke.yaml 2>&1 | tee "$work/run.log" || run_status=$?

fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

result=$(sed -n 's/^\[wicket\] result.json: //p' "$work/run.log" | tail -1)
echo "== result: ${result:-<none>}"
field() { jq -r ".$1 // empty" <<<"$result" 2>/dev/null; }

check "wicket run exited 0" '[ "$run_status" = 0 ]'
check "the agent wrote result.json" '[ -n "$result" ]'
check "the box runs on gVisor" 'field version | grep -qi gvisor || field dmesg | grep -qi gvisor'
check "a request in reach gets 200" '[ "$(field allowed)" = 200 ]'
check "a request outside reach gets 403" '[ "$(field outside)" = 403 ]'
check "a direct connection fails" '[ "$(field direct)" != 200 ] && [ -n "$(field direct)" ]'
check "no real model credential in the box" '[ "$(field real_credentials)" = 0 ]'
check "the model saw the injected credential" 'grep -q "key=injected" "$work/mock.log"'
check "the model never saw the placeholder" '! grep -q "PLACEHOLDER" "$work/mock.log"'
check "the audit chain verifies" '"$WICKET" audit --verify >/dev/null'

if [ "$fail" != 0 ]; then
  echo "== mock model log"; cat "$work/mock.log"
  exit 1
fi
echo "smoke test passed"

#!/usr/bin/env bash
# End-to-end smoke test: one Claude Code agent in a gVisor box, driven by `wicket dev mock-llm`.
# Needs Docker with the runsc runtime, and the agent image (`wicket image`). No model credential.
#
#   WICKET=target/debug/wicket ci/smoke.sh      (IMAGE=tag to test an image other than the default)
#
# Building ci/h3get needs Rust's x86_64-unknown-linux-musl target and musl-tools (H3GET=path to use a
# prebuilt static binary instead).
#
# Checks, from inside the box (the probe the mock model asks the agent to run):
#   - the kernel is gVisor's;
#   - a request in the zone's reach (GET https://example.com/) gets 200 through wicket's proxy;
#   - a request outside it gets wicket's 403;
#   - a direct connection that bypasses the proxy fails (the box has no network);
#   - over HTTP/3 (#92; ci/h3get, built here and copied into the box's workspace): the same request
#     in reach gets 200, the one outside it wicket's 403, and a forbidden host doesn't resolve;
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
'h=$(/workspace/h3get https://example.com/ 2>/dev/null || true); '\
'ho=$(/workspace/h3get https://www.iana.org/ 2>/dev/null || true); '\
'hf=$(/workspace/h3get https://forbidden.example.com/ 2>/dev/null || true); '\
'c=$(env | grep -iE "^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_CODE_OAUTH_TOKEN)=" | grep -vic placeholder || true); '\
'jq -n --arg v "$v" --arg d "$d" --arg a "$a" --arg o "$o" --arg n "$n" --arg c "$c" --arg h "$h" --arg ho "$ho" --arg hf "$hf" '\
'"{version:\$v,dmesg:\$d,allowed:\$a,outside:\$o,direct:\$n,real_credentials:\$c,h3_allowed:\$h,h3_outside:\$ho,h3_forbidden_host:\$hf}" > /workspace/out/result.json'

# The HTTP/3 client, static so it runs on the image's C library.
mkdir -p "$work/ws"
if [ -n "${H3GET:-}" ]; then
  cp "$H3GET" "$work/ws/h3get"
else
  cargo build --release --locked --target x86_64-unknown-linux-musl --manifest-path ci/h3get/Cargo.toml
  cp ci/h3get/target/x86_64-unknown-linux-musl/release/h3get "$work/ws/h3get"
fi

"$WICKET" identity init --trust-domain ci.wicket.test >/dev/null
printf 'mock-model-credential' | "$WICKET" secret set mock >/dev/null

"$WICKET" dev mock-llm --listen 127.0.0.1:9999 --command "$probe" 2>"$work/mock.log" &
mock_pid=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/9999) 2>/dev/null && break; sleep 0.2; done

echo "== wicket run ci/smoke.yaml"
run_status=0
"$WICKET" run ci/smoke.yaml --workdir "$work/ws" ${IMAGE:+--image "$IMAGE"} 2>&1 | tee "$work/run.log" || run_status=$?

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
check "HTTP/3: a request in reach gets 200" '[ "$(field h3_allowed)" = 200 ]'
check "HTTP/3: a request outside reach gets 403" '[ "$(field h3_outside | cut -d: -f1)" = 403 ]'
check "HTTP/3: a forbidden host doesn't resolve" '[ "$(field h3_forbidden_host)" = nxdomain ]'
check "HTTP/3: the lookups are logged" 'grep -qE "\[egress\] ALLOW +DNS example.com" "$work/run.log" && grep -qE "\[egress\] BLOCKED DNS forbidden.example.com" "$work/run.log"'
check "no real model credential in the box" '[ "$(field real_credentials)" = 0 ]'
check "the model saw the injected credential" 'grep -q "key=injected" "$work/mock.log"'
check "the model never saw the placeholder" '! grep -q "PLACEHOLDER" "$work/mock.log"'
check "the audit chain verifies" '"$WICKET" audit --verify >/dev/null'

if [ "$fail" != 0 ]; then
  echo "== mock model log"; cat "$work/mock.log"
  exit 1
fi
echo "smoke test passed"

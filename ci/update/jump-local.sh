# shellcheck shell=bash disable=SC2016,SC2034,SC2154  # sourced by ci/update.sh at its end: its helpers and variables
# #207, last: with the remote nodes revoked (absent), a protocol jump with only this host's own node
# goes through, and its node's serve moves with the control host.
log "7. a protocol jump with only this host's own node"
w node revoke n1 >/dev/null 2>&1 || true
w node revoke n2 >/dev/null 2>&1 || true
set +e
WICKET_TEST_DESCRIBE_PROTOCOL=199 w self update "$work/K" --window 5s --interval 5s >"$work/u-jump-local.log" 2>&1
st=$?
set -e
cat "$work/u-jump-local.log"
W=$WICKET_HOME/versions/current/wicket
check "a jump with no remote node left goes through, this host's node with it" \
  '[ "$st" = 0 ] && [ "$(current "$WICKET_HOME/versions")" = "$K_ID" ] && [ "$(serve_runs "$local_serve")" = "$K_ID" ]'

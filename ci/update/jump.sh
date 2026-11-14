# shellcheck shell=bash disable=SC2016,SC2034,SC2154  # sourced by ci/update.sh: its helpers, variables and eval'd checks
# Protocol jumps (#207). Builds J and K are the same code again, staged as if they spoke a protocol
# far ahead (WICKET_TEST_DESCRIBE_PROTOCOL: a debug build's test override, read only by `self
# describe`, so the processes themselves still talk). A jump switches the control host with every
# enrolled node or not at all:
#   1. with node n2 left out, it is refused, naming n2, and nothing changes;
#   2. with every node, the control host and both nodes switch together, their serves re-executed in
#      place, and the agents take another turn;
#   3. with the remote nodes revoked, a jump with only this host's own node goes through.
log "5c. protocol jumps"
for b in J K; do cp "$A" "$work/$b" && printf '\nwicket ci/update.sh build %s\n' "$b" >>"$work/$b"; w self sign --key "$work/release.key" "$work/$b" >/dev/null; done
J_ID=$(id_of "$work/J") K_ID=$(id_of "$work/K")
before=$(current "$WICKET_HOME/versions")
set +e
WICKET_TEST_DESCRIBE_PROTOCOL=99 w self update "$work/J" --nodes n1 --window 5s --interval 5s >"$work/u-jump-refused.log" 2>&1
st=$?
set -e
cat "$work/u-jump-refused.log"
check "a protocol jump with node n2 left behind is refused, naming it" \
  '[ "$st" != 0 ] && grep -q "n2 would not" "$work/u-jump-refused.log" && [ "$(current "$WICKET_HOME/versions")" = "$before" ] && [ "$(current "$(node_dir n1)/versions")" != "$J_ID" ]'
set +e
WICKET_TEST_DESCRIBE_PROTOCOL=99 w self update "$work/J" --nodes all --window 5s --interval 5s >"$work/u-jump.log" 2>&1
st=$?
set -e
cat "$work/u-jump.log"
W=$WICKET_HOME/versions/current/wicket
check "  with every node in it, the control host and both nodes switch together" \
  '[ "$st" = 0 ] && grep -q "switch together" "$work/u-jump.log" && [ "$(current "$WICKET_HOME/versions")" = "$J_ID" ] && [ "$(current "$(node_dir n1)/versions")" = "$J_ID" ] && [ "$(current "$(node_dir n2)/versions")" = "$J_ID" ] && [ "$(serve_runs "$n1_pid")" = "$J_ID" ] && [ "$(serve_runs "$n2_pid")" = "$J_ID" ]'
check "  and the nodes' switch is audited as with the control host" 'w audit --tail 300 | grep self.committed | grep -q "\"with_control_host\":true"'
another_turn "the protocol jump"

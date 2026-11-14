#!/usr/bin/env bash
# End-to-end check of `wicket node serve` (#57, #153): a box on a node keeps working while the control
# host is unreachable, for as long as its authority lasts, and its node stops it when that ends.
#
#   ci/node-e2e.sh --local        localhost as the node: two data directories, `node serve` run directly,
#                                 the ssh hop replaced by WICKET_NODE_SSH (everything but ssh is real)
#   ci/node-e2e.sh <node>         an enrolled node (enrolled with --hosts example.com, `wicket node install`
#                                 done, the agent image present there), with this shell's WICKET_HOME
#                                 (and WICKET_NODE_SSH, if wicket reaches the node through one)
#
# Needs Docker with runsc where the box runs and the agent image (`wicket image`). Env: WICKET (the
# binary, default target/debug/wicket); IMAGE (the agent image, default wicket/claude-code:poc); for
# --local, WICKET_DOCKER (e.g. "sudo -n docker").
#
# The program (ci/node-e2e/probe.sh) probes once a second: an allowed read and write on example.com,
# an out-of-reach path there (decided on the node), and www.example.org (forwarded to the control
# host). Its zone's authority lasts AUTH seconds from the run's start (default 100; the nightly run uses
# 300). The script:
#   1. lets it run connected;
#   2. cuts the control channel for CUT seconds (default 30; the nightly run uses 165, longer than
#      the old 150 s offline window): the node's control socket is moved aside (so reconnects fail)
#      and the channel's forwarder (`... wicket node attach`) is killed;
#   3. restores it; the out-of-reach request queued on the node meanwhile is raised;
#   4. approves it (a grant pushed to the node), then revokes the grant;
#   5. sends the node a tampered and a replayed freshness statement;
#   6. cuts the channel again, past the authority's end: the node stops the box on its own; restores it;
# and reports, from the box's own timestamps, how the box fared while cut off.
# Short feed timings (TTL 6 s, refresh 1 s) through the WICKET_FEED_* test overrides.
set -euo pipefail
cd "$(dirname "$0")/.."
WICKET=$(realpath "${WICKET:-target/debug/wicket}")
MODE=${1:?usage: ci/node-e2e.sh --local | <enrolled node>}
export WICKET_FEED_TTL_MS=${WICKET_FEED_TTL_MS:-6000} WICKET_FEED_REFRESH_MS=${WICKET_FEED_REFRESH_MS:-1000}
# The cut and the authority are short by default (#219): what they show doesn't depend on their
# length, since a node keeps deciding for as long as the authority lasts. The nightly run
# (.github/workflows/acceptance.yml) sets CUT=165 AUTH=300, past the old 150 s offline window.
TTL=$((WICKET_FEED_TTL_MS / 1000)) CUT=${CUT:-30} AUTH=${AUTH:-100}
[ "$AUTH" -ge $((CUT + 60)) ] || { echo "AUTH ($AUTH s) must outlast the first cut and the steps after it: at least CUT + 60" >&2; exit 2; }
work=$(mktemp -d)
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -f "${manifest:-}"
  echo "logs: $work"
}
trap cleanup EXIT
log() { echo "== $(date +%T) $*"; }
now_ms() { date +%s%3N; }

if [ "$MODE" = --local ]; then
  NODE=n1
  export WICKET_HOME="$work/control"
  nodehome="$work/nodehome"
  mkdir -p "$nodehome"
  nodedir="$nodehome/.local/share/wicket-node"
  export WICKET_NODE_SSH="env HOME=$nodehome sh -c"
  "$WICKET" identity init --trust-domain e2e.wicket.test >/dev/null
  token=$("$WICKET" node token --name "$NODE" 2>/dev/null)
  # A placeholder host key: with WICKET_NODE_SSH nothing checks it.
  "$WICKET" node enrol wicket@n1.example.com --token "$token" --hosts example.com \
    --host-key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEggj6FyU//JJDZKykzPImKRPFveTcOK9nWc/L0oCx+k'
  "$WICKET" node install "$NODE" --no-service
  HOME=$nodehome "$nodehome/.local/bin/wicket" node serve >"$work/node.log" 2>&1 &
  pids+=($!)
  # `serve` hashes its binary as it starts, which takes a while on a busy machine.
  for _ in $(seq 450); do [ -S "$nodedir/ctl/ctl.sock" ] && break; sleep 0.2; done
  [ -S "$nodedir/ctl/ctl.sock" ] || { echo "node serve did not start within 90 s"; cat "$work/node.log"; exit 1; }
  node_sh() { env HOME="$nodehome" sh -c "$1"; }
else
  NODE=$MODE
  row=$("$WICKET" node list | awk -v n="$NODE" '$1==n')
  [ -n "$row" ] || { echo "node $NODE is not enrolled here"; exit 1; }
  target=$(awk '{print $3}' <<<"$row")
  pin="${WICKET_HOME:-$HOME/.local/share/wicket}/nodes/$NODE/known_hosts"
  # WICKET_E2E_SSH_KEY: the identity for the node, if ssh's default keys don't reach it.
  # WICKET_NODE_SSH (as wicket itself honours it): a stand-in for ssh, e.g. a node on this host.
  if [ -n "${WICKET_NODE_SSH:-}" ]; then
    node_sh() { $WICKET_NODE_SSH "$1"; }
  else
    node_sh() { ssh ${WICKET_E2E_SSH_KEY:+-i "$WICKET_E2E_SSH_KEY"} -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$pin" -o GlobalKnownHostsFile=/dev/null \
      -o "HostKeyAlias=wicket-node-$NODE" "$target" "$1"; }
  fi
  nodedir='$HOME/.local/share/wicket-node'
fi

log "wicket run --node $NODE"
# The probe runs until its node stops it at the authority's end. The copy sits next to the original so
# `source: .` still works.
manifest=ci/node-e2e/.e2e-run.yaml
sed "s/\"110\"/\"$((AUTH + 300))\"/; s/timeout: 5m/timeout: $((AUTH + 300))s, authority: ${AUTH}s/" ci/node-e2e/e2e.yaml > "$manifest"
t_start=$(now_ms)
"$WICKET" run "$manifest" --image "${IMAGE:-wicket/claude-code:poc}" --node "$NODE" >"$work/run.log" 2>&1 &
run_pid=$!
pids+=($run_pid)
for _ in $(seq 120); do grep -q ' read=' "$work/run.log" && break; sleep 1; done
grep -q ' read=' "$work/run.log" || { cat "$work/run.log"; exit 1; }
run=$(sed -n 's/^wicket run \(run_[a-z0-9]*\).*/\1/p' "$work/run.log" | head -1)
transcript="${WICKET_HOME:-$HOME/.local/share/wicket}/runs/$run/transcript.jsonl"
# Whether the box has printed a probe line at or after $1 (ms) matching $2 (an awk regex); and
# waiting up to $1 seconds for one, instead of a fixed sleep.
probed() { awk -v t="$1" -v k="$2" '$1+0 >= t && $0 ~ k {f=1} END {exit !f}' "$transcript" 2>/dev/null; }
wait_probe() { local n=$1; shift; for _ in $(seq $((n * 2))); do probed "$@" && return 0; sleep 0.5; done; return 1; }
sleep 3   # a few lines while connected, before the cut

# The channel's forwarder: the run's child (ssh, or the local stand-in) and everything under it.
kill_tree() { local c; for c in $(pgrep -P "$1"); do kill_tree "$c"; done; kill "$1" 2>/dev/null || true; }
cut() {
  node_sh "mv $nodedir/ctl/ctl.sock $nodedir/ctl/ctl.sock.off"
  for c in $(pgrep -P "$run_pid"); do kill_tree "$c"; done
}
restore() { node_sh "mv $nodedir/ctl/ctl.sock.off $nodedir/ctl/ctl.sock"; }

log "cutting the control channel for ${CUT}s"
cut
t_cut=$(now_ms)
sleep "$CUT"
log "restoring it"
restore
t_restore=$(now_ms)
for _ in $(seq 30); do grep -q 'reconnected' "$work/run.log" && break; sleep 0.5; done
t_reconnected=$(now_ms)
# The out-of-reach request queued on the node while cut off, raised on reconnect.
# (grep reads all of it: with -q, `pending` could die of SIGPIPE, and pipefail would call that a miss.)
for _ in $(seq 60); do "$WICKET" pending 2>/dev/null | grep 'example.com/out-of-reach' >/dev/null && break; sleep 0.5; done

log "approving the out-of-reach request (queued on the node while cut off, raised on reconnect)"
"$WICKET" pending
rid=$("$WICKET" pending | grep 'example.com/out-of-reach' | grep -o '^r-[a-z0-9]*' | head -1)
gid=$("$WICKET" approve "$rid" --yes --unlimited --ttl 10m | grep -o '→ grant g-[a-z0-9]*' | grep -o 'g-[a-z0-9]*' | head -1)
t_approve=$(now_ms)
# Until the box sees the grant: the out-of-reach request is let through (anything but a 403).
wait_probe 30 "$t_approve" ' out=([^4]|4[^0]|40[^3])' || true
log "revoking grant $gid"
"$WICKET" grant revoke "$gid"
t_revoke=$(now_ms)
# Until the box sees the revocation: refused again.
wait_probe 30 "$t_revoke" ' out=403' || true

log "a tampered and a replayed statement"
if [ "$MODE" = --local ]; then
  HOME=$nodehome "$nodehome/.local/bin/wicket" dev node-feed-probe | tee "$work/probe.out"
else
  node_sh '"$HOME/.local/bin/wicket" dev node-feed-probe' | tee "$work/probe.out"
fi
sleep 4

log "cutting the channel again, past the end of the box's authority (${AUTH}s from the run's start)"
cut
t_cut2=$(now_ms)
while [ "$(now_ms)" -lt $((t_start + AUTH * 1000 + 20000)) ]; do sleep 2; done
log "restoring it"
restore
t_restore2=$(now_ms)
for _ in $(seq 90); do kill -0 "$run_pid" 2>/dev/null || break; sleep 1; done
if kill -0 "$run_pid" 2>/dev/null; then
  echo "FAIL the run did not end after its box's authority expired"
  kill -INT "$run_pid" 2>/dev/null || true
  exit 1
fi
# The node's log: NODE_LOG if the caller has it (a node run by hand), else its journal.
if [ -n "${NODE_LOG:-}" ]; then cp "$NODE_LOG" "$work/node.log"
elif [ "$MODE" != --local ]; then node_sh 'XDG_RUNTIME_DIR=/run/user/$(id -u) journalctl --user -u wicket-node -o cat --since "-15 min"' >"$work/node.log" 2>/dev/null || true
fi
# When the node stopped the box: what the run printed from the node's exit (#153), or the node's log.
t_expired=$(grep -o "stopped by wicket: its authority expired at [0-9]* ms" "$work/run.log" | grep -o '[0-9]* ms' | grep -o '[0-9]*' | tail -1 || true)
[ -n "$t_expired" ] || t_expired=$(grep -o "$run: its authority expired at [0-9]* ms" "$work/node.log" 2>/dev/null | grep -o '[0-9]* ms' | grep -o '[0-9]*' | tail -1 || true)
# Else from the node's audit, shipped to the control host on reconnect.
for _ in $(seq 20); do
  [ -z "$t_expired" ] || break
  t_expired=$("$WICKET" audit --tail 5000 | grep node.authority_expired | grep "$run" | grep -o '"until_ms":[0-9]*' | grep -o '[0-9]*' | tail -1 || true)
  [ -n "$t_expired" ] || sleep 1
done
[ -n "$t_expired" ] || { echo "no authority expiry found; the run's last lines:"; tail -5 "$work/run.log"; grep -i authority "$work/node.log" 2>/dev/null | tail -3; }

python3 -I - "$transcript" "$t_cut" "$t_restore" "$t_reconnected" "$t_approve" "$t_revoke" "$t_cut2" "$t_restore2" "${t_expired:-0}" "$CUT" <<'PY' | tee "$work/summary.txt"
import sys
path, cut, restore, reconnected, approve, revoke, cut2, restore2, expired, cut_s = sys.argv[1], *map(int, sys.argv[2:])
rows = {}
for line in open(path):
    f = line.split()
    if len(f) < 5 or not f[0].isdigit():
        continue
    rows[int(f[0])] = dict(kv.split("=", 1) for kv in f[1:])
ts = sorted(rows)
# Let through by wicket (no x-wicket kind), whatever the upstream answered.
ok = lambda v: not v.startswith("000") and v.rsplit(":", 1)[-1] == "-"
within = lambda a, b: [t for t in ts if a <= t < b]
s = lambda t, at: "-" if t is None else f"{(t - at) / 1000:+.1f}s"
c1 = within(cut, restore)
w_ok = [t for t in c1 if ok(rows[t]['write'])]
r_ok = [t for t in c1 if ok(rows[t]['read'])]
print(f"lines: {len(ts)} ({len(c1)} during the {cut_s}s cut; replayed after reconnect)")
print(f"  during the cut: {len(w_ok)} writes and {len(r_ok)} reads allowed of {len(c1)}; last write {s(max(w_ok) if w_ok else None, cut)}")
print(f"  out-of-reach (node decides): {sorted({rows[t]['out'] for t in c1})}")
print(f"  forwarded host:              {sorted({rows[t]['fwd'] for t in c1})}")
back = [t for t in ts if t >= restore and ok(rows[t]['write'])]
print(f"  restored: socket back at {s(restore, cut)}, reconnected {s(reconnected, cut)}, first write after {s(min(back) if back else None, cut)}")
before = sorted({rows[t]['out'] for t in ts if t < cut})
print(f"connected, before the cut: read {sorted({rows[t]['read'] for t in ts if t < cut})} write {sorted({rows[t]['write'] for t in ts if t < cut})} out {before} fwd {sorted({rows[t]['fwd'] for t in ts if t < cut})}")
g = [t for t in ts if approve <= t < revoke and not rows[t]['out'].startswith("403")]
print(f"after approval: out-of-reach allowed from {s(min(g), approve) if g else '-'} after the approval")
r = [t for t in ts if t >= revoke and rows[t]['out'].startswith("403")]
print(f"after revocation: refused again from {s(min(r), revoke) if r else '-'} after the revocation")
c2 = within(cut2, restore2)
last = max(c2) if c2 else None
print(f"second cut: {len(c2)} lines; the node stopped the box at its authority's end, {expired} ms; last line {s(last, expired) if expired else '-'}")
checks = [
    (f"writes and reads kept working through the {cut_s}s cut, past {cut_s - 10} s", len(c1) > 0 and len(w_ok) >= 0.9 * len(c1) and len(r_ok) >= 0.9 * len(c1) and w_ok and max(w_ok) - cut >= (cut_s - 10) * 1000),
    ("an out-of-reach request was queued on the node while cut off", any(rows[t]['out'] == "403:queued" for t in c1)),
    ("the forwarded host was refused while cut off", all(not ok(rows[t]['fwd']) for t in c1)),
    ("restored after reconnect", bool(back)),
    ("approval reached the node", bool(g)),
    ("revocation reached the node", bool(r)),
    ("cut off again, the box kept working until its authority's end, and stopped then", expired > 0 and last is not None and expired - 15_000 <= last <= expired + 3_000),
]
bad = 0
for name, c in checks:
    print(("ok   " if c else "FAIL ") + name)
    bad += not c
sys.exit(1 if bad else 0)
PY
# Push latency of the revocation: ledger → published (the run polls the ledger every 250 ms) → applied
# on the node (after the node fsyncs it). Remote: the two clocks differ by their skew.
pub=$(grep -o 'token with [0-9]* live grant(s) to node [a-z0-9-]*, epoch [0-9]* (at [0-9]* ms)' "$work/run.log" | tail -1 || true)
if [ -n "$pub" ]; then
  ep=$(sed -E 's/.*epoch ([0-9]+).*/\1/' <<<"$pub"); tp=$(sed -E 's/.*at ([0-9]+) ms.*/\1/' <<<"$pub")
  ta=$(grep "feed delta applied, epoch $ep " "$work/node.log" 2>/dev/null | sed -E 's/.*at ([0-9]+) ms.*/\1/' | tail -1 || true)
  applied="(node log unavailable)"
  [ -n "$ta" ] && applied="$((ta - tp)) ms after publishing"
  echo "revocation: published $((tp - t_revoke)) ms after \`wicket grant revoke\`, applied on the node $applied" | tee -a "$work/summary.txt"
fi
grep -q '^bad_signature' "$work/probe.out" && echo "ok   a tampered statement is refused (bad signature)" || { echo "FAIL tampered statement"; exit 1; }
grep -q '^replay' "$work/probe.out" && echo "ok   a replayed statement is refused" || { echo "FAIL replayed statement"; exit 1; }
"$WICKET" audit --verify | tee -a "$work/summary.txt"
"$WICKET" audit --verify | grep -q "node $NODE audit chain OK" && echo "ok   the node's audit records were shipped and verify"
echo "node e2e passed"

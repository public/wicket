#!/usr/bin/env bash
# End-to-end check of `wicket node serve` (#57): a box on a node keeps working for allowed requests
# while the control host is unreachable, fails narrow, and comes back when the channel does.
#
#   ci/node-e2e.sh --local        localhost as the node: two data directories, `node serve` run directly,
#                                 the ssh hop replaced by WICKET_NODE_SSH (everything but ssh is real)
#   ci/node-e2e.sh <node>         an enrolled node (enrolled with --hosts example.com, `wicket node install`
#                                 done, the agent image present there), with this shell's WICKET_HOME
#
# Needs Docker with runsc where the box runs and the agent image (`wicket image`). Env: WICKET (the
# binary, default target/debug/wicket); for --local, WICKET_DOCKER (e.g. "sudo -n docker").
#
# The program (ci/node-e2e/probe.sh) probes once a second: an allowed read and write on example.com,
# an out-of-reach path there (decided on the node), and www.example.org (forwarded to the control
# host). The script then:
#   1. lets it run connected;
#   2. cuts the control channel: the node's control socket is moved aside (so reconnects fail) and the
#      channel's forwarder (`... wicket node attach`) is killed;
#   3. restores it after TTL + narrow window + margin;
#   4. approves the out-of-reach request (a grant pushed to the node), then revokes the grant;
#   5. sends the node a tampered and a replayed freshness statement;
# and reports, from the box's own timestamps, how long writes and reads kept working after the cut.
# Short feed timings (TTL 6 s, refresh 1 s, narrow 10 s) through the WICKET_FEED_* test overrides.
set -euo pipefail
cd "$(dirname "$0")/.."
WICKET=$(realpath "${WICKET:-target/debug/wicket}")
MODE=${1:?usage: ci/node-e2e.sh --local | <enrolled node>}
export WICKET_FEED_TTL_MS=${WICKET_FEED_TTL_MS:-6000} WICKET_FEED_REFRESH_MS=${WICKET_FEED_REFRESH_MS:-1000} WICKET_FEED_NARROW_MS=${WICKET_FEED_NARROW_MS:-10000}
TTL=$((WICKET_FEED_TTL_MS / 1000)) NARROW=$((WICKET_FEED_NARROW_MS / 1000))
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
  for _ in $(seq 50); do [ -S "$nodedir/ctl/ctl.sock" ] && break; sleep 0.2; done
  node_sh() { env HOME="$nodehome" sh -c "$1"; }
else
  NODE=$MODE
  row=$("$WICKET" node list | awk -v n="$NODE" '$1==n')
  [ -n "$row" ] || { echo "node $NODE is not enrolled here"; exit 1; }
  target=$(awk '{print $3}' <<<"$row")
  pin="${WICKET_HOME:-$HOME/.local/share/wicket}/nodes/$NODE/known_hosts"
  # WICKET_E2E_SSH_KEY: the identity for the node, if ssh's default keys don't reach it.
  node_sh() { ssh ${WICKET_E2E_SSH_KEY:+-i "$WICKET_E2E_SSH_KEY"} -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$pin" -o GlobalKnownHostsFile=/dev/null \
    -o "HostKeyAlias=wicket-node-$NODE" "$target" "$1"; }
  nodedir='$HOME/.local/share/wicket-node'
fi

log "wicket run --node $NODE"
# The probe must outlast the cut (TTL + narrow window) and the steps after it; 110 s fits the test
# timings, and longer timings stretch it. The copy sits next to the original so `source: .` still works.
probe_secs=$(( TTL + NARROW + 70 > 110 ? TTL + NARROW + 70 : 110 ))
manifest=ci/node-e2e/.e2e-run.yaml
sed "s/\"110\"/\"$probe_secs\"/" ci/node-e2e/e2e.yaml > "$manifest"
"$WICKET" run "$manifest" --image wicket/claude-code:poc --node "$NODE" >"$work/run.log" 2>&1 &
run_pid=$!
pids+=($run_pid)
for _ in $(seq 120); do grep -q ' read=' "$work/run.log" && break; sleep 1; done
grep -q ' read=' "$work/run.log" || { cat "$work/run.log"; exit 1; }
run=$(sed -n 's/^wicket run \(run_[a-z0-9]*\).*/\1/p' "$work/run.log" | head -1)
sleep 8

log "cutting the control channel"
node_sh "mv $nodedir/ctl/ctl.sock $nodedir/ctl/ctl.sock.off"
t_cut=$(now_ms)
# The channel's forwarder: the run's child (ssh, or the local stand-in) and everything under it.
kill_tree() { local c; for c in $(pgrep -P "$1"); do kill_tree "$c"; done; kill "$1" 2>/dev/null || true; }
for c in $(pgrep -P "$run_pid"); do kill_tree "$c"; done
sleep $((TTL + NARROW + 8))
log "restoring it"
node_sh "mv $nodedir/ctl/ctl.sock.off $nodedir/ctl/ctl.sock"
t_restore=$(now_ms)
for _ in $(seq 30); do grep -q 'reconnected' "$work/run.log" && break; sleep 0.5; done
t_reconnected=$(now_ms)
sleep 6

log "approving the out-of-reach request"
"$WICKET" pending
rid=$("$WICKET" pending | grep 'example.com/out-of-reach' | grep -o '^r-[a-z0-9]*' | head -1)
gid=$("$WICKET" approve "$rid" --unlimited --ttl 10m | grep -o 'g-[a-z0-9]*' | head -1)
t_approve=$(now_ms)
sleep 6
log "revoking grant $gid"
"$WICKET" grant revoke "$gid"
t_revoke=$(now_ms)
sleep 6

log "a tampered and a replayed statement"
if [ "$MODE" = --local ]; then
  HOME=$nodehome "$nodehome/.local/bin/wicket" dev node-feed-probe | tee "$work/probe.out"
else
  node_sh '"$HOME/.local/bin/wicket" dev node-feed-probe' | tee "$work/probe.out"
fi
sleep 4
log "stopping the run"
kill -INT "$run_pid" 2>/dev/null || true
for _ in $(seq 60); do kill -0 "$run_pid" 2>/dev/null || break; sleep 1; done

transcript="${WICKET_HOME:-$HOME/.local/share/wicket}/runs/$run/transcript.jsonl"
python3 -I - "$transcript" "$t_cut" "$t_restore" "$t_reconnected" "$t_approve" "$t_revoke" "$TTL" "$NARROW" <<'PY' | tee "$work/summary.txt"
import sys
path, cut, restore, reconnected, approve, revoke, ttl, narrow = sys.argv[1], *map(int, sys.argv[2:])
rows = {}
for line in open(path):
    f = line.split()
    if len(f) < 5 or not f[0].isdigit():
        continue
    rows[int(f[0])] = dict(kv.split("=", 1) for kv in f[1:])
ts = sorted(rows)
ok = lambda v: not v.endswith(":unavailable") and not v.startswith("000")
def last(key, a, b):
    t = [x for x in ts if a <= x < b and ok(rows[x][key])]
    return max(t) if t else None
def first_bad(key, a, b):
    t = [x for x in ts if a <= x < b and not ok(rows[x][key])]
    return min(t) if t else None
s = lambda t: "-" if t is None else f"{(t - cut) / 1000:+.1f}s"
print(f"lines: {len(ts)} ({len([t for t in ts if cut <= t < restore])} while cut; replayed after reconnect)")
print(f"after the cut (TTL {ttl}s, narrow window {narrow}s; times from the cut, box clock):")
print(f"  writes allowed until {s(last('write', cut, restore))}, first refused {s(first_bad('write', cut, restore))}")
print(f"  reads  allowed until {s(last('read', cut, restore))}, first refused {s(first_bad('read', cut, restore))}")
print(f"  out-of-reach (node decides): {sorted({rows[t]['out'] for t in ts if cut <= t < restore})}")
print(f"  forwarded host:              {sorted({rows[t]['fwd'] for t in ts if cut <= t < restore})}")
back = [t for t in ts if t >= restore and ok(rows[t]['write'])]
print(f"  restored: socket back at {s(restore)}, reconnected {s(reconnected)}, first write allowed {s(min(back) if back else None)}")
before = sorted({rows[t]['out'] for t in ts if t < cut})
print(f"connected, before the cut: read {sorted({rows[t]['read'] for t in ts if t < cut})} write {sorted({rows[t]['write'] for t in ts if t < cut})} out {before} fwd {sorted({rows[t]['fwd'] for t in ts if t < cut})}")
g = [t for t in ts if approve <= t < revoke and not rows[t]['out'].startswith("403")]
print(f"after approval: out-of-reach allowed from {s(min(g)) if g else '-'} (approved at {s(approve)})")
r = [t for t in ts if t >= revoke and rows[t]['out'].startswith("403")]
print(f"after revocation: refused again from {s(min(r)) if r else '-'} (revoked at {s(revoke)})")
w_last, r_last, r_bad = last('write', cut, restore), last('read', cut, restore), first_bad('read', cut, restore)
checks = [
    ("writes kept working after the cut, then stopped before TTL+1s", w_last is not None and w_last - cut >= 0 and w_last - cut <= (ttl + 1) * 1000),
    ("reads outlived writes, and stopped by TTL+narrow+1s", r_last is not None and w_last is not None and r_last > w_last and r_last - cut <= (ttl + narrow + 1) * 1000),
    ("everything refused after that", r_bad is not None and all(not ok(rows[t]['write']) and not ok(rows[t]['read']) for t in ts if r_bad <= t < restore)),
    ("restored after reconnect", bool(back)),
    ("approval reached the node", bool(g)),
    ("revocation reached the node", bool(r)),
]
bad = 0
for name, c in checks:
    print(("ok   " if c else "FAIL ") + name)
    bad += not c
sys.exit(1 if bad else 0)
PY
# Push latency of the revocation: ledger → published (the run polls the ledger every 250 ms) → applied
# on the node (after the node fsyncs it). Remote: the two clocks differ by their skew.
[ "$MODE" = --local ] || node_sh 'XDG_RUNTIME_DIR=/run/user/$(id -u) journalctl --user -u wicket-node -o cat --since "-15 min"' >"$work/node.log" 2>/dev/null || true
pub=$(grep -o 'published [0-9]* grant change(s) to node [a-z0-9-]*, epoch [0-9]* (at [0-9]* ms)' "$work/run.log" | tail -1 || true)
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

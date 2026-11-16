#!/usr/bin/env bash
# The deterministic simulation's seeds (#324, crates/wicket-sim): its scenarios on turmoil's
# simulated network and clock, with faults from each seed, checked against #321's invariants:
# `feed` (no egress allow without a live grant; model spend within the run's budget), `placement`
# (no node used past its lease; no two runs colliding on one node; no node released while a run's
# box or uncollected work is on it; the money envelope) and `messages` (no message lost or delivered
# twice; a refused message's receipt says so).
#
#   ci/sim.sh [--seeds N] [--from S] [--file-issues]
#
# Pull requests don't need this script: `wicket-sim`'s tests run a fixed set of seeds whenever
# ci/affected.py selects the crate (a change to it, to a crate it uses, or to the node code its
# stand-ins follow, ci/affected.map). This runs N more (default 200) from S (default: a different
# block each day, so the nightly runs cover new seeds), optimised. Every failing seed's replay
# command goes to sim-failures.txt. With --file-issues (nightly, GH_TOKEN set), each failing seed
# without an open issue gets one, filed with its replay command and what it broke. Known findings
# not yet fixed (the messages scenario's relay loss) are counted in the log, not failures.
set -euo pipefail
cd "$(dirname "$0")/.."

seeds=200
from=$((10#$(date -u +%j) * 100000))
file=false
while [ $# -gt 0 ]; do
  case "$1" in
    --seeds) seeds=$2; shift 2 ;;
    --from) from=$2; shift 2 ;;
    --file-issues) file=true; shift ;;
    *) echo "usage: ci/sim.sh [--seeds N] [--from S] [--file-issues]" >&2; exit 2 ;;
  esac
done

echo "simulation: seeds $from..$((from + seeds - 1))"
status=0
WICKET_SIM_SEEDS=$seeds WICKET_SIM_FROM=$from \
  cargo test --release --locked -p wicket-sim --test scenario seeds -- --nocapture --test-threads 1 >sim.log 2>&1 || status=$?
grep -E '^seed [0-9]+: [a-z]+: hash' sim.log | tail -n 5 || true
echo "simulation: $(grep -c '^  KNOWN' sim.log || true) known finding(s) (not failures)"
grep -oE 'WICKET_SIM_SEED=[0-9]+ WICKET_SIM_SCENARIO=[a-z]+ cargo test [^`]*' sim.log | sort -u >sim-failures.txt || true
if [ "$status" -ne 0 ] && [ ! -s sim-failures.txt ]; then
  # Not a broken invariant: the build or the harness failed.
  tail -n 50 sim.log
  exit "$status"
fi
if [ ! -s sim-failures.txt ]; then
  echo "simulation: all $seeds seeds hold every invariant"
  exit 0
fi
echo "simulation: $(wc -l <sim-failures.txt) seed(s) broke an invariant:"
sed 's/^/  /' sim-failures.txt
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo "### Simulation seeds that broke an invariant"; sed 's/^/    /' sim-failures.txt; } >>"$GITHUB_STEP_SUMMARY"
fi
if $file; then
  while read -r replay; do
    seed=${replay#WICKET_SIM_SEED=}
    seed=${seed%% *}
    scenario=${replay#*WICKET_SIM_SCENARIO=}
    scenario=${scenario%% *}
    title="simulation: $scenario seed $seed breaks an invariant"
    open=$(gh issue list --state open --search "\"$title\" in:title" --json number --jq length)
    if [ "$open" = 0 ]; then
      body=$(printf 'The nightly simulation run (#324) found seed %s of the %s scenario breaking an invariant.\n\nReplay it:\n\n    %s\n\nWhat it broke:\n\n%s\n' \
        "$seed" "$scenario" "$replay" "$(grep -A80 -E "^(placement |messages )?seed $seed: (node clock|link latency)" sim.log | grep -E 'VIOLATION|fault|grant at|  at ' | head -40 | sed 's/^/    /')")
      gh issue create --title "$title" --body "$body"
    fi
  done <sim-failures.txt
fi
exit 1

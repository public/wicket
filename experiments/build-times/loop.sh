#!/usr/bin/env bash
# The inner loop (#219): what a session waits for after a one-line change. For each case: append a
# comment to one file, then
#   build      cargo build -p wicket-cli (the binary the e2e scripts run)
#   test-build cargo test --no-run for the affected crates (the change's crate and its reverse
#              dependencies, as ci/affected.py selects them)
#   test-run   running those tests (cargo test, or cargo nextest run with LOOP_NEXTEST=1)
# and record each one's wall time and peak memory, then revert and rebuild (untimed).
#
#   experiments/build-times/loop.sh LABEL [CASE...]     cases: proxy cli core (default proxy core)
#
# The variant is the environment (CARGO_BUILD_JOBS, CARGO_INCREMENTAL, RUSTC_WRAPPER, RUSTFLAGS,
# CARGO_PROFILE_*), plus LOOP_CARGO_ARGS for `--config` overrides, all recorded with each line. The
# target dir (LOOP_TARGET, default target-loop) is primed first (`prime`, timed too) and kept, so
# a variant measured twice is warm the second time; delete it between variants that change flags.
set -euo pipefail
cd "$(dirname "$0")/../.."
label=${1:?label}
shift
cases=("$@")
[ ${#cases[@]} -gt 0 ] || cases=(proxy core)
out=experiments/build-times
export CARGO_TARGET_DIR=$PWD/${LOOP_TARGET:-target-loop}
read -r -a extra <<<"${LOOP_CARGO_ARGS:-}"

record() { # case phase seconds peak_kib
  jq -nc --arg label "$label" --arg case "$1" --arg phase "$2" --argjson secs "$3" --argjson peak "$4" \
    --arg jobs "${CARGO_BUILD_JOBS:-}" --arg wrapper "$(basename "${RUSTC_WRAPPER:-}")" --arg incr "${CARGO_INCREMENTAL:-}" \
    --arg rustflags "${RUSTFLAGS:-}" --arg cargo_args "${LOOP_CARGO_ARGS//$HOME/~}" --arg nextest "${LOOP_NEXTEST:-}" \
    --arg load "$(cut -d' ' -f1 /proc/loadavg)" --arg commit "$(git rev-parse --short HEAD)" \
    '{label: $label, case: $case, phase: $phase, secs: $secs, peak_mib: (($peak / 1024) | floor), commit: $commit,
      jobs: $jobs, rustc_wrapper: $wrapper, incremental: $incr, rustflags: $rustflags, cargo_args: $cargo_args,
      nextest: $nextest, load: $load}' >>"$out/loop.jsonl"
  printf '%-28s %-6s %-11s %7ss  peak %5s MiB\n' "$label" "$1" "$2" "$3" "$(($4 / 1024))"
}

timed() { # case phase command...: a failed build stops the run; failed tests are recorded as such
  local c=$1 p=$2; shift 2
  local tf; tf=$(mktemp)
  local log=$out/.loop-$label-$c-$p.log
  local st=0
  /usr/bin/time -f '%e %M' -o "$tf" "$@" >"$log" 2>&1 || st=$?
  if [ "$st" != 0 ] && [ "$p" != test-run ]; then
    tail -30 "$log"
    rm -f "$tf"
    return 1
  fi
  read -r secs peak < <(tail -1 "$tf")
  rm -f "$tf"
  record "$c" "$p$([ "$st" = 0 ] || echo "-failed")" "$secs" "$peak"
}

crates_of() {
  case "$1" in
    proxy) echo "-p wicket-proxy -p wicket-cli" ;;
    cli) echo "-p wicket-cli" ;;
    core) echo "--workspace" ;;
  esac
}
file_of() {
  case "$1" in
    proxy) echo crates/wicket-proxy/src/lib.rs ;;
    cli) echo crates/wicket-cli/src/main.rs ;;
    core) echo crates/wicket-core/src/lib.rs ;;
  esac
}

test_cmd() { # crates...: the command that runs them
  if [ "${LOOP_NEXTEST:-}" = 1 ]; then
    echo "cargo ${extra[*]} nextest run --locked --no-fail-fast $*"
  else
    echo "cargo ${extra[*]} test --locked $*"
  fi
}

# Warm: everything the cases build, with these settings.
all=(--workspace)
timed all prime bash -c "cargo ${extra[*]} build --locked -p wicket-cli && cargo ${extra[*]} test --locked --no-run ${all[*]}"

for c in "${cases[@]}"; do
  f=$(file_of "$c")
  read -r -a crates <<<"$(crates_of "$c")"
  printf '\n// loop.sh: a one-line change\n' >>"$f"
  trap 'git checkout -- "$f"' EXIT
  timed "$c" build cargo "${extra[@]}" build --locked -p wicket-cli
  timed "$c" test-build cargo "${extra[@]}" test --locked --no-run "${crates[@]}"
  timed "$c" test-run bash -c "$(test_cmd "${crates[@]}")"
  git checkout -- "$f"
  trap - EXIT
  cargo "${extra[@]}" build --locked -p wicket-cli >/dev/null 2>&1
  cargo "${extra[@]}" test --locked --no-run "${all[@]}" >/dev/null 2>&1
done

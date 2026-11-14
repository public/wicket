#!/usr/bin/env bash
# Build and test times (#219): one labelled set of measurements of this checkout, appended as JSON
# lines to experiments/build-times/results.jsonl, with each clean build's `cargo --timings` report
# kept as timings-<label>-<step>.html.
#
#   experiments/build-times/measure.sh LABEL [STEP...]
#
# Steps (default: all, in this order):
#   clean        cargo build --workspace --all-targets, from an empty target dir
#   touch-core   rebuild after a one-line change in wicket-core (a comment appended, then removed)
#   touch-cli    the same in wicket-cli
#   test-build   cargo test --workspace --no-run (after `clean`, so what it adds)
#   test-run     cargo test --workspace (built already: the tests' own time)
#   sizes        target dir size, test binary count and sizes
#   release      cargo build --release -p wicket-cli, from an empty target dir (its own)
#
# The environment decides how it builds: CARGO_BUILD_JOBS, RUSTC_WRAPPER (unset it for a cold
# compile), CARGO_INCREMENTAL, RUSTFLAGS. They are recorded with each line. Wall time and peak
# memory (the largest process: rustc or the linker) come from GNU time. Run it alone on the host:
# times on a shared machine vary with its load, which is recorded too (the 1-minute load average
# before each step).
set -euo pipefail
cd "$(dirname "$0")/../.."
label=${1:?label}
shift
steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(clean touch-core touch-cli test-build test-run sizes)
out=experiments/build-times
target=${MEASURE_TARGET:-target-measure}
export CARGO_TARGET_DIR=$PWD/$target

record() { # step seconds peak_kib [extra json]
  local load; load=$(cut -d' ' -f1 /proc/loadavg)
  jq -nc --arg label "$label" --arg step "$1" --argjson secs "$2" --argjson peak "$3" --argjson extra "${4:-{\}}" \
    --arg jobs "${CARGO_BUILD_JOBS:-}" --arg wrapper "$(basename "${RUSTC_WRAPPER:-}")" --arg incr "${CARGO_INCREMENTAL:-}" \
    --arg rustflags "${RUSTFLAGS:-}" --arg load "$load" --arg commit "$(git rev-parse --short HEAD)" \
    '{label: $label, step: $step, secs: $secs, peak_mib: (($peak / 1024) | floor), commit: $commit, jobs: $jobs,
      rustc_wrapper: $wrapper, incremental: $incr, rustflags: $rustflags, load: $load} + $extra' >>"$out/results.jsonl"
  echo "$label $1: ${2}s, peak $(( $3 / 1024 )) MiB"
}

timed() { # step command...: runs it, records wall time and peak memory
  local step=$1; shift
  local tf; tf=$(mktemp)
  /usr/bin/time -f '%e %M' -o "$tf" "$@" >"$out/.last.log" 2>&1 || { tail -20 "$out/.last.log"; rm -f "$tf"; return 1; }
  read -r secs peak <"$tf"
  rm -f "$tf"
  record "$step" "$secs" "$peak"
}

touch_and_build() { # step file
  printf '\n// measure.sh: a one-line change\n' >>"$2"
  timed "$1" cargo build --workspace --all-targets --locked || { git checkout -- "$2"; return 1; }
  git checkout -- "$2"
  # Back to the committed source, so the next step starts from it.
  cargo build --workspace --all-targets --locked >/dev/null 2>&1
}

for s in "${steps[@]}"; do
  case "$s" in
    clean)
      rm -rf "$CARGO_TARGET_DIR"
      timed clean cargo build --workspace --all-targets --locked --timings
      cp "$CARGO_TARGET_DIR"/cargo-timings/cargo-timing.html "$out/timings-$label-clean.html"
      ;;
    touch-core) touch_and_build touch-core crates/wicket-core/src/lib.rs ;;
    touch-cli) touch_and_build touch-cli crates/wicket-cli/src/main.rs ;;
    test-build) timed test-build cargo test --workspace --locked --no-run ;;
    test-run)
      timed test-run cargo test --workspace --locked
      ;;
    sizes)
      bins=$(find "$CARGO_TARGET_DIR/debug/deps" -maxdepth 1 -type f -executable -name '*-*' ! -name '*.so' ! -name '*.d' | wc -l)
      bin_mib=$(find "$CARGO_TARGET_DIR/debug/deps" -maxdepth 1 -type f -executable -name '*-*' ! -name '*.so' -printf '%s\n' | awk '{s+=$1} END{print int(s/1048576)}')
      total=$(du -sm "$CARGO_TARGET_DIR" | cut -f1)
      biggest=$(find "$CARGO_TARGET_DIR/debug/deps" -maxdepth 1 -type f -executable -name '*-*' ! -name '*.so' -printf '%s %f\n' | sort -rn | head -5 \
        | awk '{printf "%s%s=%d", (NR>1?",":""), $2, int($1/1048576)}')
      record sizes 0 0 "$(jq -nc --argjson bins "$bins" --argjson bin_mib "$bin_mib" --argjson total "$total" --arg biggest "$biggest" \
        '{test_and_bin_executables: $bins, executables_mib: $bin_mib, target_mib: $total, biggest_mib: $biggest}')"
      ;;
    release)
      rm -rf "$CARGO_TARGET_DIR-release"
      CARGO_TARGET_DIR=$CARGO_TARGET_DIR-release timed release cargo build --release --locked -p wicket-cli --timings
      cp "$CARGO_TARGET_DIR-release"/cargo-timings/cargo-timing.html "$out/timings-$label-release.html"
      rm -rf "$CARGO_TARGET_DIR-release"
      ;;
    *) echo "unknown step $s" >&2; exit 2 ;;
  esac
done

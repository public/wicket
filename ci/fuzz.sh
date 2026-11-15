#!/usr/bin/env bash
# The fuzz targets (#323, fuzz/): their corpora replayed on stable, then a short coverage-guided run
# of each target selected. A finding is minimized and left under $FUZZ_WORK/artifacts/<target>/, and
# the script fails.
#
#   ci/fuzz.sh [--secs N] [--affected [--base REF]] [--sanitizer none|address] [--no-replay] [target…]
#
#   target…        the targets to run (default: all; `none` runs none, for a workflow's selection)
#   --secs N       how long each target runs (default 60)
#   --affected     the targets the change selects (ci/affected.py's fuzz-<target> suites), instead
#   --base REF     with --affected: what to compare with (default origin/main)
#   --sanitizer S  none (default: coverage only, the build that fits a 4 GiB box) or address
#   --no-replay    skip the corpus replay (cargo test in fuzz/)
#
# The fuzzer needs a nightly rustc; the stable toolchain is used with RUSTC_BOOTSTRAP=1. Optimized
# builds compile as 16 codegen units (cargo-fuzz's default of one needs more than 3 GiB for
# cedar-policy-core); in a 4 GiB box set CARGO_BUILD_JOBS=1. cargo-fuzz is installed if missing
# (a pinned version). $FUZZ_WORK (default target/fuzz-work) holds the corpora the runs grow, the
# findings and the logs; a run starts from fuzz/corpus/<target> and fuzz/regressions/<target>.
#
# A finding: copy the minimized input to fuzz/regressions/<target>/<name> (the corpus replay then
# runs it on every change), fix it, and run `cargo test` in fuzz/.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

CARGO_FUZZ_VERSION=0.13.2
ALL_TARGETS="egress gateway chan feed token manifest store git"
secs=60 affected=0 base=origin/main sanitizer=none replay=1 targets=()
while [ $# -gt 0 ]; do
  case "$1" in
    --secs) secs=$2; shift ;;
    --affected) affected=1 ;;
    --base) base=$2; shift ;;
    --sanitizer) sanitizer=$2; shift ;;
    --no-replay) replay=0 ;;
    -h | --help) sed -n '2,/^set -E/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
    *) targets+=("$1") ;;
  esac
  shift
done
case "$sanitizer" in none | address) ;; *) echo "--sanitizer: none or address" >&2; exit 2 ;; esac

if [ "$affected" = 1 ]; then
  sel=$(python3 ci/affected.py --base "$base" --worktree 2>/dev/null | sed -n 's/^fuzz: //p')
  [ "$sel" = - ] && sel=none
  read -r -a targets <<<"${sel:-$ALL_TARGETS}"
fi
[ ${#targets[@]} -eq 0 ] && read -r -a targets <<<"$ALL_TARGETS"
if [ "${targets[*]}" = none ]; then
  echo "fuzz: no target selected"
  exit 0
fi
for t in "${targets[@]}"; do
  [[ " $ALL_TARGETS " == *" $t "* ]] || { echo "unknown fuzz target $t (one of: $ALL_TARGETS)" >&2; exit 2; }
done

export RUSTC_BOOTSTRAP=1
target_dir=${CARGO_TARGET_DIR:-$PWD/fuzz/target}
work=${FUZZ_WORK:-$PWD/target/fuzz-work}
mkdir -p "$work"
work=$(cd "$work" && pwd)
# The harnesses' scratch files (a store checkout, a vault, a feed) go here, not to a small /tmp.
export WICKET_FUZZ_TMP=$work/tmp
mkdir -p "$WICKET_FUZZ_TMP"

log() { printf '\n== %s %s\n' "$(date +%H:%M:%S)" "$*"; }

if ! cargo fuzz --version 2>/dev/null | grep -q " $CARGO_FUZZ_VERSION\$"; then
  log "installing cargo-fuzz $CARGO_FUZZ_VERSION"
  cargo install --locked --version "$CARGO_FUZZ_VERSION" cargo-fuzz
fi

if [ "$replay" = 1 ]; then
  log "replaying the corpora and past findings (stable)"
  (cd fuzz && cargo test --locked)
fi

flags=(-O -s "$sanitizer" --codegen-units 16 --target-dir "$target_dir")
failed=() summary=()
for t in "${targets[@]}"; do
  log "fuzz $t (${secs} s, sanitizer $sanitizer)"
  (cd fuzz && cargo fuzz build "${flags[@]}" "$t")
  mkdir -p "$work/corpus/$t" "$work/artifacts/$t"
  dirs=("$work/corpus/$t" "corpus/$t")
  [ -d "fuzz/regressions/$t" ] && dirs+=("regressions/$t")
  rc=0
  (cd fuzz && cargo fuzz run "${flags[@]}" "$t" "${dirs[@]}" -- \
    -max_total_time="$secs" -rss_limit_mb=2048 -timeout=25 -print_final_stats=1 \
    -artifact_prefix="$work/artifacts/$t/") >"$work/$t.log" 2>&1 || rc=$?
  grep -E '^(#[0-9]+ +(INITED|DONE)|Done |==[0-9]+==|SUMMARY|thread .* panicked)' -A1 "$work/$t.log" | head -40 || true
  runs=$(sed -n 's/^stat::number_of_executed_units: *//p' "$work/$t.log" | tail -1)
  if [ "$rc" = 0 ]; then
    summary+=("ok   $t (${runs:-?} runs)")
    continue
  fi
  failed+=("$t")
  summary+=("FAIL $t (${runs:-?} runs; see $work/$t.log)")
  for a in "$work/artifacts/$t"/crash-* "$work/artifacts/$t"/leak-* "$work/artifacts/$t"/timeout-* "$work/artifacts/$t"/oom-*; do
    [ -f "$a" ] || continue
    log "minimizing $(basename "$a")"
    (cd fuzz && cargo fuzz tmin "${flags[@]}" "$t" "$a" -r 2000 -- -timeout=25 \
      -exact_artifact_path="$a.min") >"$a.tmin.log" 2>&1 || true
    [ -f "$a.min" ] || cp "$a" "$a.min"
    echo "finding: $a.min ($(wc -c <"$a.min") bytes); base64:"
    base64 -w0 "$a.min"; echo
    echo "add it as fuzz/regressions/$t/<name>, fix it, and run cargo test in fuzz/"
  done
done

log "summary"
printf '%s\n' "${summary[@]}"
[ ${#failed[@]} -eq 0 ] || { echo "findings in: ${failed[*]}"; exit 1; }

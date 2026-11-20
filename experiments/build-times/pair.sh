#!/usr/bin/env bash
# #219's done-when pair: a clean `cargo build --workspace --all-targets`, then `cargo test --workspace`
# (built by the first step, so the second times the run, doctests included), each from an empty
# target dir, for one checkout. Run it once per variant, alone on the host, and compare the rows.
#
#   experiments/build-times/pair.sh LABEL CHECKOUT [TARGET_DIR]
#
# TARGET_DIR defaults to /tmp/pair-LABEL. Keep it short: tests make unix sockets under
# CARGO_TARGET_TMPDIR, and a path past 108 bytes fails them. `CARGO_BUILD_JOBS` and
# `CARGO_INCREMENTAL` are the caller's (the pair in the README set 4, and 0 for "before"). Rows go to
# pair.jsonl beside this script; each step's log to /tmp/pair-LABEL-STEP.log.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
label=$1 checkout=$2
export CARGO_TARGET_DIR=${3:-/tmp/pair-$label}
unset RUSTC_WRAPPER
rm -rf "$CARGO_TARGET_DIR"
cd "$checkout"
step() {
  local name=$1; shift
  local s e rc
  s=$(date +%s%N)
  "$@" >"/tmp/pair-$label-$name.log" 2>&1
  rc=$?
  e=$(date +%s%N)
  printf '{"label":"%s","commit":"%s","step":"%s","secs":%s,"rc":%s,"jobs":"%s","incremental":"%s"}\n' "$label" \
    "$(git rev-parse --short HEAD)" "$name" "$(( (e - s) / 1000000 ))e-3" "$rc" "${CARGO_BUILD_JOBS:-}" "${CARGO_INCREMENTAL:-}" >>"$here/pair.jsonl"
}
step clean-build cargo build --workspace --all-targets --locked
step test-run cargo test --workspace --no-fail-fast --locked
echo "target dir: $(du -sh "$CARGO_TARGET_DIR" | cut -f1)"

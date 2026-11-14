#!/usr/bin/env bash
# Profiles an end-to-end script (#219 item 4): runs it under `bash -x` with a timestamp on every
# traced command, written to a file of its own (BASH_XTRACEFD, so the script's output and its
# redirections are untouched), then summarises where the time went with analyze.py.
#
#   experiments/build-times/e2e/profile.sh OUT_DIR ci/smoke.sh [args…]
#
# OUT_DIR gets trace.log (the trace), out.log (the script's output) and summary.txt. The script's
# own environment applies (WICKET, IMAGE, WICKET_DOCKER, …).
set -uo pipefail
out=$1; shift
mkdir -p "$out"
here=$(cd "$(dirname "$0")" && pwd)
t0=$(date +%s.%N)
# Each traced command: its time, its file and line, and the call stack's lines (outermost last).
PS4='+${EPOCHREALTIME}|${BASH_SOURCE##*/}:${LINENO}|${BASH_LINENO[*]}| ' BASH_XTRACEFD=7 \
  bash -x "$@" >"$out/out.log" 2>&1 7>"$out/trace.log"
rc=$?
t1=$(date +%s.%N)
python3 -I "$here/analyze.py" "$out/trace.log" "$1" "$rc" "$(echo "$t1 - $t0" | bc)" | tee "$out/summary.txt"
exit "$rc"

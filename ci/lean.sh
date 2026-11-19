#!/usr/bin/env bash
# The Lean spec of authority and matching (#322, verification/lean): its proofs, with no `sorry`,
# then wicket-core checked against it as an oracle (crates/wicket-authz/tests/lean_oracle.rs).
# Lean is pinned (verification/lean/lean-toolchain) and installed by URL and checksum; no Mathlib.
#
#   ci/lean.sh          (LEAN_HOME: an installed toolchain to use instead of downloading one)
set -euo pipefail
cd "$(dirname "$0")/.."
LEAN_VERSION=4.35.0
LEAN_SHA256=c8531faaa4a93d5a4dae0c742cbc1bd42a2993594d02f93a9d629ebf299fb2c8
if ! grep -qx "leanprover/lean4:v$LEAN_VERSION" verification/lean/lean-toolchain; then
  echo "verification/lean/lean-toolchain doesn't pin v$LEAN_VERSION: update both together" >&2
  exit 1
fi
lean_home=${LEAN_HOME:-${TOOLS_DIR:-$PWD/target/tools}/lean-$LEAN_VERSION}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ ! -x "$lean_home/bin/lake" ]; then
  curl -fsSL -o "$work/lean.zip" "https://github.com/leanprover/lean4/releases/download/v$LEAN_VERSION/lean-$LEAN_VERSION-linux.zip"
  echo "$LEAN_SHA256  $work/lean.zip" | sha256sum -c -
  unzip -q "$work/lean.zip" -d "$work"
  mkdir -p "$(dirname "$lean_home")"
  # A cache can restore part of an earlier install (no bin/lake): mv would then nest the new
  # toolchain inside it, off PATH. Replace it whole.
  rm -rf "$lean_home"
  mv "$work/lean-$LEAN_VERSION-linux" "$lean_home"
fi
[ -x "$lean_home/bin/lean" ] || { echo "no lean in $lean_home/bin" >&2; exit 1; }
export PATH="$lean_home/bin:$PATH" LAKE="$lean_home/bin/lake"
lean --version

# The proofs. A `sorry` (or an axiom of our own) would let a proof claim anything.
if grep -rnwE 'sorry|admit|axiom|native_decide' verification/lean/Wicket verification/lean/Wicket.lean verification/lean/Oracle.lean; then
  echo "the spec has an unproved step" >&2
  exit 1
fi
# In GitHub Actions, the lines of $1 that start an error (`<file>:<line>:<col>: error: ...` for Lean),
# each with the lines after it up to the next blank one, as annotations on the run: they show in
# the pull request without its log.
annotate() {
  [ -n "${GITHUB_ACTIONS:-}" ] || return 0
  awk -v dir="$2" '
    function esc(l) { gsub(/%/, "%25", l); return l }
    function flush() { if (msg != "") { print "::error" loc "::" msg; n++ } msg = "" }
    /error|panicked|divergen/ && n < 20 { flush(); loc = ""
      if (match($0, /^[^: ]+\.lean:[0-9]+:/)) { split(substr($0, 1, RLENGTH), p, ":"); loc = " file=" dir p[1] ",line=" p[2] }
      msg = esc($0); lines = 1; next }
    msg != "" && /^$/ { flush(); next }
    msg != "" && lines < 12 { msg = msg "%0A" esc($0); lines++ }
    END { flush() }' "$1"
}

if ! (cd verification/lean && lake build 2>&1) | tee "$work/build.log"; then
  annotate "$work/build.log" verification/lean/
  exit 1
fi
if grep -q "declaration uses 'sorry'" "$work/build.log"; then
  echo "the spec has an unproved step" >&2
  exit 1
fi

# The oracle: every fixture and generated case decided alike by wicket-core and the spec.
if ! cargo test -q --locked -p wicket-authz --test lean_oracle -- --ignored --nocapture 2>&1 | tee "$work/oracle.log"; then
  annotate "$work/oracle.log" ""
  exit 1
fi

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
if [ ! -x "$lean_home/bin/lake" ]; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  curl -fsSL -o "$work/lean.zip" "https://github.com/leanprover/lean4/releases/download/v$LEAN_VERSION/lean-$LEAN_VERSION-linux.zip"
  echo "$LEAN_SHA256  $work/lean.zip" | sha256sum -c -
  unzip -q "$work/lean.zip" -d "$work"
  mkdir -p "$(dirname "$lean_home")"
  mv "$work/lean-$LEAN_VERSION-linux" "$lean_home"
fi
export PATH="$lean_home/bin:$PATH" LAKE="$lean_home/bin/lake"
lean --version

# The proofs. A `sorry` (or an axiom of our own) would let a proof claim anything.
if grep -rnwE 'sorry|admit|axiom|native_decide' verification/lean/Wicket verification/lean/Wicket.lean verification/lean/Oracle.lean; then
  echo "the spec has an unproved step" >&2
  exit 1
fi
log=$(mktemp)
(cd verification/lean && lake build 2>&1) | tee "$log"
if grep -q "declaration uses 'sorry'" "$log"; then
  echo "the spec has an unproved step" >&2
  exit 1
fi

# The oracle: every fixture and generated case decided alike by wicket-core and the spec.
cargo test -q --locked -p wicket-authz --test lean_oracle -- --ignored --nocapture

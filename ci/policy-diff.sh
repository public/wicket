#!/usr/bin/env bash
# SymCC in CI (#51, docs/reference/policy.md): its fixtures (known narrowings and widenings), then, for each
# org policy under examples/policy/ that this change touches, whether the change narrows or widens.
# cvc5 1.3.1 (the version SymCC pins), checksum-verified; a timeout, an `unknown` or a solver error
# fails. A widening doesn't fail: it is printed, for the review to decide.
#
#   ci/policy-diff.sh [BASE]      (BASE: the commit to compare with; default origin/main)
set -euo pipefail
cd "$(dirname "$0")/.."
base=${1:-origin/main}
CVC5_SHA256=1a1cda20d2df4938fa4944a69f33ddc9172e319ece0eed0aa09c4d7abede3ed1
tools=${TOOLS_DIR:-$PWD/target/tools}
mkdir -p "$tools"
if [ ! -x "$tools/cvc5" ]; then
  curl -sSL -o "$tools/cvc5.zip" https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.1/cvc5-Linux-x86_64-static.zip
  echo "$CVC5_SHA256  $tools/cvc5.zip" | sha256sum -c -
  unzip -q -j -o "$tools/cvc5.zip" '*/bin/cvc5' -d "$tools"
  chmod +x "$tools/cvc5"
fi
export CVC5="$tools/cvc5" CVC5_REQUIRED=1
cargo build -q --locked -p wicket-policy-diff
cargo test -q --locked -p wicket-policy-diff
diff_bin=target/debug/wicket-policy-diff
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
status=0
for f in $(git diff --name-only "$base"...HEAD -- 'examples/policy/*.cedar' 2>/dev/null); do
  [ -f "$f" ] || { echo "$f: removed"; continue; }
  if ! git show "$base:$f" >"$work/old.cedar" 2>/dev/null; then
    echo "$f: new (nothing to compare with)"
    continue
  fi
  echo "== $f against $base"
  set +e
  "$diff_bin" "$work/old.cedar" "$f"
  rc=$?
  set -e
  case $rc in
    0) ;;
    1) echo "   (a widening: the review decides)" ;;
    *) echo "   FAILED: the solver gave no answer"; status=1 ;;
  esac
done
exit "$status"

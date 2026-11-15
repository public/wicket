#!/usr/bin/env bash
# Kani proof harnesses (#325): bounded model checking of wicket's pure decision functions, the
# `#[kani::proof]` functions under `crates/*/src/proofs/` (built only by `cargo kani`, `cfg(kani)`).
# Each names the Lean theorem of #322 (verification/lean) it restates, where there is one.
#
#   ci/kani.sh [--list] [HARNESS ...]
#
# Runs every harness (or those named), one `cargo kani` at a time: CBMC's memory is per harness,
# and one at a time keeps a run within a 4-6 GiB box (the largest needs about 2 GiB; see
# changes/325-kani.md). Prints each one's result and time, and fails if any harness does.
# Needs Kani (`cargo install --locked kani-verifier && cargo kani setup`); CI pins its version in
# .github/workflows/ci.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

# crate<TAB>harness, for every #[kani::proof] in a crate's src/proofs/.
harnesses() {
  for f in crates/*/src/proofs/*.rs; do
    crate=$(cut -d/ -f2 <<<"$f")
    awk -v c="$crate" '/#\[kani::proof\]/ { p = 1; next } p && /^fn / { sub(/^fn /, ""); sub(/\(.*/, ""); print c "\t" $0; p = 0 }' "$f"
  done
}

if [ "${1:-}" = --list ]; then
  harnesses
  exit 0
fi
want=("$@")
# `--harness` matches by substring, so no harness name may be part of another's.
names=$(harnesses | cut -f2)
for a in $names; do
  if [ "$(grep -c -- "$a" <<<"$names")" != 1 ]; then
    echo "harness name $a is not unique, or part of another's (ci/kani.sh selects by name)" >&2
    exit 2
  fi
done

failed=() ran=0
while IFS=$'\t' read -r crate h; do
  if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " == *" $h "* ]]; then
    continue
  fi
  ran=$((ran + 1))
  t0=$SECONDS
  if out=$(cargo kani -p "$crate" --harness "$h" --output-format terse 2>&1); then
    echo "ok   $crate $h ($((SECONDS - t0)) s)"
  else
    echo "FAIL $crate $h ($((SECONDS - t0)) s)"
    grep -E 'Failed Checks|^Check [0-9]+:|Status: FAILURE|Description:|Location:|^error' <<<"$out" | head -n 40 || tail -n 40 <<<"$out"
    failed+=("$h")
  fi
done < <(harnesses)

if [ "$ran" = 0 ]; then
  echo "no harness matched: ${want[*]}" >&2
  exit 2
fi
if [ ${#failed[@]} -gt 0 ]; then
  echo "kani: ${#failed[@]} of $ran harnesses failed: ${failed[*]}"
  exit 1
fi
echo "kani: all $ran harnesses verified"

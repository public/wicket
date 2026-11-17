#!/usr/bin/env bash
# Kani proof harnesses (#325): bounded model checking of wicket's pure decision functions, the
# `#[kani::proof]` functions under `crates/*/src/proofs/` (built only by `cargo kani`, `cfg(kani)`).
# Each names the Lean theorem of #322 (verification/lean) it restates, where there is one.
#
#   ci/kani.sh [--list] [--no-loom] [--shard I/N] [HARNESS ...]
#
# Then, unless harnesses are named or --no-loom is given, the budget counter's loom test
# (crates/wicket-core/tests/loom_budget.rs: every interleaving of its node's reports, slice leases,
# model calls and carve-outs, up to 3 preemptions per run), built with `--cfg loom` in its own
# target directory.
#
# --shard I/N runs the Ith of N parts (1-based) of what it would run, the harnesses and then loom
# taken in turn, so N CI jobs run it all at once (#460).
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
loom=1 shard=1 shards=1
while [ $# -gt 0 ]; do
  case "$1" in
    --no-loom) loom=0; shift ;;
    --shard)
      [[ "${2:-}" =~ ^([0-9]+)/([0-9]+)$ ]] && [ "${BASH_REMATCH[1]}" -ge 1 ] && [ "${BASH_REMATCH[1]}" -le "${BASH_REMATCH[2]}" ] \
        || { echo "--shard wants I/N, 1 <= I <= N" >&2; exit 2; }
      shard=${BASH_REMATCH[1]} shards=${BASH_REMATCH[2]}
      shift 2 ;;
    *) break ;;
  esac
done
want=("$@")
[ $# -gt 0 ] && loom=0
# `--harness` matches by substring, so no harness name may be part of another's.
names=$(harnesses | cut -f2)
for a in $names; do
  if [ "$(grep -c -- "$a" <<<"$names")" != 1 ]; then
    echo "harness name $a is not unique, or part of another's (ci/kani.sh selects by name)" >&2
    exit 2
  fi
done

# Whether the next item (a harness, then loom) is this shard's: they are dealt out in turn.
item=0
mine() {
  item=$((item + 1))
  [ $(((item - 1) % shards + 1)) = "$shard" ]
}
failed=() ran=0 matched=0 times=()
while IFS=$'\t' read -r crate h; do
  if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " == *" $h "* ]]; then
    continue
  fi
  matched=$((matched + 1))
  mine || continue
  ran=$((ran + 1))
  t0=$SECONDS
  if out=$(cargo kani -p "$crate" --harness "$h" --output-format terse 2>&1); then
    echo "ok   $crate $h ($((SECONDS - t0)) s)"
    times+=("$h $((SECONDS - t0)) s")
  else
    echo "FAIL $crate $h ($((SECONDS - t0)) s)"
    grep -E 'Failed Checks|^Check [0-9]+:|Status: FAILURE|Description:|Location:|^error' <<<"$out" | head -n 40 || tail -n 40 <<<"$out"
    failed+=("$h")
  fi
done < <(harnesses)

if [ "$matched" = 0 ]; then
  echo "no harness matched: ${want[*]}" >&2
  exit 2
fi
if [ "$loom" = 1 ] && mine; then
  t0=$SECONDS
  if out=$(RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=${LOOM_MAX_PREEMPTIONS:-3} CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}/loom" \
    cargo test --release --locked -p wicket-core --test loom_budget 2>&1); then
    echo "ok   loom budget counter ($((SECONDS - t0)) s): $(grep -E '^test result' <<<"$out" | tail -n 1)"
    times+=("loom $((SECONDS - t0)) s")
  else
    echo "FAIL loom budget counter ($((SECONDS - t0)) s)"
    tail -n 40 <<<"$out"
    failed+=(loom)
  fi
fi
# Each one's time, as an annotation on the run: what to rebalance the shards by.
if [ -n "${GITHUB_ACTIONS:-}" ] && [ ${#times[@]} -gt 0 ]; then
  echo "::notice title=kani shard $shard/$shards times::$(printf '%s%%0A' "${times[@]}")"
fi
if [ ${#failed[@]} -gt 0 ]; then
  echo "kani: ${#failed[@]} of $ran failed: ${failed[*]}"
  exit 1
fi
echo "kani: all $ran verified (shard $shard/$shards)"

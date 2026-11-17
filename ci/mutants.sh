#!/usr/bin/env bash
# Mutation testing of wicket's decision code (#326), with cargo-mutants: zone subsets and reach
# (wicket-core subset.rs, op.rs), path canonicalisation (canon.rs), the host and glob matchers
# (manifest.rs), the model budget (budget.rs), token loading and cost (wicket-authz) and grant
# bounds (wicket-cli grant.rs). Each mutant is a small change to the code (`>` for `>=`, a
# function returning a constant, a deleted match arm); one the tests still pass on is a test gap.
#
#   ci/mutants.sh [--jobs N] [--only <name>] [--list]
#
#   --only   one set: core, matchers, authz or grant
#   --list   print the mutants each set would test, and test none
#
# A surviving mutant fails the run unless ci/mutants.accepted lists it (equivalent mutants: ones no
# test could tell apart, each with why). The surviving list is printed, and in CI written to the
# job summary; mutants.out/ under target/mutants has the details.
#
# Needs cargo-mutants (CARGO_MUTANTS_VERSION, installed with `cargo install --locked` if missing).
# A mutant that loops and allocates (fold_case_glob's `+=` turned `*=`) is ended by --timeout; on a
# small machine it can run out of memory first, so this wants a CI runner's memory, not a 4 GiB box.
# Not per PR: about 40 minutes on 4 cores. The slowest test of each crate is skipped here
# (wicket-core's segment_proofs_agree_with_the_matcher, 26 s; wicket-authz's oracle3, the vendored
# evaluator's own differential): they run on every PR, and checking each mutant with them would
# multiply the run's length for little.
set -euo pipefail
cd "$(dirname "$0")/.."
jobs=2 only= list=false
while [ $# -gt 0 ]; do
  case "$1" in
    --jobs) jobs=$2; shift 2 ;;
    --only) only=$2; shift 2 ;;
    --list) list=true; shift ;;
    *) echo "usage: ci/mutants.sh [--jobs N] [--only NAME] [--list]" >&2; exit 2 ;;
  esac
done
version=${CARGO_MUTANTS_VERSION:-27.1.0}
if ! cargo mutants --version 2>/dev/null | grep -q " $version"; then
  cargo install --locked "cargo-mutants@$version"
fi
out=${CARGO_TARGET_DIR:-target}/mutants
mkdir -p "$out"
core_tests=(-- --lib -- --skip segment_proofs --skip compiled_zones_decide)
# name | package | cargo-mutants filters | test arguments
sets=(
  "core|wicket-core|-f crates/wicket-core/src/subset.rs -f crates/wicket-core/src/op.rs -f crates/wicket-core/src/canon.rs -f crates/wicket-core/src/budget.rs|core"
  "matchers|wicket-core|-f crates/wicket-core/src/manifest.rs -F host_matches|compile_glob|wildcard_for|allows_model|model_covers|names_host|covers_host|ReachRule::matches|check_models|fold_case_glob|core"
  "authz|wicket-authz|-f crates/wicket-authz/src/decide.rs -f crates/wicket-authz/src/token.rs -f crates/wicket-authz/src/cost.rs|authz"
  "grant|wicket-control|-f crates/wicket-control/src/grant.rs -F within_authority|check_terms|agent_terms|outlasts|descendant_chain|agent_renews|bounds|check_ttl|check_prefix|grant"
)
survived=()
for s in "${sets[@]}"; do
  name=${s%%|*}; rest=${s#*|}; pkg=${rest%%|*}; rest=${rest#*|}
  tests=${s##*|}; filters=${rest%|*}
  [ -z "$only" ] || [ "$only" = "$name" ] || continue
  case "$tests" in
    core) targs=("${core_tests[@]}") ;;
    authz) targs=(-- -- --skip oracle3) ;;
    grant) targs=(-- --lib -- grant) ;;
  esac
  # The -F regex holds `|`: split the filters on spaces only.
  read -r -a fargs <<<"$filters"
  echo "== $name ($pkg)"
  if $list; then
    cargo mutants --list -p "$pkg" "${fargs[@]}" | sed 's/^/  /'
    continue
  fi
  cargo mutants --no-shuffle --jobs "$jobs" --timeout 90 -p "$pkg" "${fargs[@]}" --output "$out/$name" "${targs[@]}" || true
  missed=$out/$name/mutants.out/missed.txt
  [ -f "$missed" ] || { echo "$name: cargo-mutants wrote no results (the baseline failed?)" >&2; exit 1; }
  while IFS= read -r m; do
    # Accepted: the mutant's line, without its line and column numbers (they move with edits).
    key=$(sed -E 's/:[0-9]+:[0-9]+:/:/' <<<"$m")
    grep -qxF "$key" <(grep -v '^#' ci/mutants.accepted | sed -E 's/ +#.*$//' | sed '/^$/d') || survived+=("$m")
  done <"$missed"
done
$list && exit 0
if [ ${#survived[@]} -eq 0 ]; then
  echo "mutants: every mutant of the decision code is caught (or accepted in ci/mutants.accepted)"
  exit 0
fi
echo "mutants: ${#survived[@]} survived (a test gap each, or an equivalent mutant for ci/mutants.accepted):"
printf '  %s\n' "${survived[@]}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo "### Surviving mutants"; printf -- '- `%s`\n' "${survived[@]}"; } >>"$GITHUB_STEP_SUMMARY"
fi
exit 1

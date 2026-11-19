#!/usr/bin/env bash
# Kani proof harnesses (#325): bounded model checking of wicket's pure decision functions, the
# `#[kani::proof]` functions under `crates/*/src/proofs/` (built only by `cargo kani`, `cfg(kani)`).
# Each names the Lean theorem of #322 (verification/lean) it restates, where there is one.
#
#   ci/kani.sh [--list] [--plan N] [--no-loom] [--shard I/N] [HARNESS ...]
#
# Then, unless harnesses are named or --no-loom is given, the budget counter's loom test
# (crates/wicket-core/tests/loom_budget.rs: every interleaving of its node's reports, slice leases,
# model calls and carve-outs, up to 3 preemptions per run), built with `--cfg loom` in its own
# target directory.
#
# --shard I/N runs the Ith of N parts (1-based) of what it would run, so N CI jobs run it all at
# once (#460). The parts are balanced by each item's time in CI (`ci_times` below): longest first,
# each to the part with the least so far. Every part computes the same split, and every item is in
# exactly one. An item missing from `ci_times` counts as 30 s.
# --plan N prints that split into N parts, each with its expected seconds, and runs nothing.
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

# Each harness's (and loom's) seconds on a CI runner, as the run's "kani shard I/N times"
# annotations print them (these from #542's run, with #540's and #541's harnesses, and #568's
# prefix harness from its own), so they can be pasted in as they are. Only the split depends on
# them: a stale or missing time can slow a part, never skip an item.
ci_times() {
  cat <<'EOF'
a_prefix_grant_covers_only_paths_under_it 158 s
a_grant_is_made_as_picked_or_as_a_push_window 93 s
a_push_is_a_post_to_a_repositorys_receive_pack 88 s
a_token_ends_with_its_grant_through_2106 82 s
check_plain_is_plain_ok 71 s
children_never_exceed_the_parent 57 s
upstream_reads_the_same_segments 52 s
a_pin_is_allowed_only_by_its_own_digest 37 s
a_wicket_host_is_refused_to_agents 33 s
pattern_overlap_is_symmetric 32 s
a_reserved_method_is_refused_to_agents 29 s
patterns_that_share_a_host_overlap 29 s
host_covers_sound 24 s
a_carve_out_keeps_the_run_within_its_budget 22 s
overlap_with_a_host_is_matching_it 21 s
a_chain_is_a_strict_ancestry 18 s
accept_from_lets_in_exactly_whom_it_names 17 s
a_principal_list_ignores_the_senders_zone 15 s
matching_ignores_case_and_trailing_dots 14 s
loom 11 s
a_slice_never_exceeds_what_is_left 10 s
a_zone_list_ignores_the_senders_principal 10 s
check_escapes_is_escapes_ok 8 s
evaluate_reach_set 8 s
a_covered_model_pattern_lets_in_nothing_more 7 s
a_descendant_is_found 7 s
wildcard_never_matches_its_apex 7 s
allow_iff 5 s
an_ipv6_address_is_public_exactly_outside_the_special_blocks 4 s
default_agent_rules_refuse_what_agent_terms_did 4 s
a_refusal_needs_a_grant_only_if_every_failure_is_escalatable 3 s
allow_lower_risk 3 s
an_ipv4_address_is_public_exactly_outside_the_special_blocks 3 s
each_agent_rule_lifts_only_its_refusal 3 s
forbid_wins 3 s
a_carried_second_is_added_exactly_or_refused 2 s
a_grant_of_k_uses_is_accepted_k_times 2 s
a_renewed_slice_is_the_next_or_no_more_than_it 2 s
a_spawn_ceiling_admits_what_is_within_it_and_tighter_admits_less 2 s
a_use_never_takes_a_grant_below_zero 2 s
an_approval_widens_unless_it_is_one_use_for_an_hour_for_the_run 2 s
merging_spent_only_raises_the_counts 2 s
negotiation_is_symmetric_and_a_jump_is_what_cant_talk 2 s
peers_talk_within_the_skew_at_the_lower_version 2 s
the_schema_floor_only_rises 2 s
a_feature_is_used_only_if_both_peers_have_it 1 s
a_token_allows_a_reading_before_the_epoch 1 s
an_agents_grant_ends_within_its_authority 1 s
an_org_policy_check_is_never_escalatable 1 s
money_is_accepted_exactly_within_the_limits 1 s
EOF
}
default_time=30

# item<TAB>part<TAB>seconds for the items on stdin (one name a line, in order), split into $1 parts
# by ci/shard.awk.
plan() { awk -v n="$1" -v dflt="$default_time" -f ci/shard.awk <(ci_times) -; }

if [ "${1:-}" = --list ]; then
  harnesses
  exit 0
fi
if [ "${1:-}" = --plan ]; then
  [[ "${2:-}" =~ ^[1-9][0-9]*$ ]] || { echo "--plan wants a number of parts" >&2; exit 2; }
  { harnesses | cut -f2; echo loom; } | awk -v n="$2" -v dflt="$default_time" -v summary=1 -f ci/shard.awk <(ci_times) -
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

# What this run would run (the named harnesses, or all and loom), then this shard's part of it.
selected=()
while IFS=$'\t' read -r crate h; do
  if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " == *" $h "* ]]; then
    continue
  fi
  selected+=("$crate"$'\t'"$h")
done < <(harnesses)
matched=${#selected[@]}
if [ "$matched" = 0 ]; then
  echo "no harness matched: ${want[*]}" >&2
  exit 2
fi
items=("${selected[@]#*$'\t'}")
[ "$loom" = 1 ] && items+=(loom)
declare -A part=()
while IFS=$'\t' read -r name p _; do
  part[$name]=$p
done < <(printf '%s\n' "${items[@]}" | plan "$shards")
mine() { [ "${part[$1]}" = "$shard" ]; }
failed=() ran=0 times=()
for sel in "${selected[@]}"; do
  IFS=$'\t' read -r crate h <<<"$sel"
  mine "$h" || continue
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
done

if [ "$loom" = 1 ] && mine loom; then
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

#!/usr/bin/env bash
# The gates a change must pass, in one place (#218). With --affected, only what the change can affect
# (ci/determinator: the crates guppy's determinator marks and their reverse dependencies, and the
# suites ci/determinator/suites.toml maps them and its paths to); without it, everything.
#
#   ci/gates.sh [--affected] [--base REF] [--no-e2e] [--only-e2e] [--suites "smoke hibernate"]
#
#   --affected     select from the change: committed since the merge base with REF, plus uncommitted
#                  and untracked files (so it can run before a commit)
#   --base REF     what to compare with (default origin/main)
#   --no-e2e       format, lint, tests and doc checks only
#   --only-e2e     the end-to-end suites only (a build of wicket-cli first)
#   --suites "…"   these suites instead of the selected ones
#
# Always: ci/preflight.sh (rustfmt, ci/check-public.py, the term, link, plugin and changelog checks,
# the lockfiles, gitleaks when installed, clippy of the selected crates). Rust: the tests of the
# selected crates, with cargo-nextest when it is installed (a retried test that then passed is
# reported as flaky, never hidden), else cargo test. End-to-end suites run against
# target/debug/wicket; they need what each script says (Docker with runsc, the agent image, sudo).
# Selected fuzz targets run for $GATES_FUZZ_SECS (default 30) each, after the suites (ci/fuzz.sh;
# in a 4 GiB box, set CARGO_BUILD_JOBS=1).
# Pass WICKET_DOCKER, IMAGE and the like through the environment as for the scripts themselves.
#
# Sessions on the shared build host give it their slot command, so only the heavy steps take a slot
# (a docs-only change then never waits for one):
#   GATES_SLOT="boxslot run --name <session> --mem 4500M -- timeout 3600" ci/gates.sh --affected
set -Eeuo pipefail
cd "$(dirname "$0")/.."

affected=0 base=origin/main e2e=1 rust=1 only_suites=
while [ $# -gt 0 ]; do
  case "$1" in
    --affected) affected=1 ;;
    --base) base=$2; shift ;;
    --no-e2e) e2e=0 ;;
    --only-e2e) rust=0 ;;
    --suites) only_suites=$2; shift ;;
    -h | --help) sed -n '2,/^set -E/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '\n== %s %s\n' "$(date +%H:%M:%S)" "$*"; }
ran=() failed=()
step() {
  local name=$1; shift
  log "$name"
  local t0=$SECONDS
  if "$@"; then ran+=("ok   $name ($((SECONDS - t0)) s)"); else ran+=("FAIL $name ($((SECONDS - t0)) s)"); failed+=("$name"); fi
}
# A heavy step (a cargo build or test, an end-to-end suite): through $GATES_SLOT when it is set, so
# the light checks don't wait for a slot. On the shared development host:
#   GATES_SLOT="boxslot run --name <session> --mem 4500M -- timeout 3600" ci/gates.sh --affected
# Without it, every step runs directly (wrap the whole script as before).
read -r -a slot <<<"${GATES_SLOT:-}"
hstep() { local name=$1; shift; step "$name" "${slot[@]}" "$@"; }

# Without --affected: every crate (nextest's filterset all()), every suite, every fuzz target.
crates=all args=--workspace filter='all()' doc_args=--workspace suites=all
if [ "$affected" = 1 ] && ! sel=$(cargo run -q --locked --manifest-path ci/determinator/Cargo.toml -- --base "$base" --worktree); then
  log "the selection failed (ci/determinator): everything"
elif [ "$affected" = 1 ]; then
  echo "$sel"
  val() { sed -n "s/^$1=//p" <<<"$sel"; }
  crates=$(val crates) args=$(val args) filter=$(val filter) doc_args=$(val doc_args) suites=$(val suites)
fi
[ -n "$only_suites" ] && suites=$only_suites
has() { [ "$suites" = all ] || [[ " $suites " == *" $1 "* ]]; }
read -r -a pkgs <<<"$args"
read -r -a doc_pkgs <<<"$doc_args"

# ---- always ----
# ci/preflight.sh: rustfmt, the public, terms, link and plugin checks, the changelog fragment, the
# lockfiles, gitleaks when installed, and clippy over the selected crates. Its heavy steps go through
# $GATES_SLOT too.
if [ "$rust" = 1 ]; then
  step "preflight (ci/preflight.sh)" ci/preflight.sh --base "$base" --packages "$args"
fi

# ---- Rust ----
if [ "$rust" = 1 ] && [ ${#pkgs[@]} -gt 0 ]; then
  if cargo nextest --version >/dev/null 2>&1; then
    hstep "tests ($filter, nextest)" cargo nextest run "${pkgs[@]}" -E "$filter" --locked --profile ci
    # nextest doesn't run doctests. They run over the tests' own crates (ci/determinator), so cargo
    # resolves the same features and reuses what the tests built; none when none has a doctest.
    if [ ${#doc_pkgs[@]} -gt 0 ]; then hstep "doctests (${crates})" cargo test "${doc_pkgs[@]}" --locked --doc; fi
  else
    hstep "tests (${crates})" cargo test "${pkgs[@]}" --locked
  fi
fi

# ---- the cheap checks of a few files (#219), as CI runs them when those change ----
if has deny; then
  if command -v cargo-deny >/dev/null; then
    hstep "cargo deny" cargo deny --locked check
  else
    log "cargo deny: skipped, cargo-deny is not installed (cargo install --locked cargo-deny); CI runs it"
  fi
fi
if has dep-age; then
  hstep "dependency cooldown (7 days)" python3 -I ci/dep-age.py --base "$base"
fi

# ---- end to end ----
export WICKET=${WICKET:-target/debug/wicket}
if has policy && [ "$rust" = 1 ]; then
  hstep "SymCC policy diffs" ci/policy-diff.sh "$base"
fi
if has lean && [ "$rust" = 1 ]; then
  hstep "Lean spec and oracle" ci/lean.sh
fi
if has kani && [ "$rust" = 1 ]; then
  if command -v cargo-kani >/dev/null; then
    hstep "Kani harnesses and the loom test" ci/kani.sh
  else
    log "kani: skipped, Kani is not installed (cargo install --locked kani-verifier && cargo kani setup); CI runs it"
  fi
fi
if has tla; then
  hstep "TLA+ models (TLC)" ci/tla.sh
fi
if [ "$e2e" = 1 ]; then
  e2e_suites=()
  for s in smoke hibernate restore services acceptance daemon-uids install-test node-e2e acceptance-nodes update; do
    has "$s" && e2e_suites+=("$s")
  done
  if [ ${#e2e_suites[@]} -gt 0 ]; then
    hstep "build wicket-cli" cargo build -p wicket-cli --locked
    for s in "${e2e_suites[@]}"; do
      case "$s" in
        smoke) hstep smoke ci/smoke.sh; hstep "attack matrix" ci/attack-matrix.sh ;;
        hibernate) hstep "hibernate" ci/hibernate.sh; hstep "hibernate --node" ci/hibernate.sh --node ;;
        restore) hstep restore ci/restore.sh ;;
        services) hstep "per-node services" ci/service-e2e.sh ;;
        # acceptance --nodes local includes the local flows.
        acceptance) has acceptance-nodes || hstep acceptance ci/acceptance.sh ;;
        acceptance-nodes) hstep "acceptance --nodes local" ci/acceptance.sh --nodes local ;;
        daemon-uids) hstep "wicketd with second uids" ci/daemon-uids.sh "$WICKET" ;;
        install-test) hstep "install script in a container" ci/install-test.sh "$WICKET" ubuntu:24.04 ;;
        node-e2e) hstep "node e2e" ci/node-e2e.sh --local ;;
        update) hstep "self update" ci/update.sh ;;
      esac
    done
  fi
fi

# ---- fuzz targets (#323): a short run of each one selected (ci/fuzz.sh) ----
if [ "$e2e" = 1 ]; then
  fuzz=()
  if [ "$suites" != all ]; then
    for s in $suites; do [[ $s == fuzz-* ]] && fuzz+=("${s#fuzz-}"); done
  fi
  # Every suite: ci/fuzz.sh's default, every target.
  if [ "$suites" = all ] || [ ${#fuzz[@]} -gt 0 ]; then
    hstep "fuzz (${fuzz[*]:-every target}, ${GATES_FUZZ_SECS:-30} s each)" ci/fuzz.sh --secs "${GATES_FUZZ_SECS:-30}" "${fuzz[@]}"
  fi
fi

log "summary (crates: $crates; suites: $suites)"
printf '%s\n' "${ran[@]}"
[ ${#failed[@]} -eq 0 ] || { echo "failed: ${failed[*]}"; exit 1; }

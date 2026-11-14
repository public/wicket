#!/usr/bin/env bash
# The gates a change must pass, in one place (#218). With --affected, only what the change can affect
# (ci/affected.py: its crates and their reverse dependencies, and the end-to-end suites
# ci/affected.map maps its paths to); without it, everything.
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
# Always: rustfmt, ci/check-public.py and the Markdown link check. Rust: clippy and the tests of the
# selected crates, with cargo-nextest when it is installed (a retried test that then passed is
# reported as flaky, never hidden), else cargo test. End-to-end suites run against
# target/debug/wicket; they need what each script says (Docker with runsc, the agent image, sudo).
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

if [ "$affected" = 1 ]; then
  sel=$(python3 ci/affected.py --base "$base" --worktree)
  echo "$sel"
  crates=$(sed -n 's/^crates: //p' <<<"$sel")
  doc_crates=$(sed -n 's/^doc crates: //p' <<<"$sel")
  suites=$(sed -n 's/^suites: //p' <<<"$sel")
else
  crates=all suites=all doc_crates=all
fi
[ -n "$only_suites" ] && suites=$only_suites
all_suites="docs policy smoke hibernate restore acceptance daemon-uids install-test node-e2e acceptance-nodes update"
[ "$suites" = all ] && suites=$all_suites
has() { [[ " $suites " == *" $1 "* ]]; }

pkgs=() doc_pkgs=()
if [ "$crates" = all ]; then
  pkgs=(--workspace) doc_pkgs=(--workspace)
else
  for c in $crates; do pkgs+=(-p "$c"); done
  for c in $doc_crates; do doc_pkgs+=(-p "$c"); done
fi

# ---- always ----
if [ "$rust" = 1 ]; then
  step "rustfmt" cargo fmt --all -- --check
  step "no secrets or machine details" python3 ci/check-public.py
  step "Markdown links" ci/check-doc-links.sh
fi

# ---- Rust ----
if [ "$rust" = 1 ] && [ ${#pkgs[@]} -gt 0 ]; then
  hstep "clippy (${crates})" cargo clippy "${pkgs[@]}" --all-targets --locked -- -D warnings
  if cargo nextest --version >/dev/null 2>&1; then
    hstep "tests (${crates}, nextest)" cargo nextest run "${pkgs[@]}" --locked --profile ci
    # nextest doesn't run doctests. They run over the tests' own crates (ci/affected.py), so cargo
    # resolves the same features and reuses what the tests built.
    if [ ${#doc_pkgs[@]} -gt 0 ]; then hstep "doctests (${doc_crates})" cargo test "${doc_pkgs[@]}" --locked --doc; fi
  else
    hstep "tests (${crates})" cargo test "${pkgs[@]}" --locked
  fi
fi

# ---- end to end ----
export WICKET=${WICKET:-target/debug/wicket}
if has policy && [ "$rust" = 1 ]; then
  hstep "SymCC policy diffs" ci/policy-diff.sh "$base"
fi
if [ "$e2e" = 1 ]; then
  e2e_suites=()
  for s in smoke hibernate restore acceptance daemon-uids install-test node-e2e acceptance-nodes update; do
    has "$s" && e2e_suites+=("$s")
  done
  if [ ${#e2e_suites[@]} -gt 0 ]; then
    hstep "build wicket-cli" cargo build -p wicket-cli --locked
    for s in "${e2e_suites[@]}"; do
      case "$s" in
        smoke) hstep smoke ci/smoke.sh ;;
        hibernate) hstep "hibernate" ci/hibernate.sh; hstep "hibernate --node" ci/hibernate.sh --node ;;
        restore) hstep restore ci/restore.sh ;;
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

log "summary (crates: $crates; suites: $suites)"
printf '%s\n' "${ran[@]}"
[ ${#failed[@]} -eq 0 ] || { echo "failed: ${failed[*]}"; exit 1; }

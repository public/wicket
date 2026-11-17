#!/usr/bin/env bash
# The cheap checks CI runs that a box can run before it pushes, so a pull request doesn't fail in CI
# on something a push could have caught: a lockfile, an address or a token in a test vector, a lint.
#
#   ci/preflight.sh [--full] [--base REF] [--all]
#
#   --full         also the tests of the affected crates (cargo-nextest when installed, else cargo test)
#   --base REF     what to compare with (default origin/main): the merge base of REF and HEAD
#   --all          clippy (and with --full, the tests) over the whole workspace, without a selection
#   --packages "…" clippy over these cargo package arguments, as ci/determinator prints them in
#                  args= (ci/gates.sh passes its own selection, so it isn't computed twice; empty
#                  for none)
#
# In order: rustfmt; ci/check-public.py over tracked and untracked files; ci/check-terms.sh;
# ci/check-doc-links.sh; ci/check-plugin.py; ci/changelog.py check against REF; both lockfiles
# (cargo metadata --locked for the workspace and for fuzz/, which has its own); gitleaks over the
# commits since the merge base, when gitleaks is on PATH (skipped with a note if not; CI runs it over
# every commit); then clippy -D warnings over the crates ci/determinator says the change affects,
# committed, uncommitted and untracked (the workspace if the selection fails).
#
# Every check runs; it ends with a summary and exits 1 if any failed. GATES_SLOT, as for
# ci/gates.sh, is a command to run the heavy steps (clippy, tests) through.
set -Euo pipefail
cd "$(dirname "$0")/.."

base=origin/main full=0 all=0 given= given_set=0
while [ $# -gt 0 ]; do
  case "$1" in
    --full) full=1 ;;
    --base) base=$2; shift ;;
    --all) all=1 ;;
    --packages) given=$2 given_set=1; shift ;;
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
skip() { log "$1: skipped, $2"; ran+=("skip $1: $2"); }
read -r -a slot <<<"${GATES_SLOT:-}"
hstep() { local name=$1; shift; step "$name" "${slot[@]}" "$@"; }

# Tracked files and untracked ones git doesn't ignore, so a new file is checked before its commit.
public_files() {
  local files
  mapfile -d '' files < <(git ls-files -z --cached --others --exclude-standard)
  python3 -I ci/check-public.py "${files[@]}"
}
lockfiles() {
  cargo metadata --locked --format-version 1 >/dev/null &&
    cargo metadata --locked --format-version 1 --manifest-path fuzz/Cargo.toml >/dev/null
}
gitleaks_new() { gitleaks git --redact --no-banner --log-opts="$1..HEAD" --config .gitleaks.toml .; }

step "rustfmt" cargo fmt --all -- --check
step "no secrets or machine details (check-public)" public_files
step "terms" ci/check-terms.sh
step "Markdown links" ci/check-doc-links.sh
step "plugin and skills" python3 -I ci/check-plugin.py
step "changelog fragment (against $base)" python3 -I ci/changelog.py check --base "$base"
step "lockfiles (workspace and fuzz/)" lockfiles

if ! mb=$(git merge-base "$base" HEAD 2>/dev/null); then
  skip gitleaks "no merge base with $base"
elif [ "$mb" = "$(git rev-parse HEAD)" ]; then
  skip gitleaks "no commits since $base"
elif ! command -v gitleaks >/dev/null; then
  skip gitleaks "gitleaks is not on PATH (CI runs it over every commit; see .github/workflows/ci.yml)"
else
  step "gitleaks ($(git rev-list --count "$mb..HEAD") new commits)" gitleaks_new "$mb"
fi

# The crates the change affects (ci/determinator), unless they were given.
crates=all args=--workspace filter='all()'
if [ "$given_set" = 1 ]; then
  crates=$given args=$given filter=
elif [ "$all" = 0 ]; then
  if sel=$(cargo run -q --locked --manifest-path ci/determinator/Cargo.toml -- --base "$base" --worktree 2>/dev/null); then
    val() { sed -n "s/^$1=//p" <<<"$sel"; }
    crates=$(val crates) args=$(val args) filter=$(val filter)
  else
    log "the selection failed (ci/determinator): the workspace"
  fi
fi
read -r -a pkgs <<<"$args"
if [ ${#pkgs[@]} -eq 0 ]; then
  skip clippy "the change affects no crate"
else
  hstep "clippy (${crates})" cargo clippy "${pkgs[@]}" --all-targets --locked -- -D warnings
  if [ "$full" = 1 ]; then
    if cargo nextest --version >/dev/null 2>&1; then
      hstep "tests (${filter:-$crates}, nextest)" cargo nextest run "${pkgs[@]}" ${filter:+-E "$filter"} --locked --profile ci
    else
      hstep "tests (${crates})" cargo test "${pkgs[@]}" --locked
    fi
  fi
fi

log "preflight summary (against $base)"
printf '%s\n' "${ran[@]}"
[ ${#failed[@]} -eq 0 ] || { echo "preflight failed: ${failed[*]}"; exit 1; }
echo "preflight passed"

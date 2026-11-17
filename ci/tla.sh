#!/usr/bin/env bash
# TLC on the TLA+ models under verification/tla/ (#321), at the small bounds their .cfg files state.
# A Temurin 21 JRE and tla2tools.jar, both pinned by URL and sha256 and checked. Every `pass_*.cfg`
# (and each model's own .cfg) must pass; every `fail_*.cfg` must be refused with the invariant this
# script names for it, so a variant that stops failing (the model stopped seeing the bug) fails too.
#
#   ci/tla.sh [--traces] [CFG...]     (default: every .cfg under verification/tla/)
#
# A model that should pass and doesn't prints TLC's counterexample (the states up to the violation).
# --traces prints each fail_* variant's counterexample too: the trace to file with a finding.
#
# TOOLS_DIR (default target/tools) keeps the downloads; TLA_HEAP (default 1g) is TLC's heap.
set -euo pipefail
cd "$(dirname "$0")/.."

traces=0 args=()
for a in "$@"; do
  case "$a" in
    --traces) traces=1 ;;
    -h | --help) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $a (see --help)" >&2; exit 2 ;;
    *) args+=("$a") ;;
  esac
done

# TLC's counterexample in a log: from its first `Error:` line to the statistics after the trace,
# without progress lines. Empty when TLC printed none (a parse error, say).
trace() {
  awk '/^Error:/ { on = 1 } on && /states generated|^Finished in|^The depth of the complete state graph/ { exit }
       on && !/^Progress\(/ { print }' "$1"
}

JRE_URL=https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz
JRE_SHA256=a535a1df9c6284d9618872984e026ae0352d1f7e9e0605425c0e6114f47351dd
TLA_URL=https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
# The release publishes sha1 bee4a54f3ee3d4afc347c3240ec2d9e93b075104; this is the same file's sha256.
TLA_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88

tools=${TOOLS_DIR:-$PWD/target/tools}
mkdir -p "$tools"
if [ ! -x "$tools/jre21/bin/java" ]; then
  curl -sSfL -o "$tools/jre21.tar.gz" "$JRE_URL"
  echo "$JRE_SHA256  $tools/jre21.tar.gz" | sha256sum -c -
  rm -rf "$tools/jre21" && mkdir -p "$tools/jre21"
  tar -xzf "$tools/jre21.tar.gz" -C "$tools/jre21" --strip-components=1
  rm "$tools/jre21.tar.gz"
fi
if ! echo "$TLA_SHA256  $tools/tla2tools.jar" | sha256sum -c - >/dev/null 2>&1; then
  curl -sSfL -o "$tools/tla2tools.jar" "$TLA_URL"
  echo "$TLA_SHA256  $tools/tla2tools.jar" | sha256sum -c -
fi
java=$tools/jre21/bin/java

# What each failing variant must be refused with (an extended regex of TLC's invariant names).
expect_fail() {
  case "$1" in
    fail_token_boundary | fail_node_skew) echo 'NoAllowPastLifetime' ;;
    fail_no_journal | fail_merged_counters | fail_slice_unreserved | fail_edge_carve | fail_no_first_slice) echo 'SpendWithinBudget' ;;
    fail_today) echo 'NoAllowPastLifetime|SpendWithinBudget' ;;
    # #369's model (ApprovalEffect.tla): each switch off breaks the invariant it protects.
    fail_effect_no_hold) echo 'HoldUntilDecided' ;;
    fail_effect_replay) echo 'ExactlyOnceOnReplay' ;;
    fail_effect_check_at_decision) echo 'NoActionAfterExpiry' ;;
    fail_effect_relay_as_self) echo 'IdentityKeptAcrossHops' ;;
    fail_effect_unbound_args) echo 'ArgumentsBound' ;;
    # #321's run lifecycle (RunLifecycle.tla): today's code, one switch at a time.
    fail_lifecycle_finish_lost) echo 'FinishKnown' ;;
    fail_lifecycle_message_lost) echo 'NoMessageLost' ;;
    fail_lifecycle_twin_wake) echo 'OneHarness' ;;
    fail_lifecycle_today) echo 'NoMessageLost|OneHarness' ;;
    # #321's placement (Placement.tla): the bugs its switches fixed.
    fail_placement_no_start_by) echo 'NoStartPastLease' ;;
    fail_placement_no_admission) echo 'NoOvercommit' ;;
    fail_placement_release_running) echo 'NoReleaseWithWork' ;;
    *) echo "" ;;
  esac
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ ${#args[@]} -gt 0 ]; then cfgs=("${args[@]}"); else mapfile -t cfgs < <(ls verification/tla/*.cfg); fi
status=0
for cfg in "${cfgs[@]}"; do
  dir=$(dirname "$cfg") name=$(basename "$cfg" .cfg)
  # A model's own .cfg is named after it; a variant names its model on a `\* model: <Name>` line
  # (needed where a directory holds more than one model; with one, it checks that one).
  model=$(sed -n 's/^\\\* model: *\([A-Za-z0-9_]*\) *$/\1/p' "$cfg" | head -n 1)
  if [ -f "$dir/$name.tla" ]; then
    spec=$dir/$name.tla
  elif [ -n "$model" ] && [ -f "$dir/$model.tla" ]; then
    spec=$dir/$model.tla
  elif [ "$(ls "$dir"/*.tla | wc -l)" -eq 1 ]; then
    spec=$(ls "$dir"/*.tla)
  else
    echo "FAIL  $name: names no model (a \`\\* model: <Name>\` line) and $dir holds several"
    status=1
    continue
  fi
  log=$work/$name.log
  start=$(date +%s)
  set +e
  (cd "$dir" && "$java" -Xmx"${TLA_HEAP:-1g}" -XX:+UseParallelGC -Djava.io.tmpdir="$work" -cp "$tools/tla2tools.jar" \
    tlc2.TLC -workers auto -deadlock -cleanup -metadir "$work/states-$name" -config "$name.cfg" "$(basename "$spec")") >"$log" 2>&1
  rc=$?
  set -e
  took=$(( $(date +%s) - start ))
  states=$(grep -Eo '^[0-9]+ states generated, [0-9]+ distinct states found' "$log" | tail -n 1 || true)
  want=$(expect_fail "$name")
  if [ -z "$want" ]; then
    if [ $rc -eq 0 ] && grep -q 'Model checking completed. No error has been found.' "$log"; then
      echo "ok    $name ($states; ${took}s)"
    else
      echo "FAIL  $name: TLC found an error (exit $rc):"
      if [ -n "$(trace "$log")" ]; then
        trace "$log" | sed 's/^/    /'
      else
        sed 's/^/    /' "$log" | tail -n 120
      fi
      status=1
    fi
  elif grep -Eq "Invariant ($want) is violated" "$log"; then
    echo "ok    $name refused: $(grep -Eo "Invariant ($want) is violated" "$log" | head -n 1) (${took}s)"
    if [ $traces -eq 1 ]; then
      trace "$log" | sed 's/^/    /'
    fi
  else
    echo "FAIL  $name: expected TLC to refuse it with $want (exit $rc):"
    sed 's/^/    /' "$log" | tail -n 60
    status=1
  fi
done
exit $status

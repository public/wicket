#!/usr/bin/env bash
# The CI verdict (ci.yml's `verdict` job) waits for every other job in ci.yml (#219): a job added
# without being in its `needs` would never count. Fails, naming each, when one is missing or extra.
#   ci/verdict-needs.sh [path/to/ci.yml]
set -euo pipefail
wf=${1:-$(dirname "$0")/../.github/workflows/ci.yml}
jobs=$(awk '/^jobs:/ { f = 1; next } f && /^[^ #]/ { f = 0 } f && /^  [a-z][a-z0-9_-]*:[[:space:]]*$/ { sub(":", "", $1); print $1 }' "$wf" | grep -vx verdict | sort)
needs=$(awk '/^  verdict:/ { f = 1; next } f && /^  [a-z]/ { f = 0 } f && /^    needs:/ { sub(/^    needs:[[:space:]]*\[/, ""); sub(/\][[:space:]]*$/, ""); gsub(/[[:space:]]/, ""); print }' "$wf" | tr ',' '\n' | grep -v '^$' | sort)
[ -n "$needs" ] || { echo "$wf: no verdict job with a needs list" >&2; exit 1; }
missing=$(comm -23 <(echo "$jobs") <(echo "$needs"))
extra=$(comm -13 <(echo "$jobs") <(echo "$needs"))
[ -z "$missing" ] || echo "the verdict doesn't wait for: $(echo $missing)" >&2
[ -z "$extra" ] || echo "the verdict waits for jobs that don't exist: $(echo $extra)" >&2
[ -z "$missing$extra" ] || exit 1
echo "the verdict waits for all $(echo "$jobs" | wc -l) jobs"

#!/usr/bin/env bash
# The CI verdict (ci.yml's `verdict` job) waits for every other job in ci.yml (#219): a job added
# without being in its `needs` would never count. Fails, naming each, when one is missing or extra.
#   ci/verdict-needs.sh [path/to/ci.yml]
# Reads the YAML with python3's yaml module where it is installed (GitHub's runners have it), else
# with awk: job ids are the 2-space keys under `jobs:`, and the verdict's `needs` a one-line list.
set -euo pipefail
wf=${1:-$(dirname "$0")/../.github/workflows/ci.yml}
if python3 -c 'import yaml' 2>/dev/null; then
  lists=$(python3 -I - "$wf" <<'PY'
import sys, yaml
jobs = yaml.safe_load(open(sys.argv[1]))["jobs"]
needs = jobs.get("verdict", {}).get("needs", [])
needs = [needs] if isinstance(needs, str) else needs
print(" ".join(sorted(j for j in jobs if j != "verdict")))
print(" ".join(sorted(needs)))
PY
)
  jobs=$(sed -n 1p <<<"$lists" | tr ' ' '\n' | grep -v '^$' | sort)
  needs=$(sed -n 2p <<<"$lists" | tr ' ' '\n' | grep -v '^$' | sort)
else
  jobs=$(awk '/^jobs:/ { f = 1; next } f && /^[^ #]/ { f = 0 }
    f && /^  [A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*(#.*)?$/ { sub(/^  /, ""); sub(/:.*/, ""); print }' "$wf" | grep -vx verdict | sort)
  needs=$(awk '/^  verdict:/ { f = 1; next } f && /^  [A-Za-z_]/ { f = 0 }
    f && /^    needs:/ { sub(/^    needs:[[:space:]]*\[/, ""); sub(/\][[:space:]]*(#.*)?$/, ""); gsub(/[[:space:]]/, ""); print }' "$wf" |
    tr ',' '\n' | grep -v '^$' | sort)
fi
[ -n "$needs" ] || { echo "$wf: no verdict job with a needs list" >&2; exit 1; }
missing=$(comm -23 <(echo "$jobs") <(echo "$needs"))
extra=$(comm -13 <(echo "$jobs") <(echo "$needs"))
[ -z "$missing" ] || echo "the verdict doesn't wait for: $(echo $missing)" >&2
[ -z "$extra" ] || echo "the verdict waits for jobs that don't exist: $(echo $extra)" >&2
[ -z "$missing$extra" ] || exit 1
echo "the verdict waits for all $(echo "$jobs" | wc -l) jobs"

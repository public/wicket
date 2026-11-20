#!/usr/bin/env bash
# What each candidate costs to ship and to build: sizes, packages, build time, reproducibility.
#
#   ./static.sh [candidate...]      (default: baseline and every directory with a package.json)
#
# For each: gzip -9 of what the browser loads (the baseline: console.js and console.css; a prototype:
# dist/app.js and dist/app.css); the packages in package-lock.json, all and runtime only (not "dev");
# node_modules' size; the wall time of `npm ci && npm run build` from clean; whether a second clean
# build gives the same bytes; and the lines of the prototype's own source (src/, without helpers.*).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$here"
names=("$@")
if [ ${#names[@]} -eq 0 ]; then names=(baseline); for d in */package.json; do names+=("${d%/package.json}"); done; fi
gz() { gzip -9 -c "$1" | wc -c; }
echo "| candidate | JS gzip (B) | CSS gzip (B) | lockfile packages (runtime) | installed here | node_modules | clean build (s) | same bytes on rebuild | own lines |"
echo "|---|---|---|---|---|---|---|---|---|"
for n in "${names[@]}"; do
  if [ "$n" = baseline ]; then
    s=../../crates/wicket-cli/src/serve/static
    echo "| baseline (whole console, unminified) | $(gz $s/console.js) | $(gz $s/console.css) | 0 (0) | 0 | 0 | 0 (none) | yes (no build) | $(wc -l < $s/console.js) |"
    continue
  fi
  (
    cd "$n"
    rm -rf node_modules dist
    t0=$(date +%s.%N); npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; npm run build >/dev/null 2>&1; t1=$(date +%s.%N)
    h1=$(cat dist/app.js dist/app.css | sha256sum)
    rm -rf node_modules dist; npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; npm run build >/dev/null 2>&1
    h2=$(cat dist/app.js dist/app.css | sha256sum)
    pk=$(node -e 'const l=require("./package-lock.json");const p=Object.entries(l.packages).filter(([k])=>k);console.log(p.length+" ("+p.filter(([,v])=>!v.dev).length+")")')
    nm=$( [ -d node_modules ] && du -sh node_modules | cut -f1 || echo 0)
    # Installed on this machine: the lockfile also lists every other platform's optional binaries.
    inst=$( [ -d node_modules ] && npm ls --all --parseable 2>/dev/null | tail -n +2 | wc -l || echo 0)
    loc=$(find src -type f ! -name 'helpers.*' ! -name 'shared.*' \( -name '*.js' -o -name '*.ts' -o -name '*.jsx' -o -name '*.tsx' -o -name '*.vue' -o -name '*.svelte' \) -print0 | xargs -0 cat | grep -cv '^\s*$' || true)
    echo "| $n | $(gz dist/app.js) | $(gz dist/app.css) | $pk | $inst | $nm | $(printf '%.1f' "$(echo "$t1 - $t0" | bc)") | $([ "$h1" = "$h2" ] && echo yes || echo NO) | $loc |"
  )
done

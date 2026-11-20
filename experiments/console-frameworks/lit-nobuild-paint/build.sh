#!/usr/bin/env bash
# No build: dist/ is the files as they are, the way the console is served today. Only copied into
# dist/ because serve.mjs serves every candidate from there. vendor/lit-html/ is lit-html 3.3.3's own
# published, minified modules (BSD-3-Clause, see its LICENSE), unchanged.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf dist && mkdir dist
cp -r index.html src vendor dist/
cp ../shared/console.css dist/app.css

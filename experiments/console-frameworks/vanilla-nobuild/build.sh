#!/usr/bin/env bash
# No build: dist/ is the files as they are, the way the console is served today. Only copied into
# dist/ because serve.mjs serves every candidate from there.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf dist && mkdir dist
cp -r index.html src dist/
cp ../shared/console.css dist/app.css

#!/bin/sh
# The npm cache's start: Verdaccio from ./package-lock.json, then serving with ./config.yaml.
# Run as `node <its bin script>`, never through node_modules/.bin: the box's /tmp may be mounted
# noexec, and nothing here relies on a file's exec bit.
set -eu
prefix=/tmp/verdaccio
mkdir -p "$prefix"
cp /workspace/package.json /workspace/package-lock.json "$prefix/"
cd "$prefix"
npm ci --ignore-scripts --no-audit --no-fund
bin=$(node -p "const p = require('./node_modules/verdaccio/package.json'); require('path').join('node_modules/verdaccio', typeof p.bin === 'string' ? p.bin : p.bin.verdaccio)")
exec node "$bin" --config /workspace/config.yaml --listen 0.0.0.0:4873

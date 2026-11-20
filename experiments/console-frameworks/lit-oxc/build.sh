#!/usr/bin/env bash
# lit-nobuild-paint's files, with app.js and helpers.js minified by Oxc from Rust (../oxc-minify), as
# the console's build.rs would: no Node, no npm. lit-html's own files are already minified.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf dist && mkdir dist
cp -r index.html src vendor dist/
cp ../shared/console.css dist/app.css
(cd ../oxc-minify && cargo build -q --release)
../oxc-minify/target/release/oxc-minify dist/src/app.js dist/src/helpers.js

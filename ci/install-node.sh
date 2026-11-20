#!/usr/bin/env bash
# A pinned Node.js for building the console's session view (#327, ci/session-view.sh): nodejs.org's
# linux-x64 tarball, checked against NODE_SHA256, unpacked under RUNNER_TEMP (or /tmp) and put first
# on PATH (GITHUB_PATH in Actions). NODE_SHA256 is required (#722): the SHASUMS256.txt next to the
# tarball has the value, to compare when updating, never to fetch at run time.
#
#   NODE_VERSION=26.13.1 NODE_SHA256=<hex> ci/install-node.sh
set -euo pipefail
v=${NODE_VERSION:?NODE_VERSION}
[ -n "${NODE_SHA256:-}" ] || { echo "::error::NODE_SHA256 is not set: pin node-v$v-linux-x64.tar.xz's sha256" >&2; exit 1; }
dir=${RUNNER_TEMP:-/tmp}/node-v$v
f=node-v$v-linux-x64.tar.xz
mkdir -p "$dir"
curl -sSfL -o "$dir/$f" "https://nodejs.org/dist/v$v/$f"
echo "$NODE_SHA256  $dir/$f" | sha256sum -c -
tar -xJf "$dir/$f" -C "$dir" --strip-components=1
rm -f "$dir/$f"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$dir/bin" >>"$GITHUB_PATH"
fi
"$dir/bin/node" --version

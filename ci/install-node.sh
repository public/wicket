#!/usr/bin/env bash
# A pinned Node.js for building the console's session view (#327, ci/session-view.sh): nodejs.org's
# linux-x64 tarball, checked against NODE_SHA256, unpacked under RUNNER_TEMP (or /tmp) and put first
# on PATH (GITHUB_PATH in Actions). With NODE_SHA256 empty it uses the runner's own Node, with a
# warning: pin it (the SHASUMS256.txt next to the tarball has the value).
#
#   NODE_VERSION=26.13.1 NODE_SHA256=<hex> ci/install-node.sh
set -euo pipefail
v=${NODE_VERSION:?NODE_VERSION}
if [ -z "${NODE_SHA256:-}" ]; then
  echo "::warning::NODE_SHA256 is not set: building with the runner's node $(node --version 2>/dev/null || echo '(none)')"
  exit 0
fi
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

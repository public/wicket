#!/bin/bash
# usage: clone.sh name url [sparse dirs...]
set -u
name=$1; url=$2; shift 2
dest="$(cd "$(dirname "$0")/../.." && pwd)/refs/repos/$name"
[ -d "$dest/.git" ] && { echo "SKIP $name"; exit 0; }
export GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0
if [ $# -gt 0 ]; then
  git clone -q --depth 1 --filter=blob:none --sparse -c core.hooksPath=/dev/null "$url" "$dest" && \
  git -C "$dest" -c core.hooksPath=/dev/null sparse-checkout set "$@"
else
  git clone -q --depth 1 -c core.hooksPath=/dev/null "$url" "$dest"
fi
if [ -d "$dest/.git" ]; then
  echo "OK $name $(git -C "$dest" rev-parse HEAD) $(git -C "$dest" log -1 --format=%cs)"
else
  echo "FAIL $name"
fi

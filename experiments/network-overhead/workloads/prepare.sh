#!/usr/bin/env bash
# Builds the workspace for the real-workload runs (#62): wicket's own source (for `cargo fetch`, a
# mid-size Rust project: about 300 crates), a cargo binary and a rustc stand-in (the agent image has
# no Rust toolchain; `cargo fetch` only asks rustc about the target), and an npm project of 168
# packages with no scoped names (see below).
#
#   experiments/network-overhead/workloads/prepare.sh WS     then, for ARM in splice inspect:
#   WICKET_HOME=... wicket run experiments/network-overhead/workloads/$ARM.yaml --workdir WS
#
# Each run writes WS/times-$ARM.txt (each step's wall time) inside the run's workspace copy.
# `inspect.yaml` is `splice.yaml` plus a forbid rule per host on a path nothing asks for, which makes
# the proxy inspect those hosts: the same zone, before and after splice-through.
#
# The npm project avoids scoped packages (@scope/name): npm asks for them as `@scope%2fname`, which
# the intercepting proxy refuses as an ambiguous path, so they can't be compared.
set -euo pipefail
ws=$1
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
mkdir -p "$ws/wicket" "$ws/npmproj"
git -C "$repo" archive HEAD Cargo.toml Cargo.lock crates third_party ci/h3get | tar -x -C "$ws/wicket"
cp "$(rustup which cargo)" "$ws/cargo"
rustc=$(rustup which rustc)
"$rustc" -vV > "$ws/rustc-vV.txt"
echo | "$rustc" - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib \
  --crate-type cdylib --crate-type staticlib --crate-type proc-macro --print=sysroot --print=split-debuginfo \
  --print=crate-name --print=cfg -Wwarnings > "$ws/rustc-print.txt" 2>/dev/null
cp "$here/run.sh" "$here/rustc" "$ws/"
cp "$here/package.json" "$ws/npmproj/"

#!/bin/bash
# Real workloads through wicket's egress proxy: each step's wall time, in /workspace/times-$ARM.txt.
cd /workspace
out=/workspace/times-$1.txt; : > "$out"
step() { local name=$1; shift; local s=$(date +%s%N); "$@" > /workspace/$name-$ARM.log 2>&1; local rc=$?; local e=$(date +%s%N); echo "$name rc=$rc ms=$(( (e - s) / 1000000 ))" >> "$out"; }
ARM=$1
step cargo-fetch env CARGO_HOME=/workspace/cache-cargo-$ARM RUSTC=/workspace/rustc ./cargo fetch --locked --manifest-path wicket/Cargo.toml
step npm-install bash -c "cd npmproj && rm -rf node_modules package-lock.json && npm install --cache /workspace/cache-npm-$ARM --no-audit --no-fund --loglevel=error"
step download-1g curl -sS -o /dev/null -w '%{size_download} %{speed_download}\n' https://proof.ovh.net/files/1Gb.dat
cat /workspace/download-1g-$ARM.log >> "$out"
du -sh /workspace/cache-cargo-$ARM npmproj/node_modules >> "$out" 2>&1
rm -rf /workspace/cache-cargo-$ARM /workspace/cache-npm-$ARM

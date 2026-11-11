#!/bin/bash
# Where the egress proxy replica's CPU goes on large downloads: perf profile of the mitm process while a
# client pulls 5 x 100 MB through it (unix socket, no socat). Needs perf (run with sudo if
# perf_event_paranoid forbids it). Writes OUT/perf-mitm.txt and OUT/perf-pass.txt.
#
#   ./perf.sh target/release/netbench logs/
set -euo pipefail
BIN=$(realpath "$1"); OUT=$(realpath "$2"); W=$(mktemp -d)
cleanup() { kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT
"$BIN" origin --listen 127.0.0.1:18443 --dir "$W" &
until [ -f "$W/origin-ca.der" ]; do sleep 0.1; done
"$BIN" mitm --listen "unix:$W/mitm.sock" --dir "$W" --upstream-port 18443 --ledger "$W/ledger.db" & MITM=$!
"$BIN" pass --listen "unix:$W/pass.sock" --mode connect --copy tokio --upstream-port 18443 & PASS=$!
until [ -S "$W/mitm.sock" ] && [ -S "$W/pass.sock" ] && [ -f "$W/run-ca.pem" ]; do sleep 0.1; done
prof() { # name pid ca sock
  perf record -q -g -o "$W/$1.data" -p "$2" -- sleep 6 >/dev/null 2>&1 &
  local P=$!; sleep 0.3
  "$BIN" probe --ep "unix:$W/$4" --connect --ca "$3" --work download --size 100000000 --n 5 > "$OUT/perf-$1-client.json"
  wait $P || true
  # Shared objects only by file name, and no build paths.
  perf report -i "$W/$1.data" --no-children --sort dso,symbol --stdio -g none 2>/dev/null \
    | grep -v '^#' | grep '%' | awk 'NR<=30' | sed -E 's#/[^ ]*/##g; s/ +- +-$//; s/ +$//; s/  +/  /g' > "$OUT/perf-$1.txt"
}
prof mitm $MITM "$W/run-ca.pem" mitm.sock
prof pass $PASS "$W/origin-ca.der" pass.sock

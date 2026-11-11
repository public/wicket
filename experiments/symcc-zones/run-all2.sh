#!/usr/bin/env bash
# Second pass after the segment-encoding simplification and the scale/band/org additions.
set -u
export CVC5="$PWD/tools/cvc5"
B=target/release/symcc-zones
run() { local log=$1; shift; timeout 3600 /usr/bin/time -v "$@" > "logs/$log" 2>&1; echo "$log exit $?"; }
SEG=1 run difftest-seg.log $B difftest
SEG=1 run zones-seg.log $B zones 5
SEG=1 run band-seg.log $B band 5
SEG=0 run band-string.log $B band 5
run org.log $B org 5
SEG=1 run policies-seg.log $B policies sh-issues-reader
SEG=1 run scale-seg.log $B scale 3
SEG=0 run scale-string.log $B scale 3
echo ALL DONE

#!/usr/bin/env bash
# Runs every measurement; outputs in logs/. Usage: ./run-all.sh (from this directory).
set -u
export CVC5="$PWD/tools/cvc5"
B=target/release/symcc-zones
run() { local log=$1; shift; timeout 3600 /usr/bin/time -v "$@" > "logs/$log" 2>&1; echo "$log exit $?"; }
SEG=0 run difftest-string.log $B difftest
SEG=1 run difftest-seg.log $B difftest
SEG=0 TLIMIT_MS=10000 run zones-string.log $B zones 5
SEG=1 run zones-seg.log $B zones 5
SEG=0 run scale-string.log $B scale 5
SEG=1 run scale-seg.log $B scale 5
SEG=1 run band-seg.log $B band 5
SEG=0 run band-string.log $B band 5
run org.log $B org 5
SEG=1 run policies-seg.log $B policies sh-issues-reader
SEG=0 run policies-string.log $B policies sh-issues-reader
# The hard string-model query on cvc5 1.3.1 and on the newer 1.4.2, 60 s per query.
SEG=0 TLIMIT_MS=60000 CASES=rc-one-session run hard-cvc5-1.3.1.log $B zones 1
CVC5="$PWD/tools/dl-cvc5-1.4.2/cvc5-Linux-x86_64-static/bin/cvc5" SEG=0 TLIMIT_MS=60000 CASES=rc-one-session run hard-cvc5-1.4.2.log $B zones 1
CVC5="$PWD/tools/dl-cvc5-1.4.2/cvc5-Linux-x86_64-static/bin/cvc5" SEG=1 run zones-seg-cvc5-1.4.2.log $B zones 3
echo ALL DONE

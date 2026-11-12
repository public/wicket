#!/usr/bin/env python3
"""Summarizes bench/box.sh output: new-connection p50/p99 (ms), and download MB/s (median, min-max)."""

import statistics
import sys
from collections import defaultdict

new, big = defaultdict(list), defaultdict(list)
for line in open(sys.argv[1]):
    f = line.split()
    if len(f) != 6:
        continue
    leg, kind = f[0], f[1]
    if kind == "new":
        new[leg].append(float(f[4]) * 1000)
    else:
        big[leg].append(float(f[5]) / 1e6)


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(p / 100 * len(v)))]


print("| leg | new conn p50 / p99 (ms) | 100 MB MB/s median (min-max) |")
print("|---|---|---|")
for leg in new:
    b = big[leg]
    print(f"| {leg} | {pct(new[leg], 50):.1f} / {pct(new[leg], 99):.1f} | {statistics.median(b):.0f} ({min(b):.0f}-{max(b):.0f}) |")

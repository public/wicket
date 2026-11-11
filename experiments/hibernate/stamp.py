#!/usr/bin/env python3
"""Prefixes each stdin line with seconds since T0 (env, epoch seconds; default: now)."""
import os, sys, time
t0 = float(os.environ.get("T0") or time.time())
for line in sys.stdin:
    sys.stdout.write(f"{time.time() - t0:.3f} {line}")
    sys.stdout.flush()

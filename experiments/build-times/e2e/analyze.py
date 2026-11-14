#!/usr/bin/env python3
"""Summarises a timestamped `bash -x` trace from profile.sh: where an end-to-end script's time went.

    analyze.py TRACE SCRIPT RC WALL_SECONDS

Each traced command's time is until the next traced command (so a command's time includes what it
waited for). Time is reported twice: by the top-level line of the script that was running (a
function call or a loop counts as the line that called it), and, for `sleep`, by the line of the
sleep itself, so fixed waits and poll intervals stand out. Background jobs interleave with the main
line, so attribution is approximate where they overlap; the total is the wall time.
"""
import collections
import re
import sys
from pathlib import Path

trace, script, rc, wall = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
name = Path(script).name
src = Path(script).read_text().splitlines()
rx = re.compile(r"^\++(\d+\.\d+)\|([^|]*):(\d+)\|([^|]*)\| ?(.*)$")
events = []
for line in Path(trace).read_text(errors="replace").splitlines():
    m = rx.match(line)
    if m:
        ts, f, ln, stack, cmd = m.groups()
        events.append((float(ts), f, int(ln), stack.split(), cmd))
if not events:
    print(f"{name}: no trace")
    sys.exit(0)
by_top = collections.Counter()
sleeps = collections.Counter()
sleep_n = collections.Counter()
for (t, f, ln, stack, cmd), nxt in zip(events, events[1:] + [(events[-1][0], None, None, None, None)]):
    dt = max(0.0, nxt[0] - t)
    # The script's own line that was running: this line if it is in the script at top level,
    # else the outermost caller's line in the script (BASH_LINENO's next-to-last entry).
    if f == name and (len(stack) <= 1):
        top = ln
    elif len(stack) >= 2:
        top = int(stack[-2])
    else:
        top = ln
    by_top[top] += dt
    if cmd.startswith("sleep "):
        sleeps[(f, ln, cmd)] += dt
        sleep_n[(f, ln, cmd)] += 1
traced = events[-1][0] - events[0][0]
print(f"{name}: exit {rc}, wall {wall:.0f} s (traced {traced:.0f} s)")
print("\nslowest lines (top-level line of the script, seconds, share):")
for ln, dt in by_top.most_common(25):
    if dt < 1:
        break
    text = src[ln - 1].strip() if 0 < ln <= len(src) else "?"
    print(f"  {dt:7.1f} s {100 * dt / max(traced, 1):5.1f}%  {name}:{ln}  {text[:110]}")
total_sleep = sum(sleeps.values())
print(f"\nsleep: {total_sleep:.0f} s in {sum(sleep_n.values())} calls ({100 * total_sleep / max(traced, 1):.0f}% of the run), by line:")
for (f, ln, cmd), dt in sorted(sleeps.items(), key=lambda kv: -kv[1])[:15]:
    if dt < 1:
        break
    print(f"  {dt:7.1f} s  {sleep_n[(f, ln, cmd)]:4d}×  {f}:{ln}  {cmd[:60]}")

#!/usr/bin/env bash
# Where runsc's own start of a box goes (#287): registers runsc with its debug log for a few starts
# of a trivial program box (experiments/box-start/measure.sh), puts Docker's settings back, then
# reads the last box's logs: each runsc command's (create, gofer, boot, start, …) first and last
# line, and the largest gaps between lines in each, with the line after the gap (what it waited for).
#
#   experiments/box-start/runsc-trace.sh [-n N] [--keep DIR]
#
# Needs sudo, Docker with runsc registered as `runsc` in /etc/docker/daemon.json, jq, python3, and
# what measure.sh needs. It restarts Docker twice (to add the debug flags, then to take them away):
# run it on a test host or a CI runner, never beside running boxes. The debug log slows runsc
# somewhat; the gaps, not the totals, are what to read.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
n=3 keep=
while [ $# -gt 0 ]; do
  case "$1" in
    -n) n=$2; shift 2 ;;
    --keep) keep=$2; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
cfg=/etc/docker/daemon.json
logs=$(mktemp -d)
sudo chmod 0777 "$logs"
backup=$(mktemp)
sudo cp "$cfg" "$backup"
restore() {
  sudo cp "$backup" "$cfg"
  sudo systemctl restart docker
}
trap restore EXIT
jq --arg log "$logs/%ID%.%COMMAND%.log" '.runtimes.runsc.runtimeArgs = ((.runtimes.runsc.runtimeArgs // []) + ["--debug", "--debug-log=" + $log])' "$backup" | sudo tee "$cfg" >/dev/null
sudo systemctl restart docker
"$here/measure.sh" -n "$n" --label runsc-trace >/dev/null
restore
trap - EXIT
sudo chmod -R a+r "$logs"
[ -z "$keep" ] || cp -r "$logs" "$keep"

python3 -I - "$logs" <<'PY'
import os, re, sys
from datetime import datetime
d = sys.argv[1]
line_re = re.compile(r"^[IWDEF](\d{4}) (\d\d:\d\d:\d\d\.\d{6})\s+\d+\s+(\S+)\] (.*)$")
boxes = {}
for f in os.listdir(d):
    m = re.match(r"^([0-9a-f]{12,})\.([a-z-]+)\.log$", f)
    if m:
        boxes.setdefault(m.group(1), []).append((m.group(2), os.path.join(d, f)))
if not boxes:
    sys.exit("runsc-trace: no debug logs written (is runsc registered as `runsc`?)")
def read(path):
    out = []
    for l in open(path, errors="replace"):
        m = line_re.match(l.rstrip("\n"))
        if m:
            t = datetime.strptime("2000" + m.group(1) + " " + m.group(2), "%Y%m%d %H:%M:%S.%f")
            out.append((t, m.group(3), m.group(4)[:140]))
    return out
# The last box started: the one whose earliest line is latest.
logs = {b: {c: read(p) for c, p in fs} for b, fs in boxes.items()}
first = lambda b: min(l[0][0] for l in logs[b].values() if l)
box = max((b for b in logs if any(logs[b].values())), key=first)
t0 = first(box)
ms = lambda t: (t - t0).total_seconds() * 1000
print(f"runsc's commands for the last box ({box[:12]}), ms from its first line:")
for c, ls in sorted(logs[box].items(), key=lambda kv: kv[1][0][0] if kv[1] else t0):
    if not ls:
        continue
    print(f"  {c:12} {ms(ls[0][0]):8.1f} → {ms(ls[-1][0]):8.1f}  ({len(ls)} lines)")
print("largest gaps (ms, at, the line after it):")
gaps = []
for c, ls in logs[box].items():
    for a, b in zip(ls, ls[1:]):
        gaps.append(((b[0] - a[0]).total_seconds() * 1000, c, ms(b[0]), b[1], b[2]))
for g, c, at, src, msg in sorted(gaps, reverse=True)[:15]:
    print(f"  {g:7.1f}  {c:10} @{at:8.1f}  {src}: {msg}")
PY

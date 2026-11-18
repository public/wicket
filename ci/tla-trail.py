#!/usr/bin/env python3
"""Audit records of real updates, as trails of verification/tla/UpdateTrace.tla (#321, #324).

    python3 -I ci/tla-trail.py AUDIT_EXPORT [--gap SECONDS]

AUDIT_EXPORT holds the control host's audit records, one a line: `seq unix_time kind subject json`
(what `wicket audit --tail N` prints). The records of runs' supervisors being re-attached are
grouped into updates (records more than --gap seconds apart, default 600, are separate updates). For each update
this prints its records, scrubbed for the public repository (run ids as r1, r2..., the local node's
run first, as Update.tla's LocalRuns; other nodes' names as `remote`; no owners, trust domains,
identities or tasks), and the TLA+ trail of the actions they are:

- `reconcile.run_adopted` then `run.attach` for a run: Update.tla's `Reattach(r)`; its supervisor
  was stopped before (`HandOver(r)`, not audited);
- `run.exit_cause` "stopped by wicket" for that run within 30 s of its attach: the `Reattach` left
  its box stopped (`box'[r] = "stopped"`), else running.

wicketd's restart, the local serve's re-exec, stopping the old supervisors and prompts aren't
audited: UpdateTrace.tla lets them happen between the trail's steps.
"""

import argparse
import json
import sys


def records(path):
    for line in open(path, encoding="utf-8"):
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        body = {}
        if len(parts) == 5:
            try:
                body = json.loads(parts[4])
            except ValueError:
                body = {}
        yield {"seq": int(parts[0]), "t": int(parts[1]), "kind": parts[2], "run": parts[3], "body": body}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("audit")
    ap.add_argument("--gap", type=int, default=600)
    a = ap.parse_args()
    rs = list(records(a.audit))
    attaches = [r for r in rs if r["kind"] == "run.attach"]
    stops = [r for r in rs if r["kind"] == "run.exit_cause" and "stopped by wicket" in str(r["body"].get("cause", ""))]
    updates, cur = [], []
    for r in attaches:
        if cur and r["t"] - cur[-1]["t"] > a.gap:
            updates.append(cur)
            cur = []
        cur.append(r)
    if cur:
        updates.append(cur)
    for u in updates:
        local = [r["run"] for r in u if r["body"].get("node") == "local"]
        others = [r["run"] for r in u if r["body"].get("node") != "local"]
        names = {}
        for run in local + others:
            names.setdefault(run, f"r{len(names) + 1}")
        when = u[0]["t"]
        hhmm = f"{when // 3600 % 24:02d}{when // 60 % 60:02d}"
        print(f"\\* update at {hhmm} UTC (unix {when}): {len(u)} re-attach(es)")
        steps = []
        for r in u:
            node = "local" if r["body"].get("node") == "local" else "remote"
            stopped = [s for s in stops if s["run"] == r["run"] and 0 <= s["t"] - r["t"] <= 30]
            box = "stopped" if stopped else "running"
            print(f"\\*   +{r['t'] - when}s reconcile.run_adopted, run.attach {names[r['run']]} on node {node}")
            for s in stopped:
                print(f"\\*   +{s['t'] - when}s run.exit_cause {names[r['run']]}: {s['body'].get('cause')} (exit {s['body'].get('code')})")
            steps.append(f'[action |-> "Reattach", run |-> "{names[r["run"]]}", box |-> "{box}"]')
        print(f"Trail{hhmm} == << {', '.join(steps)} >>")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

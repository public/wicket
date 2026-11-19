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
  its box stopped (`box'[r] = "stopped"`), else running;
- `self.switched` of the control host: `SelfUpdate`;
- `daemon.started` (wicketd's start, audited since #544's follow-up): `DrainDone` after a
  `daemon.sighup` (`wicket self update`'s), else `DaemonStart` (a restart);
- a `daemon.started` just before a `daemon.sighup` (within 5 s): the same drain, recorded out of
  order by a build that audited the SIGHUP after sending it (before #548's review). Paired as
  `DrainDone`, with a warning; mapped as written it would be a restart and a hung drain;
- a `daemon.sighup` with no `daemon.started` after it: a `Tick` for each --drain-bound seconds
  (default 10) until the next record or the export's end, at most two (Update.tla's `DrainMax` is
  one), and a warning: the daemon may not have taken commands since (#487).

A trail with `daemon.started` records needs `DaemonAudited = TRUE` in its config.

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
    ap.add_argument("--drain-bound", type=int, default=10)
    a = ap.parse_args()
    rs = list(records(a.audit))
    end = max((r["t"] for r in rs), default=0)
    def update_record(r):
        if r["kind"] == "self.switched":
            return r["body"].get("target") == "control"
        return r["kind"] in ("run.attach", "daemon.sighup", "daemon.started")
    attaches = [r for r in rs if update_record(r)]
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
        local = [r["run"] for r in u if r["kind"] == "run.attach" and r["body"].get("node") == "local"]
        others = [r["run"] for r in u if r["kind"] == "run.attach" and r["body"].get("node") != "local"]
        names = {}
        for run in local + others:
            names.setdefault(run, f"r{len(names) + 1}")
        when = u[0]["t"]
        hhmm = f"{when // 3600 % 24:02d}{when // 60 % 60:02d}"
        print(f"\\* update at {hhmm} UTC (unix {when}): {sum(r['kind'] == 'run.attach' for r in u)} re-attach(es)")
        steps = []
        sighup = None

        def none_step(action):
            return f'[action |-> "{action}", run |-> "none", box |-> "none"]'

        def ticks(upto):
            n = min(2, (upto - sighup["t"]) // a.drain_bound)
            print(f"\\*   WARNING: no daemon.started {upto - sighup['t']}s after the SIGHUP: the daemon may not have taken commands since (#487)")
            steps.extend(none_step("Tick") for _ in range(n))

        audited = any(r["kind"].startswith("daemon.") for r in u)
        paired = set()
        for k, r in enumerate(u):
            if k in paired:
                continue
            if r["kind"] == "self.switched":
                print(f"\\*   +{r['t'] - when}s self.switched {r['body'].get('from')} -> {r['body'].get('to')}")
                steps.append(none_step("SelfUpdate"))
                continue
            if r["kind"] == "daemon.sighup":
                print(f"\\*   +{r['t'] - when}s daemon.sighup")
                sighup = r
                continue
            if r["kind"] == "daemon.started" and sighup is None:
                nxt = next((j for j in range(k + 1, len(u)) if u[j]["kind"] == "daemon.sighup"), None)
                if nxt is not None and u[nxt]["t"] - r["t"] <= 5:
                    print(f"\\*   +{r['t'] - when}s daemon.started, then +{u[nxt]['t'] - when}s daemon.sighup: "
                          "WARNING: out of order (audited after the signal by an older build): paired as the drain's end")
                    steps.append(none_step("DrainDone"))
                    paired.add(nxt)
                    continue
            if r["kind"] == "daemon.started":
                after = sighup is not None
                print(f"\\*   +{r['t'] - when}s daemon.started" + (f", {r['t'] - sighup['t']}s after the SIGHUP" if after else ""))
                steps.append(none_step("DrainDone" if after else "DaemonStart"))
                sighup = None
                continue
            node = "local" if r["body"].get("node") == "local" else "remote"
            stopped = [s for s in stops if s["run"] == r["run"] and 0 <= s["t"] - r["t"] <= 30]
            box = "stopped" if stopped else "running"
            print(f"\\*   +{r['t'] - when}s reconcile.run_adopted, run.attach {names[r['run']]} on node {node}")
            for st in stopped:
                print(f"\\*   +{st['t'] - when}s run.exit_cause {names[r['run']]}: {st['body'].get('cause')} (exit {st['body'].get('code')})")
            steps.append(f'[action |-> "Reattach", run |-> "{names[r["run"]]}", box |-> "{box}"]')
        if sighup is not None:
            ticks(end)
        print(f"\\*   DaemonAudited = {'TRUE' if audited else 'FALSE'}")
        print(f"Trail{hhmm} == << {', '.join(steps)} >>")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

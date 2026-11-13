#!/usr/bin/env python3
"""Prints RESULTS.md's tables from logs/*.jsonl."""
import json
from pathlib import Path

LOGS = Path(__file__).resolve().parent / "logs"


def load(name):
    p = LOGS / name
    return [json.loads(l) for l in open(p)] if p.exists() else []


S = load("series.jsonl")
F = ("today", "age", "rustic")
A = ("rust", "node", "small")
mb = lambda b: f"{b / 1e6:,.1f}"


def g(**k):
    return [r for r in S if all(r.get(a) == b for a, b in k.items())]


def saves_table(store, upto):
    print(f"\n**{store}**: bytes added to the store per save (MB), and in total after {upto} sessions\n")
    print("| agent | format | full | +1 session | +5 (each, mean) | +20 (each, mean) | total | objects |")
    print("|---|---|---:|---:|---:|---:|---:|---:|")
    for a in A:
        for f in F:
            s = g(kind="save", store=store, agent=a, format=f)
            if not s:
                continue
            m5 = sum(x["added_bytes"] for x in s[1:6]) / max(1, len(s[1:6]))
            m20 = sum(x["added_bytes"] for x in s[1:21]) / max(1, len(s[1:21])) if len(s) > 6 else None
            print(f"| {a} | {f} | {mb(s[0]['added_bytes'])} | {mb(s[1]['added_bytes'])} | {mb(m5)} | {mb(m20) if m20 is not None else '-'} | "
                  f"{mb(s[-1]['stored_bytes_total'])} | {s[-1]['objects_total']} |")


def time_table(store):
    print(f"\n**{store}**: save and restore, wall s / CPU s / peak RSS MB (one process each)\n")
    print("| agent | format | full save | incremental save (+1) | restore (+5) | restore one tree (+5) |")
    print("|---|---|---|---|---|---|")
    w = lambda r: f"{r['wall_s']:.1f} / {r['user_s'] + r['sys_s']:.1f} / {r['maxrss_mb']:.0f}" if r else "-"
    for a in A:
        for f in F:
            s = g(kind="save", store=store, agent=a, format=f)
            if not s:
                continue
            r5 = g(kind="restore", store=store, agent=a, format=f, session=5)
            o5 = g(kind="restore_one", store=store, agent=a, format=f, session=5)
            print(f"| {a} | {f} | {w(s[0])} | {w(s[1])} | {w(r5[0] if r5 else None)} | {w(o5[0] if o5 else None)} |")


def s3_requests():
    print("\n**s3**: requests per operation (versitygw's access log)\n")
    print("| agent | format | full save PUT | incremental save PUT / GET / LIST | restore (+5) GET | restore one tree GET |")
    print("|---|---|---:|---|---:|---:|")
    for a in A:
        for f in F:
            s = g(kind="save", store="s3", agent=a, format=f)
            if not s:
                continue
            r5 = g(kind="restore", store="s3", agent=a, format=f, session=5)
            o5 = g(kind="restore_one", store="s3", agent=a, format=f, session=5)
            print(f"| {a} | {f} | {s[0]['puts']} | {s[1]['puts']} / {s[1]['gets']} / {s[1]['lists']} | {r5[0]['gets'] if r5 else '-'} | "
                  f"{o5[0]['gets'] if o5 else '-'} |")


def maint():
    print("\n**fs, after 20 sessions**: integrity check reading every byte, and prune to the newest state\n")
    print("| agent | format | check (wall s / CPU s) | prune (wall s) | store before → after (MB) | restore after prune |")
    print("|---|---|---|---:|---|---|")
    for a in A:
        for f in F:
            c = g(kind="check_read", agent=a, format=f)
            p = g(kind="prune", agent=a, format=f)
            if not (c and p):
                continue
            c, p = c[0], p[0]
            print(f"| {a} | {f} | {c['wall_s']:.1f} / {c['user_s'] + c['sys_s']:.1f} | {p['wall_s']:.1f} | {mb(p['bytes_before'])} → {mb(p['bytes_after'])} | "
                  f"{'verified' if p['restore_after_prune_verified'] else 'FAILED'} |")


def restic():
    R = load("restic.jsonl")
    if not R:
        return
    print("\n**restic CLI 0.19.1 (reference), fs**: MB added, wall s / CPU s / RSS MB\n")
    print("| agent | full | +1 session | +5 | restore (+5) | check --read-data | forget --keep-last 1 --prune |")
    print("|---|---|---|---|---|---|---|")
    for a in A:
        b = [r for r in R if r["kind"] == "restic_backup" and r["agent"] == a]
        by = lambda n: sum(r["added_bytes"] for r in b if r["session"] == n)
        ws = lambda n: sum(r["wall_s"] for r in b if r["session"] == n)
        rr = [r for r in R if r["kind"] == "restic_restore" and r["agent"] == a and r["session"] == 5]
        ck = [r for r in R if r["kind"] == "restic_check_read" and r["agent"] == a]
        pr = [r for r in R if r["kind"] == "restic_forget_prune" and r["agent"] == a]
        w = lambda r: f"{r['wall_s']:.1f} / {r['user_s'] + r['sys_s']:.1f} / {r['maxrss_mb']:.0f}"
        print(f"| {a} | {mb(by(0))} ({ws(0):.1f} s) | {mb(by(1))} ({ws(1):.1f} s) | {mb(by(5))} | {w(rr[0]) if rr else '-'} | {w(ck[0]) if ck else '-'} | "
              f"{w(pr[0]) if pr else '-'} |")


def extras():
    E = load("extras.jsonl")
    print("\n**cross-agent dedup**: a second agent with the same node tree (a fork)\n")
    print("| format | repository | first agent (MB) | second agent adds (MB) |")
    print("|---|---|---:|---:|")
    for r in E:
        if r["kind"] == "cross_agent":
            print(f"| {r['format']} | {'per zone' if r['repo_key'] != 'agent' else 'per agent'} | {mb(r['first_bytes'])} | {mb(r['second_added_bytes'])} |")
    K = load("kill9.jsonl")
    print("\n**kill -9 mid-save** (rust agent; killed at 20, 50 and 80% of a measured run of the same save)\n")
    print("| format | phase | killed | check after | previous state restores | next save + restore |")
    print("|---|---|---|---|---|---|")
    for f in F:
        for ph in ("full", "incremental"):
            rs = [r for r in K if r["format"] == f and r["phase"] == ph]
            if not rs:
                continue
            killed = sum(r["killed_rc"] == -9 for r in rs)
            warn = sum("Warn" in str(r["check_after_kill"]) for r in rs)
            err = sum(bool(r["check_after_kill"].get("errors")) or "Error" in str(r["check_after_kill"]) for r in rs)
            prev = "n/a (nothing before)" if ph == "full" else f"{sum(r['previous_state_restored'] is True for r in rs)}/{len(rs)}"
            nxt = sum(r["next_save_exit"] == 0 and r["next_restore_verified"] for r in rs)
            ck = f"{len(rs) - err - warn} clean" + (f", {warn} unreferenced-pack warnings" if warn else "") + (f", {err} errors" if err else "")
            print(f"| {f} | {ph} | {killed}/{len(rs)} | {ck} | {prev} | {nxt}/{len(rs)} |")


if __name__ == "__main__":
    saves_table("fs", 20)
    saves_table("s3", 5)
    time_table("fs")
    time_table("s3")
    s3_requests()
    maint()
    restic()
    extras()

#!/usr/bin/env python3
"""Markdown tables from logs/results.json (netbench bench). Each figure is the median over rounds of
that round's statistic (p50 or p99 over its samples)."""
import json
import statistics as st
import sys

d = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "logs/results.json"))
med = st.median


def m(rounds, f):
    return med([f(r) for r in rounds])


def table(head, rows):
    print("| " + " | ".join(head) + " |")
    print("|" + "---|" * len(head))
    for r in rows:
        print("| " + " | ".join(str(x) for x in r) + " |")
    print()


print("## 1 KB requests\n")
rows = []
for k, rs in d.items():
    rows.append([
        k,
        f"{m(rs, lambda r: r['lat_new']['total']['p50_us'])/1e3:.2f} / {m(rs, lambda r: r['lat_new']['total']['p99_us'])/1e3:.2f}",
        f"{m(rs, lambda r: r['lat_keep']['p50_us']):.0f} / {m(rs, lambda r: r['lat_keep']['p99_us']):.0f}",
        f"{m(rs, lambda r: r['rps_keep']['rps']):.0f}",
        f"{m(rs, lambda r: r['rps_new']['rps']):.0f}",
        f"{m(rs, lambda r: r['rps_keep']['lat']['p99_us'])/1e3:.1f}",
    ])
table(["setup", "new conn p50 / p99 (ms)", "keep-alive p50 / p99 (µs)", "req/s, 16 kept conns", "req/s, 16 workers, new conn each", "p99 at 16 kept conns (ms)"], rows)

print("## New connection, phase by phase (p50, µs)\n")
rows = []
for k, rs in d.items():
    rows.append([k] + [f"{m(rs, lambda r, p=p: r['lat_new'][p]['p50_us']):.0f}" for p in ["connect", "proxy_connect", "tls", "ttfb", "total"]])
table(["setup", "connect", "CONNECT", "TLS handshake", "first response", "total"], rows)

print("## 100 MB downloads\n")
rows = []
for k, rs in d.items():
    mbs = [r["download"]["bytes"] / 1e6 / s for r in rs for s in r["download"]["secs"]]
    gb = [r["download"]["bytes"] * len(r["download"]["secs"]) / 1e9 for r in rs]

    def cpu(comp):
        v = [r["download"]["cpu_s"].get(comp, 0) / g for r, g in zip(rs, gb)]
        return f"{med(v):.2f}"

    rows.append([k, f"{med(mbs):.0f} ({min(mbs):.0f}–{max(mbs):.0f})", cpu("proxy"), cpu("hop"), cpu("client"), cpu("origin")])
table(["setup", "MB/s median (min–max)", "proxy CPU s/GB", "hop CPU s/GB", "client CPU s/GB", "origin CPU s/GB"], rows)

print("## CPU per 1,000 requests at 16 kept connections (ms)\n")
rows = []
for k, rs in d.items():
    def c(comp, key="rps_keep"):
        return f"{med([r[key]['cpu_s'].get(comp, 0) / r[key]['requests'] * 1e6 for r in rs]):.0f}"
    rows.append([k, c("proxy"), c("hop"), c("proxy", "rps_new"), c("hop", "rps_new")])
table(["setup", "proxy, kept", "hop, kept", "proxy, new conn", "hop, new conn"], rows)

print("## 10 MB upload (s, median)\n")
rows = [[k, f"{med([s for r in rs for s in r['upload_10mb_secs']]):.3f}"] for k, rs in d.items()]
table(["setup", "seconds"], rows)

print("## Proxy stage timings (p50 / p99 µs, median over rounds)\n")
rows = []
for k, rs in d.items():
    stamps = [r.get("proxy_stamps") for r in rs if r.get("proxy_stamps")]
    if not stamps:
        continue
    for stage in stamps[0]:
        vs = [s[stage] for s in stamps if stage in s and s[stage].get("n")]
        rows.append([k, stage, f"{med([v['n'] for v in vs]):.0f}", f"{med([v['p50_us'] for v in vs]):.1f} / {med([v['p99_us'] for v in vs]):.1f}"])
table(["setup", "stage", "n per round", "p50 / p99"], rows)

# In-box legs (box.sh): curl -w lines "<leg> <kind> connect appconnect starttransfer total speed".
import glob
import os

files = sorted(glob.glob(os.path.join(os.path.dirname(sys.argv[1]) if len(sys.argv) > 1 else "logs", "box-*.txt")))
if files:
    print("## In-box curl (box.sh): per request ms p50 / p99, downloads MB/s median\n")
    rows = []
    for f in files:
        rt = os.path.basename(f)[4:-4]
        lines = [l.split() for l in open(f) if len(l.split()) == 7]
        for leg in sorted({l[0] for l in lines}):
            def q(kind, col, p):
                v = sorted(float(l[col]) for l in lines if l[0] == leg and l[1] == kind)
                return v[round((len(v) - 1) * p)] * 1e3 if v else float("nan")
            big = [float(l[6]) / 1e6 for l in lines if l[0] == leg and l[1] == "big"]
            rows.append([rt, leg, f"{q('new', 5, .5):.2f} / {q('new', 5, .99):.2f}", f"{q('new', 3, .5):.2f}",
                         f"{q('keep', 5, .5):.2f} / {q('keep', 5, .99):.2f}", f"{st.median(big):.0f}" if big else "-"])
    table(["box", "leg", "new conn total", "new conn: until TLS done", "keep-alive total", "100 MB MB/s"], rows)

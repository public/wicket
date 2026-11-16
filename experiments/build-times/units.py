"""Reads a `cargo --timings` report (HTML) and prints its units as JSON: each unit's crate, kind and
seconds, the longest first, and their sum (#219). Run with `python3 -I`."""
import json, re, sys

html = open(sys.argv[1]).read()
units = json.loads(re.search(r"const UNIT_DATA = (\[.*?\]);\n", html, re.S).group(1))
rows = sorted(
    ({"crate": u["name"], "version": u["version"], "kind": u["mode"] if u["mode"] != "todo" else (u.get("target") or "lib").strip() or "lib",
      "secs": round(u["duration"], 2)} for u in units),
    key=lambda r: -r["secs"],
)
json.dump({"units": len(rows), "sum_secs": round(sum(r["secs"] for r in rows), 1), "longest": [r for r in rows if r["secs"] >= 1.0]},
          sys.stdout, indent=1)
print()

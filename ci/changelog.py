#!/usr/bin/env python3
"""CHANGELOG fragments (#220): each pull request adds `changes/<pr number or slug>.md` instead of
editing CHANGELOG.md, so parallel PRs don't conflict there. This script assembles them, at release
time, into CHANGELOG.md's unreleased section; and CI checks that a PR changing more than docs adds one.

A fragment is a small header and one or more `- ` entries, in the changelog's own style:

    ---
    area: Updates
    type: Added
    ---
    - `wicket self update` takes a protocol jump when every node moves with it
      ([#207](https://github.com/public/wicket/issues/207)).

`area` is the heading the entry goes under (an existing one, such as Updates, Images or DNS, or a new
one); `type` is one of Added, Changed, Fixed, Security or Removed. Within an area, entries are ordered
Security, Added, Changed, Fixed, Removed, then by file name; Fixed, Security and Removed entries are
marked as such.

    ci/changelog.py check [--base REF]        fragments parse; a PR (HEAD against REF) that changes
                                              more than docs adds one (NO_CHANGELOG=1 skips it)
    ci/changelog.py preview                   the unreleased section as it would be assembled
    ci/changelog.py assemble --version 0.0.2  write it into CHANGELOG.md, remove the fragments

No dependencies beyond Python's standard library.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGES = ROOT / "changes"
CHANGELOG = ROOT / "CHANGELOG.md"
TYPES = ["Security", "Added", "Changed", "Fixed", "Removed"]
MARKED = {"Security", "Fixed", "Removed"}
# What a PR may change without a fragment: documentation, CI, the fragments themselves, notes, and
# the repository's own top-level dotfiles (.gitignore, .gitleaks.toml).
EXEMPT = [r"^docs/", r"^\.[^/]+$", r"^changes/", r"^ci/", r"^\.github/", r"^experiments/", r"^refs/", r"^[^/]+\.md$", r"^LICENSE$"]


class Bad(Exception):
    pass


def parse(path: Path):
    """A fragment: (area, type, [entry lines, each an entry with its continuation lines])."""
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        raise Bad(f"{path.name}: starts with a header between --- lines (area:, type:)")
    head = {}
    for line in m.group(1).splitlines():
        if not line.strip():
            continue
        k, sep, v = line.partition(":")
        if not sep:
            raise Bad(f"{path.name}: header line {line!r} isn't `key: value`")
        head[k.strip()] = v.strip()
    unknown = set(head) - {"area", "type"}
    if unknown:
        raise Bad(f"{path.name}: unknown header field(s) {', '.join(sorted(unknown))}")
    area, kind = head.get("area", ""), head.get("type", "")
    if not area:
        raise Bad(f"{path.name}: no area (the heading it goes under, e.g. Updates)")
    if kind not in TYPES:
        raise Bad(f"{path.name}: type {kind!r} is not one of {', '.join(TYPES)}")
    entries, cur = [], None
    for line in m.group(2).rstrip("\n").splitlines():
        if line.startswith("- "):
            cur = [line]
            entries.append(cur)
        elif cur is not None and (line.startswith("  ") or not line.strip()):
            cur.append(line)
        elif line.strip():
            raise Bad(f"{path.name}: {line!r} is neither an entry (`- `) nor its continuation (indented)")
    entries = ["\n".join(e).rstrip() for e in entries]
    if not entries:
        raise Bad(f"{path.name}: no entries (`- ...`)")
    return area, kind, entries


def fragments():
    if not CHANGES.is_dir():
        return []
    return sorted(p for p in CHANGES.glob("*.md") if p.name != "README.md")


def mark(kind: str, entry: str) -> str:
    return entry if kind not in MARKED else entry.replace("- ", f"- {kind}: ", 1)


def collect():
    """Every fragment's entries by area, ordered; and the errors."""
    by_area, errors = {}, []
    for p in fragments():
        try:
            area, kind, entries = parse(p)
        except Bad as e:
            errors.append(str(e))
            continue
        for e in entries:
            by_area.setdefault(area, []).append((TYPES.index(kind), p.name, mark(kind, e)))
    for v in by_area.values():
        v.sort(key=lambda x: (x[0], x[1]))
    return by_area, errors


def merge(text: str, version: str, by_area) -> str:
    """CHANGELOG.md's text with the entries added to `## <version> (unreleased)` (made if missing):
    each area's after its existing entries, new areas at the end of the section."""
    lines = text.split("\n")
    head = re.compile(rf"^## {re.escape(version)}\b")
    try:
        start = next(i for i, l in enumerate(lines) if head.match(l))
    except StopIteration:
        first = next((i for i, l in enumerate(lines) if l.startswith("## ")), len(lines))
        lines[first:first] = [f"## {version} (unreleased)", ""]
        start = first
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    section = lines[start:end]
    for area, items in by_area.items():
        block = [e for _, _, e in items]
        idx = next((i for i, l in enumerate(section) if l == f"### {area}"), None)
        if idx is None:
            while section and not section[-1].strip():
                section.pop()
            section += ["", f"### {area}", ""] + "\n".join(block).split("\n") + [""]
            continue
        nxt = next((i for i in range(idx + 1, len(section)) if section[i].startswith("### ")), len(section))
        at = nxt
        while at > idx + 1 and not section[at - 1].strip():
            at -= 1
        section[at:at] = "\n".join(block).split("\n")
    while section and not section[-1].strip():
        section.pop()
    section.append("")
    return "\n".join(lines[:start] + section + lines[end:])


def changed_files(base: str):
    out = subprocess.run(["git", "diff", "--name-only", "--diff-filter=AMR", f"{base}...HEAD"], cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"git diff against {base}: {out.stderr.strip()}")
    return [l for l in out.stdout.splitlines() if l]


def cmd_check(args) -> int:
    _, errors = collect()
    for e in errors:
        print(f"changelog: {e}", file=sys.stderr)
    if errors:
        return 1
    if not args.base:
        print(f"changelog: {len(fragments())} fragment(s) parse")
        return 0
    files = changed_files(args.base)
    code = [f for f in files if not any(re.search(p, f) for p in EXEMPT)]
    added = [f for f in files if re.match(r"^changes/(?!README\.md$)[^/]+\.md$", f)]
    if code and not added:
        if os.environ.get("NO_CHANGELOG") == "1":
            print("changelog: no fragment, and the PR says none is needed (the `no changelog` label)")
            return 0
        print(
            "changelog: this PR changes more than docs but adds no fragment: add changes/<pr number>.md "
            "(see changes/README.md), or label it `no changelog` if nobody using wicket would notice.\n"
            "  changed: " + ", ".join(code[:10]) + (" …" if len(code) > 10 else ""),
            file=sys.stderr,
        )
        return 1
    print(f"changelog: ok ({len(added)} fragment(s) added)" if code else "changelog: docs only, no fragment needed")
    return 0


def cmd_preview(args) -> int:
    by_area, errors = collect()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    for area, items in by_area.items():
        print(f"### {area}\n")
        print("\n".join(e for _, _, e in items) + "\n")
    return 0


def cmd_assemble(args) -> int:
    by_area, errors = collect()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if not by_area:
        print("changelog: no fragments")
        return 0
    CHANGELOG.write_text(merge(CHANGELOG.read_text(encoding="utf-8"), args.version, by_area), encoding="utf-8")
    for p in fragments():
        p.unlink()
    print(f"changelog: {sum(len(v) for v in by_area.values())} entr(ies) into {args.version}; fragments removed")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--base", help="the PR's base (a ref or sha): require a fragment if it changes more than docs")
    c.set_defaults(f=cmd_check)
    sub.add_parser("preview").set_defaults(f=cmd_preview)
    a = sub.add_parser("assemble")
    a.add_argument("--version", required=True)
    a.set_defaults(f=cmd_assemble)
    args = ap.parse_args()
    return args.f(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""No AI attribution in wicket's history: commit messages, pull request titles and bodies.

    ci/no-attribution.py --message FILE        a commit message (the commit-msg hook)
    ci/no-attribution.py --range BASE..HEAD    every commit message in a range
    ci/no-attribution.py --event FILE          a pull request event's title and body (GITHUB_EVENT_PATH)

The project's rule: commits and pull requests carry no AI attribution (no Co-Authored-By trailer
for an assistant, no "Generated with ..." footer, no session links). Naming a harness wicket runs,
such as Claude Code, is fine: only attribution forms are refused. Exits 1, naming each line, when
one is found.
"""

import argparse
import json
import re
import subprocess
import sys

# Each pattern is an attribution form, matched case-insensitively against one line.
PATTERNS = [
    (re.compile(r"^\s*co-authored-by:.*\b(claude|anthropic|copilot|chatgpt|openai|gemini|codex)\b", re.I),
     "a Co-Authored-By trailer for an assistant"),
    (re.compile(r"noreply@anthropic\.com", re.I), "an assistant's no-reply address"),
    (re.compile(r"generated\s+(with|by)\s+\[?\s*(claude|copilot|chatgpt|codex|gemini)", re.I),
     "a \"Generated with/by\" footer"),
    (re.compile(r"\U0001F916\s*generated", re.I), "a \"Generated with\" footer"),
    (re.compile(r"^\s*claude-session:", re.I), "a Claude-Session trailer"),
    (re.compile(r"claude\.ai/code/session_", re.I), "a session link"),
]


def findings(text: str, where: str) -> list[str]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for pat, what in PATTERNS:
            if pat.search(line):
                out.append(f"{where}, line {n}: {what}: {line.strip()[:120]}")
                break
    return out


def commit_messages(rng: str) -> list[tuple[str, str]]:
    shas = subprocess.run(["git", "rev-list", "--no-merges", rng], check=True, capture_output=True, text=True).stdout.split()
    msgs = []
    for sha in shas:
        body = subprocess.run(["git", "log", "-1", "--format=%B", sha], check=True, capture_output=True, text=True).stdout
        msgs.append((sha[:12], body))
    return msgs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--message")
    g.add_argument("--range")
    g.add_argument("--event")
    a = ap.parse_args()
    found: list[str] = []
    if a.message:
        with open(a.message, encoding="utf-8", errors="replace") as f:
            # The commit-msg hook's file includes git's comment lines; they aren't committed.
            text = "\n".join(l for l in f.read().splitlines() if not l.startswith("#"))
        found += findings(text, "the commit message")
    elif a.range:
        for sha, body in commit_messages(a.range):
            found += findings(body, f"commit {sha}")
    else:
        with open(a.event, encoding="utf-8") as f:
            ev = json.load(f)
        pr = ev.get("pull_request") or {}
        found += findings(pr.get("title") or "", "the pull request's title")
        found += findings(pr.get("body") or "", "the pull request's body")
    for f in found:
        print(f"::error title=AI attribution::{f}" if a.event or a.range else f, file=sys.stderr)
    if found:
        print("\nwicket's commits and pull requests carry no AI attribution: remove these lines "
              "(edit the PR body, or amend or rebase the commits).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

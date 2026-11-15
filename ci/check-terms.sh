#!/bin/sh
# Fails if the docs or the CLI's help use a word the glossary replaced (#332): one word per thing, as
# docs/explanation/concepts.md "The nouns" defines them. The CLI's help is checked through
# docs/reference/cli.md, which a wicket-cli unit test keeps equal to every command's --help.
#
# Flagged, case-insensitively, as whole words:
#   - "sandbox node": a node (a machine that runs boxes);
#   - "escalation request": a request ("escalation" is the act of asking, not a separate thing);
#   - "mandate", "crew": deferred designs (#259), outside docs/explanation/research/ and
#     design.md's "22. Deferred" section;
#   - "sandbox" in the user docs (README.md, docs/README.md, docs/how-to/, docs/reference/,
#     docs/tutorials/, docs/explanation/concepts.md) where "box" is meant: "sandbox" names only
#     gVisor's layer, so "gVisor sandbox", "gVisor's sandbox" and the protocol's "Blocked by wicket
#     sandbox" pass.
#
# Checked: README.md and every tracked *.md under docs/ except docs/explanation/research/, code
# blocks included.
# ci/check-terms.allow lists the lines that may use a word anyway: `<path> | <text>`, where the line
# contains <text> (or `<path> | *` for the whole file). Keep it short, and say why above each entry.
#
# Usage: ci/check-terms.sh [FILE.md...]   (default: every file it checks)
set -eu
cd "$(dirname "$0")/.."
exec python3 -I - "$@" <<'EOF'
import re
import subprocess
import sys

ALLOW_FILE = "ci/check-terms.allow"

USER_DOCS = ("README.md", "docs/README.md", "docs/how-to/", "docs/reference/", "docs/tutorials/", "docs/explanation/concepts.md")
SANDBOX_OK = re.compile(r"gvisor(?:'s)? sandbox|blocked by wicket sandbox", re.I)

RULES = [
    # (pattern, what to say instead, applies to path)
    (re.compile(r"\bsandbox[- ]nodes?\b", re.I), 'say "node"', lambda p: True),
    (re.compile(r"\bescalation[- ]requests?\b", re.I), 'say "request" ("escalation" is the act of asking)', lambda p: True),
    (re.compile(r"\b(?:mandates?|crews?)\b", re.I), "a deferred design (#259): only in research and design.md's Deferred section", lambda p: True),
    (re.compile(r"\bsandbox(?:es)?\b", re.I), 'say "box" ("sandbox" is only gVisor\'s layer)', lambda p: p.startswith(USER_DOCS)),
]


def checked(path):
    return path.endswith(".md") and (path == "README.md" or path.startswith("docs/")) and not path.startswith("docs/explanation/research/")


def load_allow():
    allow = []
    with open(ALLOW_FILE, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if " | " not in line:
                sys.exit(f"{ALLOW_FILE}:{n}: expected `<path> | <text>`")
            path, text = line.split(" | ", 1)
            allow.append([path.strip(), text.strip(), 0])
    return allow


def deferred_lines(path, lines):
    """Line numbers of design.md's "22. Deferred" section."""
    out = set()
    if path != "docs/explanation/design.md":
        return out
    inside = False
    for n, line in enumerate(lines, 1):
        if line.startswith("## "):
            inside = line.startswith("## 22. Deferred")
        if inside:
            out.add(n)
    return out


files = sys.argv[1:] or [
    f for f in subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True, check=True).stdout.split("\n") if f and checked(f)
]
allow = load_allow()
bad = 0
for path in files:
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    deferred = deferred_lines(path, lines)
    for n, line in enumerate(lines, 1):
        for pattern, instead, applies in RULES:
            if not applies(path):
                continue
            rest = SANDBOX_OK.sub("", line) if "sandbox" in pattern.pattern else line
            m = pattern.search(rest)
            if not m:
                continue
            if "mandate" in pattern.pattern and n in deferred:
                continue
            hit = [a for a in allow if a[0] == path and (a[1] == "*" or a[1] in line)]
            if hit:
                for a in hit:
                    a[2] += 1
                continue
            print(f'{path}:{n}: "{m.group(0)}": {instead}')
            bad += 1
            break
for path, text, used in allow:
    if not used and not sys.argv[1:]:
        print(f"{ALLOW_FILE}: `{path} | {text}` matches nothing: remove it")
        bad += 1
if bad:
    sys.stdout.flush()
    print(f"{bad} term(s) to fix (docs/explanation/concepts.md#the-nouns), or allow in {ALLOW_FILE}", file=sys.stderr)
    sys.exit(1)
print(f"terms: {len(files)} files, none flagged")
EOF

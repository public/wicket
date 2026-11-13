#!/bin/sh
# Fails if a relative link in a tracked Markdown file is broken: the file or directory it names
# doesn't exist, or the #anchor it names isn't a heading of the Markdown file it points to.
#
# Checked: inline links and images, [text](target) and ![alt](target), and reference definitions,
# [label]: target, outside fenced code blocks and inline code. Not checked: absolute URLs
# (http:, https:, mailto: and the like), which need the network. Anchors are GitHub's heading slugs:
# lowercased, punctuation other than '-' and '_' dropped, spaces turned into '-', and '-1', '-2'… for
# repeats.
#
# Usage: ci/check-doc-links.sh [FILE.md...]   (default: every *.md git tracks, outside third_party/,
# refs/ and vendor/ directories, which are third-party content)
set -eu
cd "$(dirname "$0")/.."
exec python3 -I - "$@" <<'EOF'
import os
import re
import subprocess
import sys

files = sys.argv[1:] or [
    f
    for f in subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True, check=True).stdout.split("\n")
    if f and not f.startswith(("third_party/", "refs/")) and "/vendor/" not in f
]

FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")
LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$")
HTML_ID = re.compile(r"<a\s+(?:name|id)=\"([^\"]+)\"")


def lines_outside_code(path):
    """Yield (number, line) for lines outside fenced code blocks."""
    fence = None
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            m = FENCE.match(line)
            if m:
                if fence is None:
                    fence = m.group(1)
                elif m.group(1) == fence:
                    fence = None
                continue
            if fence is None:
                yield n, line


def slug(text):
    text = re.sub(r"`|\*\*|__", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # a link's text only
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


anchor_cache = {}


def anchors(path):
    if path not in anchor_cache:
        seen = {}
        found = set()
        for _, line in lines_outside_code(path):
            found.update(HTML_ID.findall(line))
            m = HEADING.match(line)
            if not m:
                continue
            s = slug(m.group(1))
            k = seen.get(s, 0)
            seen[s] = k + 1
            found.add(s if k == 0 else f"{s}-{k}")
        anchor_cache[path] = found
    return anchor_cache[path]


broken = []
checked = 0
for md in files:
    base = os.path.dirname(md)
    for n, line in lines_outside_code(md):
        text = INLINE_CODE.sub("", line)
        targets = LINK.findall(text)
        m = REFDEF.match(text)
        if m:
            targets.append(m.group(1))
        for t in targets:
            if SCHEME.match(t) or t.startswith("//"):
                continue
            checked += 1
            path, _, frag = t.partition("#")
            path = path.split("?", 1)[0]
            if path == "":
                dest = md
            elif path.startswith("/"):
                dest = path.lstrip("/")
            else:
                dest = os.path.normpath(os.path.join(base, path))
            if not os.path.exists(dest):
                broken.append(f"{md}:{n}: {t}: {dest} does not exist")
            elif frag and dest.endswith(".md") and os.path.isfile(dest) and frag not in anchors(dest):
                broken.append(f"{md}:{n}: {t}: no heading #{frag} in {dest}")

for b in broken:
    print(b)
print(f"{checked} relative links in {len(files)} files, {len(broken)} broken", file=sys.stderr)
sys.exit(1 if broken else 0)
EOF

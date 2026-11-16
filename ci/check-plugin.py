#!/usr/bin/env python3
"""Checks wicket's Claude Code plugin: the marketplace, the plugin's manifest and its skills.

Fails if:
- .claude-plugin/marketplace.json or a plugin's .claude-plugin/plugin.json isn't valid JSON, lacks a
  required field, has a field Claude Code doesn't read, or names a plugin badly (letters, digits,
  '.', '_' and '-', starting with a letter or digit; plugins in kebab-case);
- a marketplace entry's source isn't a './' path inside the repository to a plugin directory, or
  its name differs from the plugin.json name it points to (the install id would not resolve);
- a skill (skills/<name>/SKILL.md) has no frontmatter on its first line, a frontmatter field outside
  the Agent Skills spec's (name, description, license, compatibility, metadata, allowed-tools, so
  the skill also loads outside Claude Code), a name that isn't its directory's or isn't lowercase
  kebab-case of at most 64 characters, a missing or empty description, one over 1024 characters,
  one with angle brackets (shown as &lt; and &gt;), or an empty body;
- a link in a plugin's Markdown is broken: a relative link must stay inside the plugin (an installed
  plugin is a copy of its directory, so nothing outside it exists there) and name a file that
  exists; a link to this repository on GitHub (https://github.com/public/wicket/blob/main/... or
  /tree/main/...) must name a tracked path, and its #anchor a heading of that Markdown file; so
  must plugin.json's homepage and repository when they point there.

The frontmatter is read as the simple YAML a skill needs: one `key: value` per line. A value that
plain YAML would read differently (one containing ': ' or ' #', or starting with a YAML indicator)
must be quoted.

Usage: ci/check-plugin.py   (from anywhere; checks the repository it is in)
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

REPO_URL = re.compile(r"^https://github\.com/public/wicket/(?:blob|tree)/main/([^#?]*)(?:#(.*))?$")
LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$")
HTML_ID = re.compile(r"<a\s+(?:name|id)=\"([^\"]+)\"")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")

ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
KEBAB = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# Every top-level key Claude Code reads (code.claude.com/docs/en/plugins/marketplace-reference and
# manifest-reference). Anything else is stripped with a warning, so it is a mistake here.
MARKETPLACE_KEYS = {
    "$schema", "name", "owner", "plugins", "description", "version", "metadata",
    "forceRemoveDeletedPlugins", "allowCrossMarketplaceDependenciesOn", "renames",
}
PLUGIN_KEYS = {
    "$schema", "name", "displayName", "version", "description", "author", "homepage", "repository",
    "license", "keywords", "metadata", "icon", "documentationUrl", "supportUrl", "privacyPolicyUrl",
    "termsOfServiceUrl", "defaultEnabled", "dependencies", "userConfig", "types", "channels",
    "skills", "commands", "agents", "hooks", "mcpServers", "lspServers", "outputStyles", "workflows",
    "experimental",
}
ENTRY_KEYS = PLUGIN_KEYS - {"icon", "documentationUrl", "supportUrl", "privacyPolicyUrl", "termsOfServiceUrl"} | {
    "source", "category", "tags", "strict", "relevance", "headers", "headersHelper",
}
SKILL_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}

errors = []


def err(where, msg):
    errors.append(f"{where}: {msg}")


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
    except (OSError, ValueError) as e:
        err(path, f"not readable JSON: {e}")
        return None
    if not isinstance(v, dict):
        err(path, "not a JSON object")
        return None
    return v


def tracked():
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    files = set(f for f in out.split("\n") if f)
    dirs = set()
    for f in files:
        d = os.path.dirname(f)
        while d:
            dirs.add(d)
            d = os.path.dirname(d)
    return files, dirs


def lines_outside_code(text):
    fence = None
    for n, line in enumerate(text.split("\n"), 1):
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
    # GitHub's heading anchors, as ci/check-doc-links.sh computes them.
    text = re.sub(r"`|\*\*|__", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


anchor_cache = {}


def anchors(path):
    if path not in anchor_cache:
        seen, found = {}, set()
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for _, line in lines_outside_code(text):
            found.update(HTML_ID.findall(line))
            m = HEADING.match(line)
            if m:
                s = slug(m.group(1))
                k = seen.get(s, 0)
                seen[s] = k + 1
                found.add(s if k == 0 else f"{s}-{k}")
        anchor_cache[path] = found
    return anchor_cache[path]


def check_links(md, plugin_dir, files, dirs):
    with open(md, encoding="utf-8") as f:
        text = f.read()
    for n, line in lines_outside_code(text):
        stripped = INLINE_CODE.sub("", line)
        targets = LINK.findall(stripped)
        m = REFDEF.match(stripped)
        if m:
            targets.append(m.group(1))
        for t in targets:
            where = f"{md}:{n}"
            m = REPO_URL.match(t)
            if m:
                path, frag = m.group(1).rstrip("/"), m.group(2)
                if path not in files and path not in dirs:
                    err(where, f"{t}: {path} isn't in the repository")
                elif frag and path.endswith(".md") and path in files and frag not in anchors(path):
                    err(where, f"{t}: no heading #{frag} in {path}")
                continue
            if SCHEME.match(t) or t.startswith("//"):
                continue
            path, _, frag = t.partition("#")
            if not path:
                dest = md
            else:
                dest = os.path.normpath(os.path.join(os.path.dirname(md), path))
            if os.path.relpath(dest, plugin_dir).startswith(".."):
                err(where, f"{t}: leaves the plugin; an installed plugin has only its own directory (link to GitHub instead)")
            elif not os.path.exists(dest):
                err(where, f"{t}: {dest} does not exist")
            elif frag and dest.endswith(".md") and frag not in anchors(dest):
                err(where, f"{t}: no heading #{frag} in {dest}")


def frontmatter(path):
    """(fields, body) of a SKILL.md, or None when it has no frontmatter on its first line."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    lines = text.split("\n")
    if not lines or lines[0].rstrip() != "---":
        return None
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].rstrip() == "---")
    except StopIteration:
        err(path, "frontmatter has no closing ---")
        return {}, ""
    fields = {}
    for n, line in enumerate(lines[1:end], 2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):(?:\s+(.*))?$", line)
        if not m:
            err(f"{path}:{n}", "expected `key: value` on one line")
            continue
        key, value = m.group(1), (m.group(2) or "").strip()
        if key in fields:
            err(f"{path}:{n}", f"{key} given twice")
        if value[:1] in ("'", '"'):
            if len(value) < 2 or value[-1] != value[0]:
                err(f"{path}:{n}", f"{key}: unterminated quote")
            value = value[1:-1]
        elif value and (": " in value or " #" in value or value[0] in "[]{},&*!|>%@`" or value.endswith(":")):
            err(f"{path}:{n}", f"{key}: quote this value: plain YAML would read it differently")
        fields[key] = value
    return fields, "\n".join(lines[end + 1:])


def check_skill(skill_dir):
    name = os.path.basename(skill_dir)
    path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(path):
        err(skill_dir, "no SKILL.md")
        return
    fm = frontmatter(path)
    if fm is None:
        err(path, "no frontmatter: the first line must be ---")
        return
    fields, body = fm
    for k in sorted(set(fields) - SKILL_KEYS):
        err(path, f"frontmatter field {k!r} isn't in the Agent Skills spec ({', '.join(sorted(SKILL_KEYS))})")
    if fields.get("name") != name:
        err(path, f"name {fields.get('name')!r} isn't the directory's, {name!r}")
    if not KEBAB.match(name) or len(name) > 64:
        err(path, f"name {name!r}: lowercase letters, digits and single hyphens, at most 64 characters")
    desc = fields.get("description", "")
    if not desc:
        err(path, "no description: it is how Claude knows when to use the skill")
    elif len(desc) > 1024:
        err(path, f"description is {len(desc)} characters; at most 1024")
    if "<" in desc or ">" in desc:
        err(path, "description has angle brackets, shown as &lt; and &gt;; use [brackets]")
    if not body.strip():
        err(path, "no instructions after the frontmatter")


def main():
    files, dirs = tracked()
    market_path = ".claude-plugin/marketplace.json"
    market = load_json(market_path)
    if market is None:
        return
    for k in sorted(set(market) - MARKETPLACE_KEYS):
        err(market_path, f"unknown field {k!r}")
    if not isinstance(market.get("name"), str) or not ID.match(market["name"]) or ".." in market["name"]:
        err(market_path, "name: letters, digits, '.', '_' and '-', starting with a letter or digit")
    if not isinstance(market.get("owner"), dict) or not market["owner"].get("name"):
        err(market_path, "owner.name is required")
    if not market.get("description"):
        err(market_path, "no description")
    plugins = market.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        err(market_path, "plugins: a non-empty list is required")
        plugins = []
    names = set()
    for i, entry in enumerate(plugins):
        where = f"{market_path}: plugins[{i}]"
        if not isinstance(entry, dict):
            err(where, "not an object")
            continue
        for k in sorted(set(entry) - ENTRY_KEYS):
            err(where, f"unknown field {k!r}")
        pname = entry.get("name")
        if not isinstance(pname, str) or not ID.match(pname):
            err(where, f"name {pname!r}: letters, digits, '.', '_' and '-', starting with a letter or digit")
            continue
        if pname in names:
            err(where, f"plugin {pname!r} listed twice")
        names.add(pname)
        if not entry.get("description"):
            err(where, "no description")
        src = entry.get("source")
        if not isinstance(src, str) or not src.startswith("./") or ".." in src.split("/"):
            err(where, f"source {src!r}: a './' path inside the repository, without '..'")
            continue
        pdir = os.path.normpath(src)
        if pdir not in dirs:
            err(where, f"source {src!r} isn't a tracked directory")
            continue
        manifest_path = os.path.join(pdir, ".claude-plugin", "plugin.json")
        manifest = load_json(manifest_path)
        if manifest is None:
            continue
        for k in sorted(set(manifest) - PLUGIN_KEYS):
            err(manifest_path, f"unknown field {k!r}")
        if manifest.get("name") != pname:
            err(manifest_path, f"name {manifest.get('name')!r} isn't the marketplace entry's, {pname!r}")
        if not isinstance(manifest.get("name"), str) or not KEBAB.match(manifest["name"]):
            err(manifest_path, "name: kebab-case")
        if not manifest.get("description"):
            err(manifest_path, "no description")
        for k in ("homepage", "repository"):
            m = REPO_URL.match(str(manifest.get(k, "")))
            if m and m.group(1).rstrip("/") not in files | dirs:
                err(manifest_path, f"{k}: {m.group(1)} isn't in the repository")
        skills_dir = os.path.join(pdir, "skills")
        skills = sorted(d for d in dirs if os.path.dirname(d) == skills_dir)
        if not skills:
            err(pdir, "no skills under skills/")
        for d in skills:
            check_skill(d)
        for f in sorted(f for f in files if f.startswith(pdir + "/") and f.endswith(".md")):
            check_links(f, pdir, files, dirs)
        print(f"plugin {pname}: {len(skills)} skills ({', '.join(os.path.basename(d) for d in skills)})")


main()
for e in errors:
    print(e)
if errors:
    print(f"{len(errors)} problem(s) in the plugin", file=sys.stderr)
    sys.exit(1)

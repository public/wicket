#!/usr/bin/env python3
"""Dependency cooldown (design §2, principle 21): no package version younger than MIN_DAYS enters a lockfile.

    ci/dep-age.py [--base REV] [--min-days N] [--exceptions FILE]

Compares every Cargo.lock and package-lock.json in the repository (outside experiments/, refs/ and
third_party/), and every VENDOR.toml (a package committed as files, as lit-html is in the console),
with the same file at REV (default origin/main). Each crates.io or npm package version
that the change adds must have been published at least MIN_DAYS (default 7) ago, by the registry's own
publish time. A younger one fails the check unless ci/dep-age-exceptions.toml lists it, with the
advisory that makes it urgent and the reason: the policy's one exception, a fix for a serious,
actively exploited vulnerability that can't wait.

Locked installs (`cargo --locked`, `npm ci`) never resolve, so the package managers' own minimum-age
settings (.cargo/config.toml, .npmrc) can't guard them: this check is where a young version is caught,
whoever or whatever changed the lockfile. Any registry error fails it.
"""
import argparse
import datetime as dt
import json
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import PurePosixPath

CRATES_IO = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")
NPM_REGISTRY = "https://registry.npmjs.org/"
SKIP_DIRS = ("experiments/", "refs/", "third_party/")
USER_AGENT = "wicket-ci-dep-age (https://github.com/public/wicket)"


def cargo_packages(text: str) -> set[tuple[str, str, str]]:
    """(ecosystem, name, version) of each crates.io package in a Cargo.lock."""
    if not text:
        return set()
    lock = tomllib.loads(text)
    return {
        ("crates.io", p["name"], p["version"])
        for p in lock.get("package", [])
        if p.get("source", "").startswith(CRATES_IO)
    }


def npm_packages(text: str) -> set[tuple[str, str, str]]:
    """(ecosystem, name, version) of each registry.npmjs.org package in a package-lock.json (v2/v3)."""
    if not text:
        return set()
    lock = json.loads(text)
    out = set()
    for key, p in lock.get("packages", {}).items():
        if not key or p.get("link") or not str(p.get("resolved", "")).startswith(NPM_REGISTRY):
            continue
        name = p.get("name") or key.rsplit("node_modules/", 1)[-1]
        out.add(("npm", name, p["version"]))
    return out


def vendored_packages(text: str) -> set[tuple[str, str, str]]:
    """(ecosystem, name, version) of a vendored package's VENDOR.toml (#574: lit-html, committed as files)."""
    if not text:
        return set()
    v = tomllib.loads(text)
    eco = {"npm": "npm", "crates.io": "crates.io"}.get(v.get("ecosystem", ""))
    if not eco or not v.get("name") or not v.get("version"):
        raise ValueError("VENDOR.toml needs ecosystem (npm or crates.io), name and version")
    return {(eco, v["name"], v["version"])}


PARSERS = {"Cargo.lock": cargo_packages, "package-lock.json": npm_packages, "VENDOR.toml": vendored_packages}


def lockfiles() -> list[str]:
    files = subprocess.run(
        ["git", "ls-files", "--", "*Cargo.lock", "*package-lock.json", "*VENDOR.toml"], check=True, capture_output=True, text=True
    ).stdout.split()
    return [f for f in files if not f.startswith(SKIP_DIRS)]


def show(rev: str, path: str) -> str:
    r = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def added(base: str) -> set[tuple[str, str, str]]:
    """Package versions in the working tree's lockfiles that no lockfile at `base` has."""
    head_pkgs, base_pkgs = set(), set()
    for f in lockfiles():
        parse = PARSERS[PurePosixPath(f).name]
        with open(f, encoding="utf-8") as fh:
            head_pkgs |= parse(fh.read())
    # Every lockfile at base, including ones the change removed or renamed.
    base_files = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", base], check=True, capture_output=True, text=True
    ).stdout.split()
    for f in base_files:
        name = PurePosixPath(f).name
        if name in PARSERS and not f.startswith(SKIP_DIRS):
            base_pkgs |= PARSERS[name](show(base, f))
    return head_pkgs - base_pkgs


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:
                raise
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"{url}: no answer after 4 tries")


_npm_docs: dict[str, dict] = {}


def published(ecosystem: str, name: str, version: str) -> dt.datetime:
    """When the registry says this version was published (UTC)."""
    if ecosystem == "crates.io":
        q = urllib.parse.quote
        doc = _get(f"https://crates.io/api/v1/crates/{q(name)}/{q(version)}")
        stamp = doc["version"]["created_at"]
        time.sleep(1)  # crates.io's crawler policy: at most one request a second.
    else:
        if name not in _npm_docs:
            _npm_docs[name] = _get(NPM_REGISTRY + name.replace("/", "%2f"))
        stamp = _npm_docs[name]["time"][version]
    return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def load_exceptions(path: str) -> dict[tuple[str, str, str], dict]:
    try:
        with open(path, "rb") as fh:
            entries = tomllib.load(fh).get("exception", [])
    except FileNotFoundError:
        return {}
    out = {}
    for e in entries:
        missing = [k for k in ("ecosystem", "name", "version", "advisory", "reason") if not str(e.get(k, "")).strip()]
        if missing:
            raise SystemExit(f"{path}: an exception lacks {', '.join(missing)}: {e}")
        if e["ecosystem"] not in ("crates.io", "npm"):
            raise SystemExit(f"{path}: unknown ecosystem {e['ecosystem']!r} (crates.io or npm)")
        out[(e["ecosystem"], e["name"], e["version"])] = e
    return out


def check(new, min_days, exceptions, published_at, now) -> tuple[list[str], list[str]]:
    """The failures (young and not excepted) and notes (young and excepted), as lines."""
    failures, notes = [], []
    limit = dt.timedelta(days=min_days)
    for pkg in sorted(new):
        age = now - published_at(*pkg)
        if age >= limit:
            continue
        eco, name, version = pkg
        line = f"{eco} {name} {version}: published {age.days} d {age.seconds // 3600} h ago (minimum {min_days} d)"
        if pkg in exceptions:
            notes.append(f"{line}; allowed: {exceptions[pkg]['advisory']} ({exceptions[pkg]['reason']})")
        else:
            failures.append(line)
    return failures, notes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--min-days", type=int, default=7)
    ap.add_argument("--exceptions", default="ci/dep-age-exceptions.toml")
    a = ap.parse_args()
    exceptions = load_exceptions(a.exceptions)
    new = added(a.base)
    print(f"{len(new)} package version(s) added since {a.base}")
    failures, notes = check(new, a.min_days, exceptions, published, dt.datetime.now(dt.timezone.utc))
    for n in notes:
        print(f"exception: {n}")
    for f in failures:
        print(f"::error title=dependency younger than {a.min_days} days::{f}")
    if failures:
        print(
            f"\n{len(failures)} version(s) younger than {a.min_days} days. Wait, pin an older version, or, for a fix "
            f"to a serious, actively exploited vulnerability, add it to {a.exceptions} with the advisory and reason."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

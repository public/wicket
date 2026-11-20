#!/usr/bin/env python3
"""Vendored files are exactly what their VENDOR.toml records (#574).

    ci/vendor-check.py [ROOT]

Finds every VENDOR.toml under ROOT (default: the repository, outside experiments/, refs/ and
third_party/), and checks that each file it lists has the sha256 it records, and that its directory
holds nothing it doesn't list. A vendored file is changed only by the script that wrote it (for
lit-html, ci/vendor-lit.sh), which records the new hashes; an edit by hand fails here. The versions'
age is ci/dep-age.py's.
"""
import hashlib
import sys
import tomllib
from pathlib import Path

SKIP_DIRS = ("experiments", "refs", "third_party", "target", "node_modules", ".git")


def manifests(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("VENDOR.toml") if not any(part in SKIP_DIRS for part in p.relative_to(root).parts))


def check(manifest: Path) -> list[str]:
    """What is wrong with one vendored directory: an empty list when nothing is."""
    d = manifest.parent
    spec = tomllib.loads(manifest.read_text())
    listed = spec.get("files") or {}
    errors = []
    for k in ("name", "version", "ecosystem"):
        if not spec.get(k):
            errors.append(f"{manifest}: no `{k}`")
    if not listed:
        errors.append(f"{manifest}: lists no files")
    for rel, want in listed.items():
        f = d / rel
        if not f.is_file():
            errors.append(f"{f}: listed in {manifest.name}, missing")
        elif (got := hashlib.sha256(f.read_bytes()).hexdigest()) != want:
            errors.append(f"{f}: sha256 {got}, {manifest.name} records {want}")
    for f in sorted(p for p in d.rglob("*") if p.is_file()):
        rel = f.relative_to(d).as_posix()
        if rel != "VENDOR.toml" and rel not in listed:
            errors.append(f"{f}: not listed in {manifest.name}")
    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    found = manifests(root)
    errors = [e for m in found for e in check(m)]
    for e in errors:
        print(f"::error title=vendored file::{e}")
    print(f"{len(found)} vendored package(s), {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

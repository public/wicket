#!/usr/bin/env python3
"""Fails if a tracked file looks like it holds a secret or details of a particular machine.

This repository is public. gitleaks (in CI) covers the long tail of token formats; this check adds
wicket's own rules:
- token shapes wicket handles (Anthropic, GitHub, AWS, Slack, private keys), in plain text;
- home-directory paths of a real machine (/home/<user>/, /Users/<user>/);
- public IPv4 addresses, except well-known ones that wicket's code and docs name on purpose.

Usage: ci/check-public.py [FILE...]   (default: every file git tracks)
"""

import ipaddress
import re
import subprocess
import sys

TOKENS = {
    "Anthropic key or token": re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}"),
    "GitHub token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    "AWS access key id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
# A path, not part of a URL: "/home" must not follow a host or path character.
HOME = re.compile(r"(?<![\w.~/-])/(home|Users)/(?!(?:user|you|me|runner|wicket|USER)/|<)[a-z][a-z0-9_-]*/")
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

# Public addresses named on purpose: metadata endpoints, a public resolver, Azure's wire server.
KNOWN_IPS = {"8.8.8.8", "1.1.1.1", "168.63.129.16", "100.100.100.200"}
# Placeholders that only look like tokens (wicket's own, and other projects' in research notes).
PLACEHOLDER = re.compile(r"placeholder|example|x{6,}|…", re.I)
# Files that describe the patterns themselves, and third-party code vendored as is.
SKIP = {"ci/check-public.py"}
SKIP_DIRS = re.compile(r"^(experiments/[^/]+/vendor/|third_party/)")


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout
    return [p for p in out.decode().split("\0") if p]


def problems(path, text):
    for n, line in enumerate(text.splitlines(), 1):
        for what, rx in TOKENS.items():
            for m in rx.finditer(line):
                if not PLACEHOLDER.search(line[m.start() : m.end() + 40]):
                    yield n, what
        if HOME.search(line):
            yield n, "home-directory path of a real machine"
        for m in IPV4.finditer(line):
            ip = m.group(1)
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue  # e.g. a version number like 1.2.300.4
            if addr.is_global and ip not in KNOWN_IPS:
                yield n, f"public IP address {ip}"


def main():
    files = sys.argv[1:] or tracked()
    bad = 0
    for path in files:
        if path in SKIP or SKIP_DIRS.match(path):
            continue
        try:
            with open(path, "rb") as f:
                data = f.read()
        except (IsADirectoryError, FileNotFoundError):
            continue
        if b"\0" in data[:8192]:
            continue  # binary
        for n, what in problems(path, data.decode("utf-8", "replace")):
            print(f"{path}:{n}: {what}")
            bad += 1
    if bad:
        print(f"\n{bad} problem(s). Replace real values with placeholders (docs: 203.0.113.0/24, /home/you/).")
        return 1
    print(f"checked {len(files)} files: no secrets or machine details")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
# Vendors lit-html's published browser modules into the console (#574): fetches the npm tarball for
# VERSION, checks it against the registry's own sha512 (`dist.integrity`), and copies the four modules
# the console imports, unchanged, with lit-html's LICENSE, into crates/wicket-cli/src/serve/static/
# vendor/lit-html/. It writes VENDOR.toml there: the version, the tarball and its integrity, and each
# file's sha256, which ci/vendor-check.py checks on every change. ci/dep-age.py reads the version too:
# it must be at least 7 days old, like any dependency.
#
#   ci/vendor-lit.sh VERSION        (needs curl, tar, openssl and node or python3)
set -euo pipefail
version=${1:?usage: ci/vendor-lit.sh VERSION}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dest=$root/crates/wicket-cli/src/serve/static/vendor/lit-html
files=(lit-html.js directive.js directive-helpers.js directives/repeat.js)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

meta=$(curl -fsS "https://registry.npmjs.org/lit-html/$version")
tarball=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["dist"]["tarball"])' <<<"$meta")
integrity=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["dist"]["integrity"])' <<<"$meta")
curl -fsS -o "$tmp/lit.tgz" "$tarball"
got="sha512-$(openssl dgst -sha512 -binary "$tmp/lit.tgz" | base64 -w0)"
[ "$got" = "$integrity" ] || { echo "lit-html $version: the tarball is $got, the registry says $integrity" >&2; exit 1; }
tar xzf "$tmp/lit.tgz" -C "$tmp"

rm -rf "$dest" && mkdir -p "$dest/directives"
cp "$tmp/package/LICENSE" "$dest/LICENSE"
{
  echo "# lit-html's published browser modules, unchanged (#574), written by ci/vendor-lit.sh. Checked by"
  echo "# ci/vendor-check.py (each file's sha256) and ci/dep-age.py (the version's age). Don't edit by hand."
  echo "ecosystem = \"npm\""
  echo "name = \"lit-html\""
  echo "version = \"$version\""
  echo "license = \"BSD-3-Clause\""
  echo "tarball = \"$tarball\""
  echo "integrity = \"$integrity\""
  echo
  echo "[files]"
  for f in LICENSE "${files[@]}"; do
    [ "$f" = LICENSE ] || cp "$tmp/package/$f" "$dest/$f"
    echo "\"$f\" = \"$(sha256sum "$dest/$f" | cut -d' ' -f1)\""
  done
} >"$dest/VENDOR.toml"
echo "vendored lit-html $version into ${dest#"$root"/}"

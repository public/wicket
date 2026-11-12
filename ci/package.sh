#!/usr/bin/env bash
# The release archive (.github/workflows/release.yml): the binary, deploy/ and images/, so that
# `sudo <archive>/deploy/install.sh` needs nothing else. Prints the archive's path.
#   ci/package.sh BINARY OUTDIR
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin=$1
out=$2
v=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml")
[ -n "$v" ] || { echo "no workspace version" >&2; exit 1; }
[ "$("$bin" --version)" = "wicket $v" ] || { echo "$bin is $("$bin" --version), not wicket $v" >&2; exit 1; }
d=wicket-$v-x86_64-linux
rm -rf "${out:?}/$d"
mkdir -p "$out/$d/deploy"
cp "$bin" "$out/$d/wicket"
cp -r "$repo/deploy/install.sh" "$repo/deploy/systemd" "$out/$d/deploy/"
cp -r "$repo/images" "$repo/README.md" "$repo/LICENSE" "$out/$d/"
tar -C "$out" -czf "$out/$d.tar.gz" "$d"
rm -rf "${out:?}/$d"
(cd "$out" && sha256sum "$d.tar.gz" >"$d.tar.gz.sha256")
echo "$out/$d.tar.gz"

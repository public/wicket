#!/usr/bin/env bash
# The release archive (.github/workflows/release.yml, build.yml): the binary, deploy/install.sh and
# deploy/systemd/, images/, examples/, README.md and LICENSE, so that `sudo <archive>/deploy/install.sh`
# needs nothing else. docs/ is not in it. Prints the archive's path.
#   ci/package.sh BINARY OUTDIR [SUFFIX]
# SUFFIX (e.g. a commit's first 12 hex digits, build.yml) goes in the archive's name after the
# version: every build of main is the same version. The archive is reproducible: entries sorted, owned
# by 0:0, dated SOURCE_DATE_EPOCH (default: the last commit's time), gzip without a name or time.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin=$1
out=$2
suffix=${3:-}
v=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml")
[ -n "$v" ] || { echo "no workspace version" >&2; exit 1; }
[ "$("$bin" --version)" = "wicket $v" ] || { echo "$bin is $("$bin" --version), not wicket $v" >&2; exit 1; }
case "$suffix" in *[!a-z0-9]*) echo "suffix: lowercase letters and digits only" >&2; exit 1 ;; esac
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct 2>/dev/null || echo 0)}
d=wicket-$v-x86_64-linux
name=wicket-$v${suffix:+-$suffix}-x86_64-linux
rm -rf "${out:?}/$d"
mkdir -p "$out/$d/deploy"
cp "$bin" "$out/$d/wicket"
cp -r "$repo/deploy/install.sh" "$repo/deploy/systemd" "$out/$d/deploy/"
cp -r "$repo/images" "$repo/examples" "$repo/README.md" "$repo/LICENSE" "$out/$d/"
# Modes as git has them (not this checkout's umask): directories and executables 755, the rest 644.
find "$out/$d" -type d -exec chmod 755 {} +
find "$out/$d" -type f -perm -u+x -exec chmod 755 {} +
find "$out/$d" -type f ! -perm -u+x -exec chmod 644 {} +
tar -C "$out" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --format=gnu -cf - "$d" | gzip -9 -n >"$out/$name.tar.gz"
rm -rf "${out:?}/$d"
(cd "$out" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
echo "$out/$name.tar.gz"

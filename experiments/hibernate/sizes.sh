#!/usr/bin/env bash
# Bundle cost for realistic trees: raw bytes, files, tar+zstd bytes, pack, unpack and verify time,
# through bundle.sh and a directory store.  sizes.sh NAME=DIR...
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
printf '%-14s %12s %8s %12s %7s %8s %8s %8s %8s\n' tree raw_bytes files stored ratio pack_s upload_s unpack_s verify_s
for nd in "$@"; do
  name=${nd%%=*} dir=${nd#*=}
  mkdir -p "$work/r"; ln -sfn "$dir" "$work/r/$name"
  "$here/bundle.sh" push "$work/store" sz 1 "$work/r" "$name/" 2> "$work/push.t" > /dev/null
  "$here/bundle.sh" pull "$work/store" sz 1 "$work/out" 2> "$work/pull.t" > /dev/null
  t() { awk -v k="$1:" '$2 ~ "^"k {print $3}' "$work/$2"; }
  python3 - "$work/store/a/sz/m/1" "$(find "$dir/" -type f | wc -l)" "$name" "$(t pack push.t)" "$(t upload push.t)" "$(t unpack pull.t)" "$(t verify pull.t)" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))["trees"][0]
print(f"{sys.argv[3]:<14} {m['raw']:>12} {sys.argv[2]:>8} {m['size']:>12} {m['raw']/m['size']:>7.1f} {float(sys.argv[4]):>8.2f} {float(sys.argv[5]):>8.2f} {float(sys.argv[6]):>8.2f} {float(sys.argv[7]):>8.2f}")
PY
  rm -rf "$work/store" "$work/out" "$work/r"
done

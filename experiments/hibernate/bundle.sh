#!/usr/bin/env bash
# H0 state bundle: one tar+zstd blob per tree, content-addressed in a directory-backed object store,
# plus a manifest written put-if-absent at m/<seq>. Encryption and signing are left out (they add a
# streaming AEAD pass; see RESULTS.md); everything else is the H0 shape.
#
#   bundle.sh push STORE AGENT SEQ ROOT TREE...    trees are directories under ROOT, e.g. state/claude/projects
#   bundle.sh pull STORE AGENT SEQ DEST            unpacks every tree under DEST and checks its digest
#
# Timings go to stderr as "time <step> <seconds>" lines.
set -euo pipefail
ZSTD=${ZSTD:-"zstd -q -3 -T2"}
now() { date +%s.%N; }
lap() { echo "time $1 $(echo "$(now) - $2" | bc)" >&2; }
# Digest over (path, type, mode, file size, link target) and every file's content: checked after unpack.
# Directory sizes are left out: they depend on the filesystem, not on the tree.
tree_digest() { (cd "$1" && { find . \( -type f -printf '%p f %m %s\n' \) -o \( -type l -printf '%p l %l\n' \) -o -printf '%p %y %m\n' | LC_ALL=C sort; find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum; } | sha256sum | cut -d' ' -f1); }

cmd=$1 store=$2 agent=$3 seq=$4; shift 4
a=$store/a/$agent
mkdir -p "$a/p" "$a/m"
case $cmd in
push)
  root=$1; shift
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  entries=()
  for tree in "$@"; do
    t0=$(now); d=$(tree_digest "$root/$tree"); lap "digest:$tree" "$t0"
    t0=$(now); tar -C "$root/$tree" -cf - . | $ZSTD -f -o "$tmp/blob"; lap "pack:$tree" "$t0"
    h=$(sha256sum "$tmp/blob" | cut -d' ' -f1); sz=$(stat -c %s "$tmp/blob")
    raw=$(du -sb "$root/$tree" | cut -f1)
    t0=$(now)
    # Content-addressed and put-if-absent: an identical blob is not uploaded twice.
    [ -e "$a/p/$h" ] || { cp "$tmp/blob" "$a/p/$h.part" && mv -n "$a/p/$h.part" "$a/p/$h"; }
    lap "upload:$tree" "$t0"
    entries+=("{\"mount\":\"$tree\",\"blob\":\"$h\",\"size\":$sz,\"raw\":$raw,\"tree_digest\":\"$d\"}")
  done
  printf '{"agent":"%s","seq":%s,"taken_at":"%s","trees":[%s]}\n' "$agent" "$seq" "$(date -u +%FT%TZ)" "$(IFS=,; echo "${entries[*]}")" > "$tmp/m"
  # The manifest key is written once: a second writer for the same seq loses (S3: If-None-Match: *).
  if ln "$tmp/m" "$a/m/$seq" 2>/dev/null; then echo "manifest $a/m/$seq"; else echo "manifest seq $seq already exists: refused" >&2; exit 3; fi
  ;;
pull)
  dest=$1; mkdir -p "$dest"
  m=$a/m/$seq
  python3 -c 'import json,sys; [print(t["mount"],t["blob"],t["tree_digest"]) for t in json.load(open(sys.argv[1]))["trees"]]' "$m" |
  while read -r tree h d; do
    t0=$(now); cp "$a/p/$h" "$dest/.blob"; lap "download:$tree" "$t0"
    t0=$(now); [ "$(sha256sum "$dest/.blob" | cut -d' ' -f1)" = "$h" ] || { echo "blob digest mismatch: $tree" >&2; exit 4; }
    mkdir -p "$dest/$tree"; zstd -q -d -c "$dest/.blob" | tar -C "$dest/$tree" -xf -; rm "$dest/.blob"; lap "unpack:$tree" "$t0"
    t0=$(now); got=$(tree_digest "$dest/$tree"); lap "verify:$tree" "$t0"
    [ "$got" = "$d" ] || { echo "tree digest mismatch: $tree" >&2; exit 5; }
    echo "ok $tree"
  done
  ;;
*) echo "usage: bundle.sh push|pull ..." >&2; exit 2 ;;
esac

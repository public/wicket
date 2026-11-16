#!/bin/sh
# Tests ci/pr-has-label.sh against a stand-in `gh` (run: ci/pr-has-label_test.sh).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
# The stand-in answers as `gh pr view N --repo R --json labels --jq '.labels[].name'` does: one
# name per line, from $FAKE_LABELS; it fails as gh does when $FAKE_FAIL is set.
cat >"$bin/gh" <<'GH'
#!/bin/sh
[ "$*" = "pr view 241 --repo public/wicket --json labels --jq .labels[].name" ] || { echo "gh: unexpected args: $*" >&2; exit 9; }
[ -z "${FAKE_FAIL:-}" ] || { echo "HTTP 403: Resource not accessible by integration" >&2; exit 1; }
printf '%s' "$FAKE_LABELS"
GH
chmod +x "$bin/gh"
fails=0
check() { # want, labels, label, [extra env...]
    want=$1 labels=$2 label=$3
    shift 3
    got=$(rc=0; env PATH="$bin:$PATH" PR=241 GH_REPO=public/wicket FAKE_LABELS="$labels" "$@" "$here/pr-has-label.sh" "$label" 2>/dev/null || rc=$?; echo "exit=$rc")
    if [ "$got" != "$want" ]; then
        echo "FAIL: labels '$labels', label '$label' $*: got '$got', want '$want'"
        fails=$((fails + 1))
    fi
}
nl='
'
check "true${nl}exit=0" "full-ci" full-ci
check "true${nl}exit=0" "bug${nl}full-ci${nl}docs" full-ci
check "false${nl}exit=0" "" full-ci
check "false${nl}exit=0" "full-ci-later${nl}not full-ci" full-ci
check "false${nl}exit=0" "Full-CI" full-ci
check "true${nl}exit=0" "bug${nl}no changelog" "no changelog"
check "false${nl}exit=0" "no changelogs" "no changelog"
check "exit=2" "full-ci" full-ci FAKE_FAIL=1
check "exit=2" "full-ci" full-ci PR=
check "exit=2" "full-ci" full-ci PR=241x
check "exit=2" "full-ci" full-ci GH_REPO=
check "exit=2" "full-ci" ""
[ "$fails" -eq 0 ] && echo "pr-has-label: all cases pass" || exit 1

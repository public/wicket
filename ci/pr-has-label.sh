#!/bin/sh
# Prints `true` if pull request $PR (in $GH_REPO) has label LABEL now, else `false` (#246): its
# labels as the API has them when this runs, not as the event's payload had them. A run that a
# later event cancelled or superseded would otherwise decide from labels older than its own start.
# Exits 2, saying why on stderr, if the labels can't be read: the caller decides what that means.
#
# Usage: PR=<number> GH_REPO=<owner/repo> GH_TOKEN=<token> ci/pr-has-label.sh LABEL
# (the token needs `pull-requests: read`; `gh` is on GitHub's runners)
set -eu
[ $# -eq 1 ] && [ -n "$1" ] || { echo "usage: ci/pr-has-label.sh LABEL" >&2; exit 2; }
case "${PR:-}" in
'' | *[!0-9]*) echo "pr-has-label: PR must be a pull request number (got '${PR:-}')" >&2; exit 2 ;;
esac
[ -n "${GH_REPO:-}" ] || { echo "pr-has-label: GH_REPO is not set" >&2; exit 2; }
if ! names=$(gh pr view "$PR" --repo "$GH_REPO" --json labels --jq '.labels[].name'); then
    echo "pr-has-label: couldn't read the labels of #$PR in $GH_REPO" >&2
    exit 2
fi
if printf '%s\n' "$names" | grep -Fxq -- "$1"; then echo true; else echo false; fi

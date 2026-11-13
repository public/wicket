#!/usr/bin/env bash
# Writes docs/reference/cli.md from the help that clap prints for every wicket command, so the CLI
# reference is the code's own description of itself. With --check, fails if the page differs from
# what the binary prints (run it after changing a command, an argument or its doc comment).
#
# Usage: WICKET=target/debug/wicket ci/gen-cli-reference.sh [--check]
#
# Hidden commands (`attach`, `node attach`, `self describe`, `self health`) are internal: they are
# what wicket runs itself, and are left out as clap leaves them out of --help.
set -euo pipefail
cd "$(dirname "$0")/.."
WICKET=${WICKET:-target/debug/wicket}
out=docs/reference/cli.md
check=0
[ "${1:-}" = --check ] && check=1

# Subcommand names listed in a help text's "Commands:" section, except `help`.
subcommands() {
    awk '/^Commands:/ { on = 1; next } on && /^$/ { exit } on && /^  [a-z]/ { print $1 }' | grep -vx help || true
}

# One section per command, depth-first: a heading, then its help in a code block.
section() {
    local depth=$1
    shift
    local hashes
    hashes=$(printf '#%.0s' $(seq "$depth"))
    local help
    help=$("$WICKET" "$@" --help)
    printf '%s `wicket %s`\n\n```text\n%s\n```\n\n' "$hashes" "$*" "$help"
    local sub
    for sub in $(subcommands <<<"$help"); do
        section $((depth + 1)) "$@" "$sub"
    done
}

# The list at the top: every command, indented by depth, linking to its section.
toc() {
    local indent=$1
    shift
    local sub help
    help=$("$WICKET" "$@" --help)
    for sub in $(subcommands <<<"$help"); do
        local name="$* $sub"
        name=${name# }
        local anchor
        anchor=$(printf 'wicket %s' "$name" | tr ' ' '-')
        printf '%s- [`wicket %s`](#%s)\n' "$indent" "$name" "$anchor"
        toc "$indent  " "$@" "$sub"
    done
}

page() {
    cat <<'EOF'
# Command line

Every `wicket` command and flag, as `wicket <command> --help` prints it. This page is generated
from the code by `ci/gen-cli-reference.sh`, and CI checks that it matches: edit the commands' doc
comments in `crates/wicket-cli/src/main.rs` (and `place.rs`), not this page.

On an installed host most commands go through the daemon, which allows each one for some callers
only: [the daemon](daemon.md#who-may-run-what) lists which commands need `sudo`. Durations are
humantime strings (`90s`, `10m`, `1h`).

EOF
    toc ""
    printf '\n'
    printf '## `wicket`\n\n```text\n%s\n```\n\n' "$("$WICKET" --help)"
    local sub
    for sub in $("$WICKET" --help | subcommands); do
        section 2 "$sub"
    done
}

if [ "$check" = 1 ]; then
    if ! diff -u "$out" <(page | sed -e '$ { /^$/d }'); then
        echo "$out is out of date: run WICKET=$WICKET ci/gen-cli-reference.sh" >&2
        exit 1
    fi
else
    page | sed -e '$ { /^$/d }' >"$out"
    echo "wrote $out"
fi

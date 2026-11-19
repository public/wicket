#!/usr/bin/env bash
# Writes docs/reference/cli.md from the help that clap prints for every wicket command, so the CLI
# reference is the code's own description of itself. Run it after changing a command, an argument or
# its doc comment. A wicket-cli unit test (src/cli_reference.rs) checks the page against every
# command's help, so CI needs no build of its own for it; --check compares with the binary.
#
# Usage: WICKET=target/debug/wicket ci/gen-cli-reference.sh [--check]
#
# Hidden commands (`attach`, `node attach`, `self describe`, `self health`, `self units`) are internal: they are
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
comments in `crates/wicket-cli/src/main.rs` (and `cmd/` and `nodecreate.rs`), not this page.

On an installed host most commands go through the daemon, which allows each one for some callers
only: [the daemon](daemon.md#who-may-run-what) lists which commands need `sudo`. Durations are
numbers with units (`90s`, `10m`, `1h`, `1h 30m`; the units in [the manifest
reference](manifest.md)).

EOF
    toc ""
    printf '\n'
    printf '## `wicket`\n\n```text\n%s\n```\n\n' "$("$WICKET" --help)"
    local sub
    for sub in $("$WICKET" --help | subcommands); do
        section 2 "$sub"
    done
    cat <<'EOF'
## Exit codes

Every command exits with one of these, through the daemon too, so a script can tell what happened
without reading the message (which goes to stderr, after `Error: `).

| Code | Means | For example |
| --- | --- | --- |
| 0 | Done. | |
| 1 | Failed, for any reason the others don't name. | The ledger can't be opened; a node doesn't answer; the daemon's policy file can't be read; asking for a spend's approval failed; `wicket run` or `wicket wrap` whose box failed (a non-zero exit, out of memory, over a cap) or timed out. |
| 2 | A usage error: the command line is wrong. Nothing was changed. | An unknown flag; `--ttl 5q`; `wicket approve s-…` (a standing ask: `wicket standing approve`). |
| 3 | Refused: wicket won't do it as asked. | The daemon's policy doesn't allow this caller the command; a decision outside the decider's authority; deciding a request that is already decided; terms wider than the request; answering no at `approve`'s or `standing approve`'s confirmation; a spend an operator denied, or over the installation's money limit; a lease that is already ended; a session on a run that isn't running; `self update` of an artifact whose signature doesn't verify. |
| 4 | Not found: what the command names doesn't exist. | `no such request r-…`; no grant, link, lease, run, agent, node, service or identity by that name; no placement decision for the run. |
| 5 | It needs an approval nobody has given yet. | `wicket node create` whose spend no capacity grant covers and no operator decided within `--wait` (or `--wait 0`); `wicket self update` of an artifact no trusted key signed and no operator approved. |
| 75 | Try again shortly: nothing was done. | wicketd is moving to a new build and took no command. |

`wicket wake`, which wicket runs itself, exits 3 when the agent is already being woken or is running.

A command the daemon runs passes its code back through it; one ended by a signal exits 128 + the
signal's number (130 for Ctrl-C), as a shell reports it. If the daemon restarts while a command
runs, the connection drops and the caller exits 1 with "wicketd closed the connection before the
command finished": the command may have done some or all of its work (a run it started goes on), so
look (`wicket top`, `wicket audit`) before running it again.
EOF
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

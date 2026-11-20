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

# Subcommand names listed in a help text's "Commands:" section (in `wicket --help`, its sections by
# area: every heading but Usage, Arguments and Options), except `help`.
subcommands() {
    awk '/^[A-Z][A-Za-z ,]*:$/ { on = ($0 != "Arguments:" && $0 != "Options:"); next }
         on && /^  [a-z]/ { print $1 }' | grep -vx help || true
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

## Output for scripts

The commands that list things take `--json`: `pending`, `top`, `agents`, `links`, `grant list`,
`standing list`, `node list`, `service list` and `audit`. With it, stdout holds one JSON document
and nothing else: a list is an array, `[]` when there is nothing to list, and `top --json` is one
frame, an object. Messages and warnings go to stderr. For the outputs the table below lists, a
field is never renamed or removed, and its meaning doesn't change; new fields may be added, so a
script should ignore fields it doesn't know. A field with nothing in it is `null`, not left out.
`why-here --json`, `zone --json` and `node top --json` print a record as wicket keeps it (the
placement decision, the zone view, the node's status report): JSON, but their shape isn't fixed
yet, and a field with nothing in it may be left out. Times are Unix seconds (`…_at`, `expires_at`, `not_after`), except
`top`'s, which are Unix milliseconds (`…_ms`). What an agent wrote (a reason, a rule, an
attribution) is as it wrote it: shown to a person, it needs the cleaning the text output gives it.

| Output | Fields |
| --- | --- |
| `wicket pending --json`, a request | `kind` (`request`), `id`, `run`, `zone`, `method`, `host`, `path`, `prefix` (the whole path prefix asked for), `risk`, `reason`, `created_at`, `attribution` (who in the box asked, as the agent reported it: untrusted) |
| `wicket pending --json`, a standing ask | `kind` (`standing`), `id`, `run`, `zone`, `principal`, `rule`, `reason`, `created_at` |
| a standing `rule` | `host`, `methods`, `paths`, `allow_dangerous` |
| `wicket links --json` | `id`, `status` (`open`, `closed`), `from_run`, `to_run`, `name`, `host` (the name the connecting box reaches it at), `port`, `by_run`, `basis`, `created_at`, `closed_at`, `close_reason` |
| `wicket grant list --json` | `id`, `state` (`live`, `expired`, `revoked`), `zone`, `run` (null: any run in the zone), `method`, `host`, `path`, `prefix`, `quota` (a quota grant's `resource` and `amount`, money in micro-USD; else null), `uses_left` (null: unlimited, or a quota), `expires_at`, `node`, `request`, `decided_by`, `created_at` |
| `wicket standing list --json` | `id`, `status` (`pending`, `approved`, `denied`, `revoked`), `state` (`status`, or `lapsed` for an approved rule past `expires_at`), `rule`, `for` (`agent`, `zone`, or null while undecided), `principal`, `zone`, `run`, `reason`, `created_at`, `decided_at`, `decided_by`, `expires_at` (null: until revoked), `revoked_at` |
| `wicket node list --json` | `name`, `status` (`active`, `revoked`), `target`, `host_key_fp`, `hosts`, `enrolled_at`, `revoked_at`, `ca` and `identity` (the active certificate's `serial` and `not_after`, or null), `labels` (an object), `taints` (`key` or `key=value`). Left out, as the text shows them: a node's lease, what it holds for runs, and nodes leased but not enrolled (`wicket lease list`, `wicket top --json`) |
| `wicket service list --json` | `name`, `sha256`, `manifest`, `tenant`, `added_by`, `added_at` |
| `wicket audit --json` | `seq`, `ts`, `kind`, `run`, `body` (the record's JSON) |
| `wicket agents --json` | `id`, `name`, `zone`, `state`, `generation`, `run`, `session_id`, `bundle_bytes`, `head`, `restorable`, `note`, `workspace`, `updated_at`, `used` |
| an agent's `used` | `requests`, `input_tokens`, `output_tokens`, `secs` |
| `wicket top --json` | `now_ms`, `nodes`, `runs`, `pending` (how many requests wait), `leases` |
| `wicket top --json`, each of `nodes` | `name`, `status`, `connected` (null: no run's supervisor has talked to it), `since_ms`, `boxes`, `capacity` (null: not reported), `health` (its latest report; null: none yet) |
| `wicket top --json`, a node's `capacity` | `vcpus`, `memory_mib`, `used_vcpus`, `used_memory_mib`, `boxes`, `room_mib` (the memory a new box may have now; null from an older node), `full` (it starts no box now) |
| `wicket top --json`, a node's `health` | `at_ms`, `disk` (`total_bytes`, `avail_bytes`, `reserve_bytes`), `memory` (`total_mib`, `available_mib`, `committed_mib`), `feed_mode`, `feed_fresh_until_ms`, `oom_kills`, `last_oom` (`at_ms` and `what`, or null), `persist_failures`, `last_persist_failure` (likewise), `ca_not_after_ms` (null: no CA), `orphaned` (runs' directories kept with no box: each `run` and `bytes`) |
| `wicket top --json`, each of `runs` | `run`, `node`, `agent`, `zone`, `status`, `started_ms`, `spent` (null: not reported yet), `connected` |
| `wicket top --json`, a run's `spent` | `requests`, `input_tokens`, `cache_read_tokens`, `cache_creation_tokens`, `output_tokens` |
| `wicket top --json`, each of `leases` | `id`, `provider`, `run`, `node`, `not_after_ms`, `reserved_micro_usd` |

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

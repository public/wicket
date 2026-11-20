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
| `wicket pending --json`, an ask for a public name | `kind` (`name`), `id`, `run` (the asking run), `zone`, `principal`, `label`, `port` (the box's own), `service`, `scope` (`run`, `standing`), `reason` (the agent's, prefixed `asked by the agent: `), `created_at` |
| a standing `rule` | `host`, `methods`, `paths`, `allow_dangerous` |
| `wicket links --json` | `id`, `status` (`open`, `closed`), `from_run`, `to_run`, `name`, `host` (the name the connecting box reaches it at), `port`, `by_run`, `basis`, `created_at`, `closed_at`, `close_reason` |
| `wicket grant list --json` | `id`, `state` (`live`, `expired`, `revoked`), `zone`, `run` (null: any run in the zone), `method`, `host`, `path`, `prefix`, `quota` (a quota grant's `resource` and `amount`, money in micro-USD; else null), `uses_left` (null: unlimited, or a quota), `expires_at`, `node`, `request`, `decided_by`, `created_at` |
| `wicket standing list --json` | `id`, `status` (`pending`, `approved`, `denied`, `revoked`), `state` (`status`, or `lapsed` for an approved rule past `expires_at`), `rule`, `for` (`agent`, `zone`, or null while undecided), `principal`, `zone`, `run`, `reason`, `created_at`, `decided_at`, `decided_by`, `expires_at` (null: until revoked), `revoked_at` |
| `wicket node list --json` | `name`, `status` (`active`, `revoked`), `target`, `host_key_fp`, `hosts`, `enrolled_at`, `revoked_at`, `ca` and `identity` (the active certificate's `serial` and `not_after`, or null), `labels` (an object), `taints` (`key` or `key=value`), `public_ipv4` and `public_ipv6` (the addresses its boxes' public names point at, as its operator set them, or null). Left out, as the text shows them: a node's lease, what it holds for runs, and nodes leased but not enrolled (`wicket lease list`, `wicket top --json`) |
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

- [`wicket run`](#wicket-run)
- [`wicket session`](#wicket-session)
- [`wicket top`](#wicket-top)
- [`wicket agents`](#wicket-agents)
- [`wicket hibernate`](#wicket-hibernate)
- [`wicket trigger`](#wicket-trigger)
  - [`wicket trigger create`](#wicket-trigger-create)
  - [`wicket trigger rotate-url`](#wicket-trigger-rotate-url)
  - [`wicket trigger list`](#wicket-trigger-list)
  - [`wicket trigger show`](#wicket-trigger-show)
  - [`wicket trigger pause`](#wicket-trigger-pause)
  - [`wicket trigger resume`](#wicket-trigger-resume)
  - [`wicket trigger renew`](#wicket-trigger-renew)
  - [`wicket trigger rm`](#wicket-trigger-rm)
  - [`wicket trigger fire`](#wicket-trigger-fire)
- [`wicket wrap`](#wicket-wrap)
- [`wicket links`](#wicket-links)
- [`wicket unlink`](#wicket-unlink)
- [`wicket zone`](#wicket-zone)
  - [`wicket zone pin`](#wicket-zone-pin)
- [`wicket program`](#wicket-program)
  - [`wicket program digest`](#wicket-program-digest)
- [`wicket image`](#wicket-image)
  - [`wicket image digest`](#wicket-image-digest)
- [`wicket pending`](#wicket-pending)
- [`wicket approve`](#wicket-approve)
- [`wicket deny`](#wicket-deny)
- [`wicket grant`](#wicket-grant)
  - [`wicket grant list`](#wicket-grant-list)
  - [`wicket grant revoke`](#wicket-grant-revoke)
  - [`wicket grant renew`](#wicket-grant-renew)
- [`wicket standing`](#wicket-standing)
  - [`wicket standing list`](#wicket-standing-list)
  - [`wicket standing show`](#wicket-standing-show)
  - [`wicket standing approve`](#wicket-standing-approve)
  - [`wicket standing deny`](#wicket-standing-deny)
  - [`wicket standing renew`](#wicket-standing-renew)
  - [`wicket standing revoke`](#wicket-standing-revoke)
- [`wicket names`](#wicket-names)
  - [`wicket names list`](#wicket-names-list)
  - [`wicket names show`](#wicket-names-show)
  - [`wicket names approve`](#wicket-names-approve)
  - [`wicket names deny`](#wicket-names-deny)
  - [`wicket names revoke`](#wicket-names-revoke)
- [`wicket audit`](#wicket-audit)
  - [`wicket audit compact`](#wicket-audit-compact)
  - [`wicket audit export`](#wicket-audit-export)
- [`wicket node`](#wicket-node)
  - [`wicket node token`](#wicket-node-token)
  - [`wicket node enrol`](#wicket-node-enrol)
  - [`wicket node list`](#wicket-node-list)
  - [`wicket node create`](#wicket-node-create)
  - [`wicket node release`](#wicket-node-release)
  - [`wicket node plans`](#wicket-node-plans)
  - [`wicket node revoke`](#wicket-node-revoke)
  - [`wicket node install`](#wicket-node-install)
  - [`wicket node serve`](#wicket-node-serve)
  - [`wicket node intake`](#wicket-node-intake)
  - [`wicket node top`](#wicket-node-top)
  - [`wicket node forget`](#wicket-node-forget)
  - [`wicket node release-fence`](#wicket-node-release-fence)
  - [`wicket node set`](#wicket-node-set)
  - [`wicket node renew-ca`](#wicket-node-renew-ca)
- [`wicket lease`](#wicket-lease)
  - [`wicket lease list`](#wicket-lease-list)
  - [`wicket lease release`](#wicket-lease-release)
- [`wicket service`](#wicket-service)
  - [`wicket service add`](#wicket-service-add)
  - [`wicket service remove`](#wicket-service-remove)
  - [`wicket service list`](#wicket-service-list)
- [`wicket why-here`](#wicket-why-here)
- [`wicket reconcile`](#wicket-reconcile)
- [`wicket serve`](#wicket-serve)
- [`wicket operator`](#wicket-operator)
  - [`wicket operator list`](#wicket-operator-list)
  - [`wicket operator reset`](#wicket-operator-reset)
  - [`wicket operator enrol-link`](#wicket-operator-enrol-link)
  - [`wicket operator sessions`](#wicket-operator-sessions)
  - [`wicket operator revoke-session`](#wicket-operator-revoke-session)
- [`wicket secret`](#wicket-secret)
  - [`wicket secret set`](#wicket-secret-set)
  - [`wicket secret list`](#wicket-secret-list)
  - [`wicket secret remove`](#wicket-secret-remove)
  - [`wicket secret verify`](#wicket-secret-verify)
  - [`wicket secret hosts`](#wicket-secret-hosts)
  - [`wicket secret link`](#wicket-secret-link)
  - [`wicket secret serve`](#wicket-secret-serve)
- [`wicket identity`](#wicket-identity)
  - [`wicket identity init`](#wicket-identity-init)
  - [`wicket identity issuer`](#wicket-identity-issuer)
  - [`wicket identity show`](#wicket-identity-show)
  - [`wicket identity list`](#wicket-identity-list)
  - [`wicket identity revoke`](#wicket-identity-revoke)
- [`wicket policy`](#wicket-policy)
  - [`wicket policy show`](#wicket-policy-show)
  - [`wicket policy check`](#wicket-policy-check)
  - [`wicket policy apply`](#wicket-policy-apply)
  - [`wicket policy zone`](#wicket-policy-zone)
- [`wicket state`](#wicket-state)
  - [`wicket state check`](#wicket-state-check)
  - [`wicket state replicate`](#wicket-state-replicate)
  - [`wicket state kit`](#wicket-state-kit)
  - [`wicket state restore`](#wicket-state-restore)
  - [`wicket state snapshots`](#wicket-state-snapshots)
  - [`wicket state snapshot`](#wicket-state-snapshot)
  - [`wicket state gc`](#wicket-state-gc)
- [`wicket keys`](#wicket-keys)
  - [`wicket keys roots-offline`](#wicket-keys-roots-offline)
  - [`wicket keys certify`](#wicket-keys-certify)
  - [`wicket keys roots-online`](#wicket-keys-roots-online)
- [`wicket doctor`](#wicket-doctor)
- [`wicket self`](#wicket-self)
  - [`wicket self status`](#wicket-self-status)
  - [`wicket self update`](#wicket-self-update)
  - [`wicket self follow`](#wicket-self-follow)
  - [`wicket self rollback`](#wicket-self-rollback)
  - [`wicket self prune`](#wicket-self-prune)
  - [`wicket self trust-key`](#wicket-self-trust-key)
  - [`wicket self keygen`](#wicket-self-keygen)
  - [`wicket self sign`](#wicket-self-sign)
  - [`wicket self apply-units`](#wicket-self-apply-units)
  - [`wicket self admit`](#wicket-self-admit)
  - [`wicket self apply-update`](#wicket-self-apply-update)
- [`wicket daemon`](#wicket-daemon)
- [`wicket dev`](#wicket-dev)
  - [`wicket dev node-feed-probe`](#wicket-dev-node-feed-probe)
  - [`wicket dev mock-llm`](#wicket-dev-mock-llm)

## `wicket`

```text
Run agents in least-privilege boxes (proof of concept)

Usage: wicket <COMMAND>

Runs and agents:
  run        Run a task manifest: one workload (an agent, or a program) in one zone
  session    Open a running agent's session in this terminal: watch it, and send it prompts
  top        A live view of nodes, runs, pending requests and leases (read-only)
  agents     Long-lived agents: state, generation, current run and bundle size
  hibernate  Hibernate a long-lived agent at its next quiet point
  trigger    Triggers: when a schedule or timer comes due, wake or message an agent
  wrap       Run an agent command line that another program launches, inside a wicket box
  links      Links between boxes (expose/connect/link), newest first
  unlink     Cut a link between boxes: its relay closes it and drops its connections within seconds
  zone       How a manifest's zone treats each host it reaches: inspected or spliced, and why
  program    Programs: deterministic workloads that run without an agent
  image      Build the agent image

Approvals and grants:
  pending    List pending requests: what boxes asked for, waiting for a decision
  approve    Approve a pending request. The grant is never wider than the request
  deny       Deny a pending request
  grant      Grants made by approvals
  standing   Standing reach: a reach rule an agent asked for once, approved once for its later runs
  names      Names for boxes: internal names, and the public names a human approves
  audit      Show or verify the hash-chained audit log, or export it to the configured sinks

Nodes and placement:
  node       Nodes, the machines that run boxes: leased from a provider, or your own
  lease      Capacity leases: the nodes agents asked for
  service    Per-node services: programs kept running on every node whose boxes use them
  why-here   Why a run's box went on the node it did, or why it went nowhere
  reconcile  Make what exists agree with the ledger: runs, leases, machines and boxes

The installation:
  serve      Serve the operator console
  operator   Operator passkeys
  secret     Manage vault secrets (values are read from the terminal, never from arguments)
  identity   Agent identities: the issuer's public key, and verified identity documents
  policy     The installation's org policy (Cedar): a ceiling and forbids over every zone
  state      Control-plane state off this host: the state store, the recovery kit, a restore
  keys       The installation's root keys
  doctor     Check the environment: Docker, gVisor, image, secrets, ledger, orphaned boxes
  self       Update this installation to another wicket build, with a health gate and rollback
  daemon     wicketd: serve other users' commands over a unix socket, as the policy allows
  dev        Development helpers
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## `wicket run`

```text
Run a task manifest: one workload (an agent, or a program) in one zone

Usage: wicket run [OPTIONS] <MANIFEST>

Arguments:
  <MANIFEST>  

Options:
      --workdir <WORKDIR>              Copy this directory into the box's /workspace first
      --workspace-dir <WORKSPACE_DIR>  Mount this directory as the box's /workspace, read-write and in place (local runs only)
      --task <TASK>                    Use this task text instead of the manifest's
      --image <IMAGE>                  Agent image, overriding the manifest's agent.image (default: that, or the installation's agent image)
      --node <NODE>                    Run the box on an enrolled node (its name; its host key is pinned), through its `wicket node serve`. Default: this host's own node, `local`
      --ssh-key <SSH_KEY>              ssh identity for --node (default: the one it was enrolled with)
  -h, --help                           Print help
```

## `wicket session`

```text
Open a running agent's session in this terminal: watch it, and send it prompts.

Open a running agent's session in this terminal, as its operator: what it says and does, live. An ACP agent's whole session shows, as on the console's session page; a Claude Code agent's messages, tool calls and turn ends. Each line typed is a prompt, the agent's next turn; `/stop` cancels an ACP agent's running turn; Ctrl-C or the end of input leaves, and the agent goes on. With TEXT, sends it as one prompt and exits when that turn ends. A long-lived agent can be named by its id or any of its runs; a hibernated one is woken.

Usage: wicket session [OPTIONS] <RUN> [TEXT]...

Arguments:
  <RUN>
          

  [TEXT]...
          A prompt to send; then only its turn shows

Options:
      --no-wait
          With TEXT: queue it and exit at once

      --timeout <TIMEOUT>
          With TEXT: stop following its turn after this long (it stays queued). Seconds, or a duration (`90s`, `5m`)

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket top`

```text
A live view of nodes, runs, pending requests and leases (read-only).

A live view of what wicket is doing across its nodes (read-only): nodes (connected, boxes, what their boxes are given), runs (node, agent, status, uptime, model usage), pending requests and active leases. Redrawn every 2 s; q or Ctrl-C quits. On a node, `wicket node top`.

Usage: wicket top [OPTIONS]

Options:
      --once
          Print one frame and exit (also what a stdout that isn't a terminal gets, every 2 s, without it)

      --json
          One frame as JSON, then exit (implies --once)

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket agents`

```text
Long-lived agents: state, generation, current run and bundle size

Usage: wicket agents [OPTIONS]

Options:
      --json  JSON instead of text
  -h, --help  Print help
```

## `wicket hibernate`

```text
Hibernate a long-lived agent at its next quiet point.

Hibernate a long-lived agent (by run or agent id) at its next quiet point: its turn has ended and nothing but the agent runs in its box. What else runs is stopped after the zone's limits.exit_grace.

Usage: wicket hibernate [OPTIONS] <RUN>

Arguments:
  <RUN>
          

Options:
      --wait <WAIT>
          How long to wait for the outcome: seconds, or a duration (`90s`, `5m`)
          
          [default: 120s]

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket trigger`

```text
Triggers: when a schedule or timer comes due, wake or message an agent.

Triggers (#578): when a schedule or timer comes due, wake or message an agent.

Usage: wicket trigger <COMMAND>

Commands:
  create      Keep a trigger document (YAML) as yours. It fires with your authority, so it asks no one; it is audited (`trigger.created`). The agent it wakes or messages is resolved now (a live agent; a `wake` is kept as the agent's id)
  rotate-url  A webhook or GitHub trigger's new URL: its old one stops working. Only its owner (or root)
  list        Triggers that aren't removed: each with its state, source, action and next firing
  show        One trigger (its id, or its name): its document, agent, state, next firing and last firings
  pause       Pause a trigger: it fires nothing until resumed (the time it was paused is not caught up)
  resume      Resume a paused trigger: only its owner (or root), since it fires as its owner
  renew       Move a trigger's lapse to --lasts from now (or `forever`): only its owner (or root)
  rm          Remove a trigger: it fires nothing again
  fire        Show what a trigger would do for an event, its templates filled in, changing nothing. The event is a JSON object of the source's fields (--event); without one, a time-told event now, or for wicket's own events, one of the first kind it listens to
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket trigger create`

```text
Keep a trigger document (YAML) as yours. It fires with your authority, so it asks no one; it is audited (`trigger.created`). The agent it wakes or messages is resolved now (a live agent; a `wake` is kept as the agent's id)

Usage: wicket trigger create [OPTIONS] --file <FILE>

Options:
      --file <FILE>                
      --lasts <LASTS>              How long it lasts, or `forever`: until removed. Renew it with `wicket trigger renew` [default: 30d]
      --intake-node <INTAKE_NODE>  A webhook or GitHub trigger's intake node (a node labelled wicket.intake=true): needed only when there are several
      --allow-local-intake         Let the intake node be this host's own (`local`): deliveries from the internet then reach the machine with the ledger and the vault. Off unless asked for
  -h, --help                       Print help
```

### `wicket trigger rotate-url`

```text
A webhook or GitHub trigger's new URL: its old one stops working. Only its owner (or root)

Usage: wicket trigger rotate-url <TRIGGER>

Arguments:
  <TRIGGER>  

Options:
  -h, --help  Print help
```

### `wicket trigger list`

```text
Triggers that aren't removed: each with its state, source, action and next firing

Usage: wicket trigger list

Options:
  -h, --help  Print help
```

### `wicket trigger show`

```text
One trigger (its id, or its name): its document, agent, state, next firing and last firings

Usage: wicket trigger show <TRIGGER>

Arguments:
  <TRIGGER>  

Options:
  -h, --help  Print help
```

### `wicket trigger pause`

```text
Pause a trigger: it fires nothing until resumed (the time it was paused is not caught up)

Usage: wicket trigger pause <TRIGGER>

Arguments:
  <TRIGGER>  

Options:
  -h, --help  Print help
```

### `wicket trigger resume`

```text
Resume a paused trigger: only its owner (or root), since it fires as its owner

Usage: wicket trigger resume <TRIGGER>

Arguments:
  <TRIGGER>  

Options:
  -h, --help  Print help
```

### `wicket trigger renew`

```text
Move a trigger's lapse to --lasts from now (or `forever`): only its owner (or root)

Usage: wicket trigger renew [OPTIONS] <TRIGGER>

Arguments:
  <TRIGGER>  

Options:
      --lasts <LASTS>  [default: 30d]
  -h, --help           Print help
```

### `wicket trigger rm`

```text
Remove a trigger: it fires nothing again

Usage: wicket trigger rm <TRIGGER>

Arguments:
  <TRIGGER>  

Options:
  -h, --help  Print help
```

### `wicket trigger fire`

```text
Show what a trigger would do for an event, its templates filled in, changing nothing. The event is a JSON object of the source's fields (--event); without one, a time-told event now, or for wicket's own events, one of the first kind it listens to

Usage: wicket trigger fire [OPTIONS] --dry-run <TRIGGER>

Arguments:
  <TRIGGER>  

Options:
      --event <EVENT>  A JSON file with the event's fields
      --dry-run        Only show what would happen (the one mode this version has)
  -h, --help           Print help
```

## `wicket wrap`

```text
Run an agent command line that another program launches, inside a wicket box.

Run an agent command line that another program launches, inside a wicket box: the harness's wrapped mode (e.g. its Remote Control sessions' process wrapper). Its stdin and stdout stay connected to the launcher, its credentials become placeholders swapped at the proxy, and wicket logs to a file.

Usage: wicket wrap [OPTIONS] --manifest <MANIFEST> <ARGV>...

Arguments:
  <ARGV>...
          The agent command line, after `--`

Options:
      --manifest <MANIFEST>
          

      --image <IMAGE>
          Agent image, overriding the manifest's agent.image

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket links`

```text
Links between boxes (expose/connect/link), newest first

Usage: wicket links [OPTIONS]

Options:
      --tail <TAIL>  [default: 40]
      --json         JSON instead of text
  -h, --help         Print help
```

## `wicket unlink`

```text
Cut a link between boxes: its relay closes it and drops its connections within seconds

Usage: wicket unlink <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket zone`

```text
How a manifest's zone treats each host it reaches: inspected or spliced, and why.

The zone view of a manifest: for each host its reach names, whether the egress proxy inspects it (terminates TLS and decides every request) or splices it through (decides on the hostname, relays the encrypted bytes), and why (#62).

Usage: wicket zone [OPTIONS] [MANIFEST]
       wicket zone <COMMAND>

Commands:
  pin   Rewrite a manifest's image tags (zone.images, agent.image, program.image) to the digests they point to now, in place, keeping the rest of the file (#192)
  help  Print this message or the help of the given subcommand(s)

Arguments:
  [MANIFEST]
          The manifest (YAML)

Options:
      --json
          JSON instead of text

  -h, --help
          Print help (see a summary with '-h')
```

### `wicket zone pin`

```text
Rewrite a manifest's image tags (zone.images, agent.image, program.image) to the digests they point to now, in place, keeping the rest of the file (#192)

Usage: wicket zone pin [OPTIONS] <MANIFEST>

Arguments:
  <MANIFEST>  

Options:
      --dry-run  Say what would change; write nothing
  -h, --help     Print help
```

## `wicket program`

```text
Programs: deterministic workloads that run without an agent

Usage: wicket program <COMMAND>

Commands:
  digest  Print a program source directory's digest (what a manifest pins to approve that exact code)
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket program digest`

```text
Print a program source directory's digest (what a manifest pins to approve that exact code)

Usage: wicket program digest <DIR>

Arguments:
  <DIR>  

Options:
  -h, --help  Print help
```

## `wicket image`

```text
Build the agent image.

Build the agent image (the image directory plus the in-box forwarder's source, compiled in the build). Without --dir, from the copy embedded in this binary, so the image matches it.

Usage: wicket image [OPTIONS]
       wicket image <COMMAND>

Commands:
  digest  The digest each image is in this installation's Docker (#192): `<ref> sha256:…`, what a zone pins it as (`name@sha256:…`)
  help    Print this message or the help of the given subcommand(s)

Options:
      --tag <TAG>
          The tag to build, kept as given [default: this installation's own image: the default harness's image repository, tagged with the build id on an installed version, else its default tag]

      --dir <DIR>
          An image directory to build instead (e.g. one under images/, while changing it). If its Dockerfile declares `ARG BASE`, BASE is this installation's own agent image

  -h, --help
          Print help (see a summary with '-h')
```

### `wicket image digest`

```text
The digest each image is in this installation's Docker (#192): `<ref> sha256:…`, what a zone pins it as (`name@sha256:…`)

Usage: wicket image digest <REFS>...

Arguments:
  <REFS>...  

Options:
  -h, --help  Print help
```

## `wicket pending`

```text
List pending requests: what boxes asked for, waiting for a decision.

List pending requests: what boxes asked for that their zones don't allow, waiting for a grant or a denial.

Usage: wicket pending [OPTIONS]

Options:
      --json
          JSON instead of text

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket approve`

```text
Approve a pending request. The grant is never wider than the request

Usage: wicket approve [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --uses <USES>      Number of uses (default 1) [default: 1]
      --unlimited        Unlimited uses until expiry
      --ttl <TTL>        Grant lifetime [default: 10m]
      --prefix <PREFIX>  Grant a path prefix of the requested path instead of the exact path
  -y, --yes              Don't ask for confirmation at a terminal (the request is printed either way)
      --zone-wide        Let any run in the request's zone use the grant, until it expires. By default only the run that asked may, and the grant ends with that run
  -h, --help             Print help
```

## `wicket deny`

```text
Deny a pending request

Usage: wicket deny <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket grant`

```text
Grants made by approvals

Usage: wicket grant <COMMAND>

Commands:
  list    List grants, newest first: approvals, and runs' quotas (#256): model budget, children and bytes (a root run's own zone budget, or what its parent carved for a child: the limits its run enforces), and money (a capacity lease's hourly cap and reservation, micro-USD shown as USD). Every grant has a lifetime; only live ones unless --all
  revoke  Revoke a grant. A grant handed to a node is revoked there through its feed by the run that published it (at once if the node is reachable)
  renew   Renew a live grant, or a running box's authority, so it lasts --ttl from now (#56): a grant by its id (or the request it answers), a box's authority by its run id. Every grant keeps a lifetime: at most 24h, and a box's authority never past its run's timeout. Audited as a decision; the run publishes it to the box's node
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket grant list`

```text
List grants, newest first: approvals, and runs' quotas (#256): model budget, children and bytes (a root run's own zone budget, or what its parent carved for a child: the limits its run enforces), and money (a capacity lease's hourly cap and reservation, micro-USD shown as USD). Every grant has a lifetime; only live ones unless --all

Usage: wicket grant list [OPTIONS]

Options:
      --all          Also revoked and expired grants
      --tail <TAIL>  [default: 40]
      --json         JSON instead of text
  -h, --help         Print help
```

### `wicket grant revoke`

```text
Revoke a grant. A grant handed to a node is revoked there through its feed by the run that published it (at once if the node is reachable)

Usage: wicket grant revoke <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

### `wicket grant renew`

```text
Renew a live grant, or a running box's authority, so it lasts --ttl from now (#56): a grant by its id (or the request it answers), a box's authority by its run id. Every grant keeps a lifetime: at most 24h, and a box's authority never past its run's timeout. Audited as a decision; the run publishes it to the box's node

Usage: wicket grant renew [OPTIONS] <ID>

Arguments:
  <ID>  A grant id (`g-…`), a request id (`r-…`: the grant made for it), or a running box's run id

Options:
      --ttl <TTL>  The new lifetime, from now [default: 10m]
  -h, --help       Print help
```

## `wicket standing`

```text
Standing reach: a reach rule an agent asked for once, approved once for its later runs.

Standing reach (#572): a reach rule an agent asked for once, approved once for its later runs.

Usage: wicket standing <COMMAND>

Commands:
  list     Standing rules: pending asks, and approved rules (with when they lapse). --all adds denied, revoked and lapsed ones
  show     One ask or rule: the rule, who it is for, the ledger's evidence (the requests it covers), and what it would allow beyond them
  approve  Approve a standing ask (`s-…`), once: the rule as asked, or --narrow to what its evidence used. For the agent that asked (each later run of it), or --for zone (every agent of its zone)
  deny     Deny a standing ask
  renew    Move an approved rule's lapse to --ttl from now (or `forever`)
  revoke   Revoke an approved rule: it allows nothing from now on (a box's node, once its run publishes the revocation)
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket standing list`

```text
Standing rules: pending asks, and approved rules (with when they lapse). --all adds denied, revoked and lapsed ones

Usage: wicket standing list [OPTIONS]

Options:
      --all   
      --json  JSON instead of text
  -h, --help  Print help
```

### `wicket standing show`

```text
One ask or rule: the rule, who it is for, the ledger's evidence (the requests it covers), and what it would allow beyond them

Usage: wicket standing show <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

### `wicket standing approve`

```text
Approve a standing ask (`s-…`), once: the rule as asked, or --narrow to what its evidence used. For the agent that asked (each later run of it), or --for zone (every agent of its zone)

Usage: wicket standing approve [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --for <BOUND>  Who it is for: `agent` (the asking agent's principal) or `zone` (its zone) [default: agent]
      --ttl <TTL>    How long it lasts (at most 366d), or `forever`: until revoked [default: 30d] [alias: --lasts]
      --narrow       Approve only the methods and paths the evidence shows were asked for
  -y, --yes          Don't ask for confirmation at a terminal (the ask is printed either way)
  -h, --help         Print help
```

### `wicket standing deny`

```text
Deny a standing ask

Usage: wicket standing deny <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

### `wicket standing renew`

```text
Move an approved rule's lapse to --ttl from now (or `forever`)

Usage: wicket standing renew [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --ttl <TTL>  How long it lasts from now (at most 366d), or `forever`: until revoked [default: 30d] [alias: --lasts]
  -h, --help       Print help
```

### `wicket standing revoke`

```text
Revoke an approved rule: it allows nothing from now on (a box's node, once its run publishes the revocation)

Usage: wicket standing revoke <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket names`

```text
Names for boxes: internal names, and the public names a human approves.

Names for boxes (#575): internal names, and the public names a human approves.

Usage: wicket names <COMMAND>

Commands:
  list     Names: pending asks for public names, and live names (internal and public). --all adds denied, withdrawn and ended ones
  show     One name or ask: the label, port, who asked, and, for a public name, what approving it means
  approve  Approve an ask for a public name (`n-…`). A standing name is for the agent that asked (each later run of it takes it up when it starts), or --for zone (every agent of its zone), for --lasts
  deny     Deny an ask for a public name
  revoke   Revoke a live name, public or internal: it ends now, whoever holds it
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket names list`

```text
Names: pending asks for public names, and live names (internal and public). --all adds denied, withdrawn and ended ones

Usage: wicket names list [OPTIONS]

Options:
      --all   
  -h, --help  Print help
```

### `wicket names show`

```text
One name or ask: the label, port, who asked, and, for a public name, what approving it means

Usage: wicket names show <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

### `wicket names approve`

```text
Approve an ask for a public name (`n-…`). A standing name is for the agent that asked (each later run of it takes it up when it starts), or --for zone (every agent of its zone), for --lasts

Usage: wicket names approve [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --for <BOUND>    A standing name's holder: `agent` (the asking agent's principal) or `zone` (its zone) [default: agent]
      --lasts <LASTS>  A standing name's lifetime (at most 366d), or `forever`: until revoked [default: 30d]
  -y, --yes            Don't ask for confirmation at a terminal (the ask is printed either way)
  -h, --help           Print help
```

### `wicket names deny`

```text
Deny an ask for a public name

Usage: wicket names deny <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

### `wicket names revoke`

```text
Revoke a live name, public or internal: it ends now, whoever holds it

Usage: wicket names revoke <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket audit`

```text
Show or verify the hash-chained audit log, or export it to the configured sinks

Usage: wicket audit [OPTIONS] [COMMAND]

Commands:
  compact  Switch the ledger to giving pruned audit space back (`auto_vacuum = incremental`), with one VACUUM (#582). Run it as the wicket user with wicketd, the console and the reconciler stopped: the whole file is rewritten under an exclusive lock (about a minute per 2.5 GB), and it needs as much free space again beside the ledger. Ledgers made by this build don't need it
  export   Feed the sinks in the sinks file (`audit-sinks.yaml` in the data dir, or $WICKET_AUDIT_SINKS) until stopped. Runs alongside `wicket run` and `wicket serve`, which feed the sinks too; each sink is fed by one process at a time. The only process that writes to a `path: "-"` (stdout) sink
  help     Print this message or the help of the given subcommand(s)

Options:
      --tail <TAIL>              [default: 40]
      --verify                   
      --against <AGAINST>        With --verify: also check the local chain against exported records and signed checkpoints (JSON lines, or a Collector's OTLP JSON file output). Catches a rewritten or truncated chain. `store:<sink>`: what a `store` sink wrote to the state store
      --issuer-jwk <ISSUER_JWK>  The issuer public key (JWK, as `wicket identity issuer` prints it) checkpoints must be signed with. Default: this installation's issuer key
      --json                     The records as JSON instead of text
  -h, --help                     Print help
```

### `wicket audit compact`

```text
Switch the ledger to giving pruned audit space back (`auto_vacuum = incremental`), with one VACUUM (#582). Run it as the wicket user with wicketd, the console and the reconciler stopped: the whole file is rewritten under an exclusive lock (about a minute per 2.5 GB), and it needs as much free space again beside the ledger. Ledgers made by this build don't need it

Usage: wicket audit compact [OPTIONS]

Options:
  -y, --yes   Don't ask for confirmation at a terminal
  -h, --help  Print help
```

### `wicket audit export`

```text
Feed the sinks in the sinks file (`audit-sinks.yaml` in the data dir, or $WICKET_AUDIT_SINKS) until stopped. Runs alongside `wicket run` and `wicket serve`, which feed the sinks too; each sink is fed by one process at a time. The only process that writes to a `path: "-"` (stdout) sink

Usage: wicket audit export [OPTIONS]

Options:
      --once        One pass, then exit (non-zero if a sink failed)
      --checkpoint  Send every sink a checkpoint now
      --status      Show each sink's position and last error
  -h, --help        Print help
```

## `wicket node`

```text
Nodes, the machines that run boxes: leased from a provider, or your own.

Nodes (#16, #37), machines that run boxes: leased from a provider (create, release, plans) or your own (one-time join tokens, enrolment with a pinned ssh host key, a node key and a name-constrained node CA); listing with leases and cost, revoking, renewing the CA.

Usage: wicket node <COMMAND>

Commands:
  token          Print a one-time join token for a node (stored hashed; single use)
  enrol          Enrol a machine you already have, over ssh: pin its host key, have it make its node key and CA key, and give it a short-lived identity certificate for its node key, a short-lived CA certificate constrained to --hosts, the feed root key and the issuer key
  list           List nodes: each enrolled node, and each node's lease, provider and cost if it has them (a node from `wicket node create` or a capacity lease), with any leased node not enrolled
  create         Lease a machine from a provider (Vultr) and enrol it, with its ssh host key generated here and pinned at creation. Its money is reserved first against placement.yaml's limits (with every lease's); then its spend is a CAPACITY request from you: approved at once by a capacity grant of yours that covers it, otherwise waiting for an operator
  release        Destroy a node `wicket node create` made, now (refusing anything without the owner tag), and revoke its enrolment
  plans          List a provider's (Vultr's) plans in a region, with their hourly price
  revoke         Revoke a node: refuse it from now on (its pinned host key is deleted, its identity certificates are revoked, and runs connected to it drop it) and record its CA serials for the feed's revocation list
  install        Copy this wicket binary to an enrolled node (sha256-checked) and install the `wicket-node` systemd user service that runs `wicket node serve` there
  serve          On the node: run its boxes and decide their egress locally from the signed feed (the `wicket-node` service runs this)
  intake         On the node: webhook intake for triggers (#578; docs/explanation/trigger-intake.md). Takes deliveries for the triggers the control host assigned to this node, checks their token and signature, and hands what it verified to this node's `wicket node serve`, which the control host pulls from. It holds no ledger and no authority (the `wicket-intake` service runs this)
  top            On the node, as its `wicket` user: a live view of the node (read-only): its identity and CA, its control connections, feed, load, memory and disk; each box's state, uptime, CPU and memory, model use and budget slice left, egress counts and queued asks; and the last egress decisions. Redrawn every 2 s; q or Ctrl-C quits
  forget         Let a run's node delete the run's files, its workspace among them. Refused while the run's work hasn't been collected (its files fetched, its outbox taken, a push or a hibernation bundle), unless --force; a forced delete is audited
  release-fence  Release a run's fence without its node (root only, audited as `run.fence_released`): for a run whose node can't confirm its box stopped (unreachable or revoked) and whose fence wouldn't otherwise end, as when its records don't say when its authority ends. Its agent can then be woken. The box may still be running on its node
  set            Set what placement and the control host know of an enrolled node: its labels and taints (#579), and how its CA may be widened at runtime (#573). A box goes on a node only if the node has every label the box's `placement.node_selector` names, and the box tolerates every taint the node has. A CA widening is a renewal over the run's channel, audited as `node.ca_widened`. Its public addresses (#575) are where its boxes' public names point: only you set them, never the node
  renew-ca       Issue a node a fresh CA certificate (and CA key, made on the node) and a fresh identity certificate for its node key, over its pinned ssh: also how a node whose identity certificate expired while it was unreachable gets back in
  help           Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket node token`

```text
Print a one-time join token for a node (stored hashed; single use)

Usage: wicket node token [OPTIONS]

Options:
      --name <NAME>  The node's name (default: a generated one, printed)
      --ttl <TTL>    [default: 1h]
  -h, --help         Print help
```

### `wicket node enrol`

```text
Enrol a machine you already have, over ssh: pin its host key, have it make its node key and CA key, and give it a short-lived identity certificate for its node key, a short-lived CA certificate constrained to --hosts, the feed root key and the issuer key

Usage: wicket node enrol [OPTIONS] --token <TOKEN> --hosts <HOSTS> <TARGET>

Arguments:
  <TARGET>  e.g. wicket@203.0.113.7

Options:
      --token <TOKEN>        From `wicket node token`
      --name <NAME>          The node name (must match the token's)
      --ssh-key <SSH_KEY>    ssh identity to log in with (remembered for later runs)
      --host-key <HOST_KEY>  The node's ssh host key (`ssh-ed25519 AAAA…`) or its fingerprint (`SHA256:…`), from the provider's console, cloud-init output or the image: not from the network
      --trust-first-use      No --host-key: pin whatever key the node presents now, and print its fingerprint
      --hosts <HOSTS>        Host names the node's CA may mint certificates for: `api.example.com`, `*.example.org` (comma-separated)
      --ca-ttl <CA_TTL>      Node CA lifetime [default: 24h]
      --cert-ttl <CERT_TTL>  Node identity certificate lifetime (renewed over the control channel at half-life) [default: 24h]
  -h, --help                 Print help
```

### `wicket node list`

```text
List nodes: each enrolled node, and each node's lease, provider and cost if it has them (a node from `wicket node create` or a capacity lease), with any leased node not enrolled

Usage: wicket node list [OPTIONS]

Options:
      --provider
          Also ask the provider (Vultr) for this installation's instances by owner tag: their state, cost and next paid hour, and any this ledger doesn't record
      --api-key-secret <API_KEY_SECRET>
          The vault secret holding the Vultr API key [default: vultr-api-key]
      --owner <OWNER>
          The owner tag's installation name (default: this installation's trust domain, else "wicket"). Garbage collection only ever touches instances carrying it, so keep it stable
      --json
          The enrolled nodes as JSON instead of text (not with --provider)
  -h, --help
          Print help
```

### `wicket node create`

```text
Lease a machine from a provider (Vultr) and enrol it, with its ssh host key generated here and pinned at creation. Its money is reserved first against placement.yaml's limits (with every lease's); then its spend is a CAPACITY request from you: approved at once by a capacity grant of yours that covers it, otherwise waiting for an operator

Usage: wicket node create [OPTIONS] --name <NAME> --ssh-key-id <SSH_KEY_IDS>

Options:
      --api-key-secret <API_KEY_SECRET>
          The vault secret holding the Vultr API key [default: vultr-api-key]
      --owner <OWNER>
          The owner tag's installation name (default: this installation's trust domain, else "wicket"). Garbage collection only ever touches instances carrying it, so keep it stable
      --name <NAME>
          Node name (hostname, label and enrolled name)
      --hosts <HOSTS>
          Host names the node's CA may issue for, as for `wicket node enrol --hosts`
      --region <REGION>
          [default: lhr]
      --plan <PLAN>
          A plan id (e.g. vc2-1c-2gb); otherwise the cheapest that fits --vcpus and --memory-mib
      --vcpus <VCPUS>
          [default: 1]
      --memory-mib <MEMORY_MIB>
          [default: 2048]
      --lifetime <LIFETIME>
          How long the node is needed: its worst-case cost is reserved for this long, and its lease ends at minute 50 of the last hour [default: 1h]
      --max-node-hourly <MAX_NODE_HOURLY>
          Most this node may cost per hour, in dollars
      --ssh-key-id <SSH_KEY_IDS>
          Id of an ssh key already in the Vultr account (installed for root, copied to `wicket`)
      --ssh-key <SSH_KEY>
          The private half of that key, on this host
      --os-id <OS_ID>
          Vultr os_id (default: Ubuntu 24.04 x64) [default: 2284]
      --idempotency-key <IDEMPOTENCY_KEY>
          Make a retried create return the same node (default: derived from --name)
      --no-enrol
          Create and wait, but don't enrol
      --ca-ttl <CA_TTL>
          [default: 24h]
      --give-up-silent <GIVE_UP_SILENT>
          Give up on the node, and release it, if nothing answers on its ssh port for this long (every connect times out or is unreachable). Once the port answers (accepted or refused), wait up to 15 minutes for setup [default: 4m]
      --wait <WAIT>
          How long to wait for an operator when none of your capacity grants covers the node (the request is pending meanwhile, on the console and in `wicket pending`); 0: don't wait [default: 15m]
  -h, --help
          Print help
```

### `wicket node release`

```text
Destroy a node `wicket node create` made, now (refusing anything without the owner tag), and revoke its enrolment

Usage: wicket node release [OPTIONS] <ID>

Arguments:
  <ID>  The provider's instance id, or the node's name

Options:
      --api-key-secret <API_KEY_SECRET>
          The vault secret holding the Vultr API key [default: vultr-api-key]
      --owner <OWNER>
          The owner tag's installation name (default: this installation's trust domain, else "wicket"). Garbage collection only ever touches instances carrying it, so keep it stable
  -h, --help
          Print help
```

### `wicket node plans`

```text
List a provider's (Vultr's) plans in a region, with their hourly price

Usage: wicket node plans [OPTIONS]

Options:
      --api-key-secret <API_KEY_SECRET>
          The vault secret holding the Vultr API key [default: vultr-api-key]
      --owner <OWNER>
          The owner tag's installation name (default: this installation's trust domain, else "wicket"). Garbage collection only ever touches instances carrying it, so keep it stable
      --region <REGION>
          [default: lhr]
      --plan-type <PLAN_TYPE>
          [default: vc2]
  -h, --help
          Print help
```

### `wicket node revoke`

```text
Revoke a node: refuse it from now on (its pinned host key is deleted, its identity certificates are revoked, and runs connected to it drop it) and record its CA serials for the feed's revocation list

Usage: wicket node revoke <NAME>

Arguments:
  <NAME>  

Options:
  -h, --help  Print help
```

### `wicket node install`

```text
Copy this wicket binary to an enrolled node (sha256-checked) and install the `wicket-node` systemd user service that runs `wicket node serve` there

Usage: wicket node install [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --ssh-key <SSH_KEY>  ssh identity (default: the one it was enrolled with)
      --no-service         Only copy the binary; don't install or restart the service
  -h, --help               Print help
```

### `wicket node serve`

```text
On the node: run its boxes and decide their egress locally from the signed feed (the `wicket-node` service runs this)

Usage: wicket node serve [OPTIONS]

Options:
      --dir <DIR>  The node's directory (default: $WICKET_NODE_HOME or ~/.local/share/wicket-node)
  -h, --help       Print help
```

### `wicket node intake`

```text
On the node: webhook intake for triggers (#578; docs/explanation/trigger-intake.md). Takes deliveries for the triggers the control host assigned to this node, checks their token and signature, and hands what it verified to this node's `wicket node serve`, which the control host pulls from. It holds no ledger and no authority (the `wicket-intake` service runs this)

Usage: wicket node intake [OPTIONS] --listen <LISTEN>

Options:
      --listen <LISTEN>                Where to listen (e.g. `0.0.0.0:8443`)
      --tls-cert <TLS_CERT>            A certificate chain (PEM) to serve TLS with; without it, plain HTTP behind a reverse proxy that has TLS
      --tls-key <TLS_KEY>              The certificate's private key (PEM)
      --socket <SOCKET>                The node's intake socket, which `wicket node serve` listens on for intake (default: `<node dir>/ctl/intake.sock`, for intake run as the node's own user). Run as its own user, intake is given the socket the node's `intake_socket` names
      --dir <DIR>                      The node's directory, for the default socket (default: $WICKET_NODE_HOME or ~/.local/share/wicket-node)
      --trusted-proxy <TRUSTED_PROXY>  A reverse proxy in front of intake (an address or a CIDR range; repeatable), whose `X-Forwarded-For` names the client. Without one, the client is the peer
  -h, --help                           Print help
```

### `wicket node top`

```text
On the node, as its `wicket` user: a live view of the node (read-only): its identity and CA, its control connections, feed, load, memory and disk; each box's state, uptime, CPU and memory, model use and budget slice left, egress counts and queued asks; and the last egress decisions. Redrawn every 2 s; q or Ctrl-C quits

Usage: wicket node top [OPTIONS]

Options:
      --dir <DIR>  The node's directory (default: $WICKET_NODE_HOME or ~/.local/share/wicket-node)
      --once       Print one frame and exit (also what a stdout that isn't a terminal gets, every 2 s, without it)
      --json       Print the node's status once, as JSON
  -h, --help       Print help
```

### `wicket node forget`

```text
Let a run's node delete the run's files, its workspace among them. Refused while the run's work hasn't been collected (its files fetched, its outbox taken, a push or a hibernation bundle), unless --force; a forced delete is audited

Usage: wicket node forget [OPTIONS] <RUN>

Arguments:
  <RUN>  The run

Options:
      --force  Delete them even though the run's work was never collected
  -h, --help   Print help
```

### `wicket node release-fence`

```text
Release a run's fence without its node (root only, audited as `run.fence_released`): for a run whose node can't confirm its box stopped (unreachable or revoked) and whose fence wouldn't otherwise end, as when its records don't say when its authority ends. Its agent can then be woken. The box may still be running on its node

Usage: wicket node release-fence --reason <REASON> <RUN>

Arguments:
  <RUN>  The run

Options:
      --reason <REASON>  Why: it goes on the audit record
  -h, --help             Print help
```

### `wicket node set`

```text
Set what placement and the control host know of an enrolled node: its labels and taints (#579), and how its CA may be widened at runtime (#573). A box goes on a node only if the node has every label the box's `placement.node_selector` names, and the box tolerates every taint the node has. A CA widening is a renewal over the run's channel, audited as `node.ca_widened`. Its public addresses (#575) are where its boxes' public names point: only you set them, never the node

Usage: wicket node set [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --ca-hosts <CA_HOSTS>        `fixed` (never: its hosts change only with renew-ca), `auto` (to every inspected host its boxes' reach or grants need), or a comma-separated list of hosts it may be widened to (`api.example.com,*.example.org`)
      --label <LABELS>             `key=value` sets a label, `key-` removes it. Repeatable
      --taint <TAINTS>             `key` or `key=value` taints the node (one taint per key), `key-` removes it. Repeatable
      --public-ipv4 <PUBLIC_IPV4>  The node's public IPv4 address (an address on the public internet: the router's, for a node behind NAT that forwards its port range), or `none`
      --public-ipv6 <PUBLIC_IPV6>  The node's public IPv6 address, or `none`
  -h, --help                       Print help
```

### `wicket node renew-ca`

```text
Issue a node a fresh CA certificate (and CA key, made on the node) and a fresh identity certificate for its node key, over its pinned ssh: also how a node whose identity certificate expired while it was unreachable gets back in

Usage: wicket node renew-ca [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --hosts <HOSTS>        Replace the host names it is constrained to (default: keep them)
      --ca-ttl <CA_TTL>      [default: 24h]
      --cert-ttl <CERT_TTL>  Node identity certificate lifetime [default: 24h]
  -h, --help                 Print help
```

## `wicket lease`

```text
Capacity leases: the nodes agents asked for.

Capacity leases (#7): nodes agents asked for with request_capacity. Approve or deny the request with `wicket approve`/`deny` (see `wicket pending`).

Usage: wicket lease <COMMAND>

Commands:
  list     Every lease: status, holder run, node, money reserved, end
  release  End a lease now: what runs on it stops and its node is destroyed (one reconcile pass)
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket lease list`

```text
Every lease: status, holder run, node, money reserved, end

Usage: wicket lease list

Options:
  -h, --help  Print help
```

### `wicket lease release`

```text
End a lease now: what runs on it stops and its node is destroyed (one reconcile pass)

Usage: wicket lease release <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket service`

```text
Per-node services: programs kept running on every node whose boxes use them.

Per-node services (#579): programs kept running on every node whose boxes use them.

Usage: wicket service <COMMAND>

Commands:
  add     Install a per-node service: a program manifest with a `service:` section. Its manifest and source are copied into wicket's data directory and pinned: what was there when it was added is what runs. Adding again replaces it (audited)
  remove  Uninstall one: its instances stop, and no new one starts
  list    The installed services
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket service add`

```text
Install a per-node service: a program manifest with a `service:` section. Its manifest and source are copied into wicket's data directory and pinned: what was there when it was added is what runs. Adding again replaces it (audited)

Usage: wicket service add <MANIFEST>

Arguments:
  <MANIFEST>  

Options:
  -h, --help  Print help
```

### `wicket service remove`

```text
Uninstall one: its instances stop, and no new one starts

Usage: wicket service remove <NAME>

Arguments:
  <NAME>  

Options:
  -h, --help  Print help
```

### `wicket service list`

```text
The installed services

Usage: wicket service list [OPTIONS]

Options:
      --json  JSON instead of text
  -h, --help  Print help
```

## `wicket why-here`

```text
Why a run's box went on the node it did, or why it went nowhere.

Why a run's box went on the node it did, or why it went nowhere (#579): what it asked for, the nodes it may go on in order, and every reason each other node was out.

Usage: wicket why-here [OPTIONS] <RUN>

Arguments:
  <RUN>
          

Options:
      --json
          

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket reconcile`

```text
Make what exists agree with the ledger: runs, leases, machines and boxes.

Make what exists agree with the ledger (#38): end runs whose process is gone, end leases past their end or whose run ended, destroy owned machines no lease needs (checking the owner tag again right before each destroy), adopt or create the ones leases need, and stop boxes whose run has ended, here and on enrolled nodes. Records every change in the audit log.

Usage: wicket reconcile [OPTIONS]

Options:
      --dry-run
          Only report what would change

      --every <EVERY>
          Keep running, one pass per interval (e.g. 30s)

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket serve`

```text
Serve the operator console.

Serve the operator console (runs, approvals, activity; start, steer and revoke runs). Plain HTTP on loopback by default; any other address needs HTTPS (--acme-domain, or --tls-cert and --tls-key) or --behind-tls-terminator.

Usage: wicket serve [OPTIONS]

Options:
      --listen <LISTEN>
          [default: 127.0.0.1:8787]

      --origin <ORIGIN>
          Browser origin for WebAuthn (default: http://localhost:PORT; https://DOMAIN with ACME)

      --rp-id <RP_ID>
          WebAuthn relying-party id (default: the origin's host)

      --tls-cert <TLS_CERT>
          Serve HTTPS with this certificate chain (PEM; re-read when it changes)

      --tls-key <TLS_KEY>
          The certificate's private key (PEM)

      --acme-domain <ACME_DOMAIN>
          Serve HTTPS with a certificate from an ACME CA (Let's Encrypt) for this name, validated with TLS-ALPN-01 on this listener (so listen on :443)

      --acme-agree-tos
          Accept the ACME CA's terms of service (required with --acme-domain)

      --acme-contact <ACME_CONTACT>
          Contact for the ACME account (mailto:...; repeatable)

      --acme-staging
          Use Let's Encrypt's staging CA (untrusted certificates; for trying the setup)

      --acme-directory <ACME_DIRECTORY>
          Another ACME directory URL

      --acme-cache <ACME_CACHE>
          Where the ACME account and certificate are kept (default $WICKET_HOME/acme)

      --behind-tls-terminator
          A TLS-terminating proxy in front serves the console's https:// --origin; listen in plain HTTP

      --trusted-proxy <TRUSTED_PROXY>
          The proxy's address or range (repeatable): its X-Forwarded-For names the client

      --max-connections <MAX_CONNECTIONS>
          Most simultaneous connections
          
          [default: 256]

      --no-bootstrap-link
          Don't print a passkey enrolment link at start when no passkey is enrolled (a system install's log may be readable by operators; root prints one with `operator enrol-link`)

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket operator`

```text
Operator passkeys

Usage: wicket operator <COMMAND>

Commands:
  list            List enrolled passkeys
  reset           Host-only break-glass: revoke every passkey (and every console session), so `wicket serve` prints a fresh enrolment link
  enrol-link      Print a fresh single-use link that enrols one passkey in the console (another device, or a replacement after `reset`). The only way to add a passkey: a signed-in console session can't
  sessions        List live console sessions (id, passkey, client address, times)
  revoke-session  End console sessions now: one by its id (or a unique prefix of it), or all with --all
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket operator list`

```text
List enrolled passkeys

Usage: wicket operator list

Options:
  -h, --help  Print help
```

### `wicket operator reset`

```text
Host-only break-glass: revoke every passkey (and every console session), so `wicket serve` prints a fresh enrolment link

Usage: wicket operator reset

Options:
  -h, --help  Print help
```

### `wicket operator enrol-link`

```text
Print a fresh single-use link that enrols one passkey in the console (another device, or a replacement after `reset`). The only way to add a passkey: a signed-in console session can't

Usage: wicket operator enrol-link [OPTIONS]

Options:
      --ttl <TTL>        How long the link stays usable (at most 1h) [default: 10m]
      --origin <ORIGIN>  The console's origin, to print the whole link (otherwise just its path)
  -h, --help             Print help
```

### `wicket operator sessions`

```text
List live console sessions (id, passkey, client address, times)

Usage: wicket operator sessions

Options:
  -h, --help  Print help
```

### `wicket operator revoke-session`

```text
End console sessions now: one by its id (or a unique prefix of it), or all with --all

Usage: wicket operator revoke-session [OPTIONS] [ID]

Arguments:
  [ID]  

Options:
      --all   
  -h, --help  Print help
```

## `wicket secret`

```text
Manage vault secrets (values are read from the terminal, never from arguments)

Usage: wicket secret <COMMAND>

Commands:
  set     Store a secret. Prompts without echo, or reads stdin when it isn't a terminal
  list    List secret names and the host names each may be sent to (never values)
  remove  Remove a secret (a reference: only the reference). Nodes holding a copy for a run delete it when the control host next checks that run's secrets, within seconds while connected (#152)
  verify  Make a secret a verify secret (#578): a webhook trigger's HMAC key, used only to check its deliveries' signatures. It is sent to no host, and can't be bound to one
  hosts   Bind a secret to the only host names it may be sent to, replacing its list
  link    Make a secret a reference to a JSON field in another file, re-read on every use (never copied): e.g. a harness's login on this host (docs/how-to/store-and-link-secrets.md). A harness login's account fields (never its holder's name) are kept with the reference as they are now, for Remote Control boxes: re-link to refresh them
  serve   Serve linked secrets to wicketd, as the owner of the files they are in (a secret helper, #350): run it as that user, e.g. as a systemd user service (deploy/systemd-user/wicket-secret-helper.service). It answers only wicketd's user, and only with each secret's current value and expiry; it reads the file at each request, so a refresh is picked up at once
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket secret set`

```text
Store a secret. Prompts without echo, or reads stdin when it isn't a terminal

Usage: wicket secret set [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --hosts <HOSTS>  The only host names it may be sent to (comma-separated; `*.example.com` for every name under it). Without it, the secret keeps the host names it had; a new one with none is sent nowhere, unless it is a harness's default model secret: then it goes to that harness's model host name
  -h, --help           Print help
```

### `wicket secret list`

```text
List secret names and the host names each may be sent to (never values)

Usage: wicket secret list

Options:
  -h, --help  Print help
```

### `wicket secret remove`

```text
Remove a secret (a reference: only the reference). Nodes holding a copy for a run delete it when the control host next checks that run's secrets, within seconds while connected (#152)

Usage: wicket secret remove <NAME>

Arguments:
  <NAME>  

Options:
  -h, --help  Print help
```

### `wicket secret verify`

```text
Make a secret a verify secret (#578): a webhook trigger's HMAC key, used only to check its deliveries' signatures. It is sent to no host, and can't be bound to one

Usage: wicket secret verify <NAME>

Arguments:
  <NAME>  

Options:
  -h, --help  Print help
```

### `wicket secret hosts`

```text
Bind a secret to the only host names it may be sent to, replacing its list

Usage: wicket secret hosts --hosts <HOSTS> <NAME>

Arguments:
  <NAME>  

Options:
      --hosts <HOSTS>  
  -h, --help           Print help
```

### `wicket secret link`

```text
Make a secret a reference to a JSON field in another file, re-read on every use (never copied): e.g. a harness's login on this host (docs/how-to/store-and-link-secrets.md). A harness login's account fields (never its holder's name) are kept with the reference as they are now, for Remote Control boxes: re-link to refresh them

Usage: wicket secret link [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --file <FILE>
          The file. With --via-helper, only noted (the helper is told its file)
      --pointer <POINTER>
          A JSON pointer into the file (e.g. /login/accessToken). Without one, the whole file is the secret, trimmed (e.g. an API key file). With --via-helper, only noted (it says whose login it is)
      --expires-pointer <EXPIRES_POINTER>
          
      --hosts <HOSTS>
          The only host names it may be sent to (as for `secret set`)
      --via-helper
          Read the secret through `wicket secret serve`, run as the file's owner, instead of reading the file: no ACL on it, and wicket gets only the value the helper serves under this name and its expiry
      --helper-user <HELPER_USER>
          The user the helper runs as (a name or uid); an answer from any other is refused. Default: you (the caller wicketd names)
      --helper-socket <HELPER_SOCKET>
          The helper's socket: `@NAME` (abstract) or a path. Default: @wicket-secret.<uid>
  -h, --help
          Print help
```

### `wicket secret serve`

```text
Serve linked secrets to wicketd, as the owner of the files they are in (a secret helper, #350): run it as that user, e.g. as a systemd user service (deploy/systemd-user/wicket-secret-helper.service). It answers only wicketd's user, and only with each secret's current value and expiry; it reads the file at each request, so a refresh is picked up at once

Usage: wicket secret serve [OPTIONS] --secret <SECRETS>

Options:
      --secret <SECRETS>  A secret to serve: NAME=FILE[#POINTER[#EXPIRES_POINTER]], e.g. claude-login=/home/me/.claude/.credentials.json#/claudeAiOauth/accessToken#/claudeAiOauth/expiresAt
      --for <FOR_USER>    The user it answers (wicketd's; a name or uid) [default: wicket]
      --socket <SOCKET>   Where to listen: `@NAME` (abstract) or a path. Default: @wicket-secret.<your uid>
  -h, --help              Print help
```

## `wicket identity`

```text
Agent identities: the issuer's public key, and verified identity documents.

Agent identities (design §3.2): the issuer's public key, and verified identity documents.

Usage: wicket identity <COMMAND>

Commands:
  init    Set up this installation's identity issuer: its key and its trust domain, which every agent's SPIFFE ID is under (spiffe://<domain>/t/…). The domain is fixed once set
  issuer  Print the installation issuer's public key (JWK) and trust domain: what verifiers need
  show    Verify and show the identity wicket issued for a run
  list    List every agent identity issued, verified
  revoke  Revoke a run's identity at once (e.g. if its environment may be compromised): its box is stopped, its messages are no longer delivered, and its requests can't be approved
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket identity init`

```text
Set up this installation's identity issuer: its key and its trust domain, which every agent's SPIFFE ID is under (spiffe://<domain>/t/…). The domain is fixed once set

Usage: wicket identity init --trust-domain <TRUST_DOMAIN>

Options:
      --trust-domain <TRUST_DOMAIN>  e.g. wicket.example.com: lowercase letters, digits, '.', '-' and '_'
  -h, --help                         Print help
```

### `wicket identity issuer`

```text
Print the installation issuer's public key (JWK) and trust domain: what verifiers need

Usage: wicket identity issuer

Options:
  -h, --help  Print help
```

### `wicket identity show`

```text
Verify and show the identity wicket issued for a run

Usage: wicket identity show <RUN>

Arguments:
  <RUN>  

Options:
  -h, --help  Print help
```

### `wicket identity list`

```text
List every agent identity issued, verified

Usage: wicket identity list

Options:
  -h, --help  Print help
```

### `wicket identity revoke`

```text
Revoke a run's identity at once (e.g. if its environment may be compromised): its box is stopped, its messages are no longer delivered, and its requests can't be approved

Usage: wicket identity revoke [OPTIONS] <RUN>

Arguments:
  <RUN>  

Options:
      --reason <REASON>  [default: "revoked by the operator"]
  -h, --help             Print help
```

## `wicket policy`

```text
The installation's org policy (Cedar): a ceiling and forbids over every zone.

The installation's org policy in Cedar (#51): a ceiling and forbids over every zone, compiled into each box's token when it is minted.

Usage: wicket policy <COMMAND>

Commands:
  show   The org policy's version, and the running runs minted under another
  check  Validate and compile an org policy without installing it
  apply  Install an org policy, and revoke the running runs minted under an older version (their boxes stop; new runs get the new policy)
  zone   A zone's policy as Cedar, generated from a manifest (what its boxes' tokens are compiled from)
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket policy show`

```text
The org policy's version, and the running runs minted under another

Usage: wicket policy show

Options:
  -h, --help  Print help
```

### `wicket policy check`

```text
Validate and compile an org policy without installing it

Usage: wicket policy check [OPTIONS] <FILE>

Arguments:
  <FILE>  

Options:
      --entities <ENTITIES>  The groups zones are in (Cedar entities JSON)
  -h, --help                 Print help
```

### `wicket policy apply`

```text
Install an org policy, and revoke the running runs minted under an older version (their boxes stop; new runs get the new policy)

Usage: wicket policy apply [OPTIONS] <FILE>

Arguments:
  <FILE>  

Options:
      --entities <ENTITIES>  
      --keep-runs            Leave running runs on the policy they were minted under until they end
  -h, --help                 Print help
```

### `wicket policy zone`

```text
A zone's policy as Cedar, generated from a manifest (what its boxes' tokens are compiled from)

Usage: wicket policy zone <MANIFEST>

Arguments:
  <MANIFEST>  

Options:
  -h, --help  Print help
```

## `wicket state`

```text
Control-plane state off this host: the state store, the recovery kit, a restore.

Control-plane state off this host (#154): the state store, the ledger's stream, the recovery kit and a restore onto a standby.

Usage: wicket state <COMMAND>

Commands:
  check      Where each kind of control-plane state goes (state-store.yaml)
  replicate  Stream the ledger to the state store until stopped (Litestream): a lost control host loses at most `ledger.sync_interval`. Run it as a service beside wicketd
  kit        Write a recovery kit: what a standby needs besides the state store (keys, state.key, nodes' feed keys and pinned host keys, config files, and the vault's secrets). Keep it offline
  restore    Make this fresh host the control host: the kit's files, then the ledger from the state store (as of now, or of --at), audit records the store has beyond it, agents fenced, and each node feed set to start a new generation
  snapshots  The ledger snapshots `wicket self update` pushed to the state store before each switch (#167): the way back past a contract step after losing the control host
  snapshot   Fetch one of them (unsealed with state.key) into a new file, to restore as docs/how-to/update-and-roll-back.md says
  gc         Collect the content-addressed stores (#258): delete what no agent's head and no ref reaches, in this host's store and the state store's, and cut this host's down to its cache cap (`local_cache:`, with bundles in the state store). The reconciler does this hourly
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket state check`

```text
Where each kind of control-plane state goes (state-store.yaml)

Usage: wicket state check [OPTIONS]

Options:
      --probe  Also write, read back and delete a probe object in the store
  -h, --help   Print help
```

### `wicket state replicate`

```text
Stream the ledger to the state store until stopped (Litestream): a lost control host loses at most `ledger.sync_interval`. Run it as a service beside wicketd

Usage: wicket state replicate

Options:
  -h, --help  Print help
```

### `wicket state kit`

```text
Write a recovery kit: what a standby needs besides the state store (keys, state.key, nodes' feed keys and pinned host keys, config files, and the vault's secrets). Keep it offline

Usage: wicket state kit [OPTIONS] --out <OUT>

Options:
      --out <OUT>        
      --without-secrets  Leave the vault's secrets out (set them again on the standby)
      --without-roots    Leave the roots out even if they are on this host
  -h, --help             Print help
```

### `wicket state restore`

```text
Make this fresh host the control host: the kit's files, then the ledger from the state store (as of now, or of --at), audit records the store has beyond it, agents fenced, and each node feed set to start a new generation

Usage: wicket state restore [OPTIONS] --kit <KIT>

Options:
      --kit <KIT>  
      --at <AT>    Restore the ledger as it was at this time (RFC 3339, UTC), discarding what came after
      --force      Replace a ledger this host already has
  -h, --help       Print help
```

### `wicket state snapshots`

```text
The ledger snapshots `wicket self update` pushed to the state store before each switch (#167): the way back past a contract step after losing the control host

Usage: wicket state snapshots

Options:
  -h, --help  Print help
```

### `wicket state snapshot`

```text
Fetch one of them (unsealed with state.key) into a new file, to restore as docs/how-to/update-and-roll-back.md says

Usage: wicket state snapshot --out <OUT> <NAME>

Arguments:
  <NAME>  Its name, as `wicket state snapshots` lists it

Options:
      --out <OUT>  
  -h, --help       Print help
```

### `wicket state gc`

```text
Collect the content-addressed stores (#258): delete what no agent's head and no ref reaches, in this host's store and the state store's, and cut this host's down to its cache cap (`local_cache:`, with bundles in the state store). The reconciler does this hourly

Usage: wicket state gc [OPTIONS]

Options:
      --dry-run  Say what would be deleted, and delete nothing
  -h, --help     Print help
```

## `wicket keys`

```text
The installation's root keys.

The installation's root keys (#154).

Usage: wicket keys <COMMAND>

Commands:
  roots-offline  Move the feed root and the authority root off this host (to removable media, say): boxes' tokens are then minted by a certified issuing key, and certificates the roots issue last --days. Nodes pin the same keys as before
  certify        With the roots' directory (--roots, or WICKET_ROOTS): renew the issuing key's and every node feed's certificate for another --days (as chosen at roots-offline), and start the new generation of any feed a restore left. Installed, the wicket user must be able to read it
  roots-online   Put the roots back on this host
  help           Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket keys roots-offline`

```text
Move the feed root and the authority root off this host (to removable media, say): boxes' tokens are then minted by a certified issuing key, and certificates the roots issue last --days. Nodes pin the same keys as before

Usage: wicket keys roots-offline [OPTIONS] --to <TO>

Options:
      --to <TO>      
      --days <DAYS>  [default: 30]
  -h, --help         Print help
```

### `wicket keys certify`

```text
With the roots' directory (--roots, or WICKET_ROOTS): renew the issuing key's and every node feed's certificate for another --days (as chosen at roots-offline), and start the new generation of any feed a restore left. Installed, the wicket user must be able to read it

Usage: wicket keys certify [OPTIONS]

Options:
      --roots <ROOTS>  
  -h, --help           Print help
```

### `wicket keys roots-online`

```text
Put the roots back on this host

Usage: wicket keys roots-online --from <FROM>

Options:
      --from <FROM>  
  -h, --help         Print help
```

## `wicket doctor`

```text
Check the environment: Docker, gVisor, image, secrets, ledger, orphaned boxes

Usage: wicket doctor [OPTIONS]

Options:
      --image <IMAGE>              The agent image to check [default: the default harness's agent image]
      --invariants                 Instead, check this installation's ledger for #321's invariants (#326): every allowed egress request had a reach rule or a live grant, no run's model spend passed its budget, no node ran past its lease, no node was released with a run's work on it uncollected, and no message was pushed to a box twice (#324). Read only; exits non-zero on any violation
      --lease-grace <LEASE_GRACE>  With --invariants: how long past a lease's end a run or the lease may still have ended (the reconciler's cadence), in seconds [default: 600]
  -h, --help                       Print help
```

## `wicket self`

```text
Update this installation to another wicket build, with a health gate and rollback.

Update this installation to another wicket build (#162): blue/green, with a health gate and automatic rollback, on the control host and then its nodes. Only artifacts signed by a release key this installation trusts, or whose sha256 an operator approved (an agent's `request_update`), are accepted. See docs/explanation/updates.md.

Usage: wicket self <COMMAND>

Commands:
  status        The staged versions, which is current and previous, and the ledger's schema
  update        Stage an artifact (a wicket binary, or a release archive from ci/package.sh), switch the control host to it, hand its processes over, and watch it; then the nodes, a canary first. Any failed health check switches back
  follow        Update to the newest build CI signed for main, if `<data dir>/ci-builds.yaml`'s follow policy lets it now (its window, soak time, only forward along main, never across a schema contract step or a failed build). Run by the wicket-follow timer
  rollback      Switch back to the previous version: the control host (unless --only-nodes) and these nodes
  prune         Remove what no rollback or running box needs: versions other than current and previous that no process runs, their agent images unless a container uses them, and ledger snapshots beyond the newest few (always keeping the newest of the current and previous versions')
  trust-key     Trust a release public key (from `wicket self keygen`) for updates
  keygen        Make a release key pair: KEY (private, keep it offline) and KEY.pub
  sign          Sign an artifact with a release key: writes <artifact>.sig
  apply-units   Install this build's systemd units (#165) where they differ from the installed ones, and reload systemd; restarts nothing. Run as root with root's own copy of the version, as a refused `self update` says: `sudo /usr/local/lib/wicket/<id>/wicket self apply-units`
  admit         Make root's own copy of the wicket build in ARTIFACT (a binary or a release archive), in /usr/local/lib/wicket/<id>/ (#261). Root runs only these: `sudo wicket self update ARTIFACT` makes one itself; this is for a build that came another way (`--from-ci`, `self follow`). /usr/local/bin/wicket moves to it if it is the current version. Refuses an artifact the wicket user could have written
  apply-update  Apply an agent's approved update request (#465): the file in its run's outbox with the sha256 the request names, as `self update <it> --nodes all` would, then tell the agent how it ended. The console runs it when an operator approves the request
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### `wicket self status`

```text
The staged versions, which is current and previous, and the ledger's schema

Usage: wicket self status

Options:
  -h, --help  Print help
```

### `wicket self update`

```text
Stage an artifact (a wicket binary, or a release archive from ci/package.sh), switch the control host to it, hand its processes over, and watch it; then the nodes, a canary first. Any failed health check switches back

Usage: wicket self update [OPTIONS] [ARTIFACT]

Arguments:
  [ARTIFACT]  The artifact: a wicket binary, or a release archive

Options:
      --from-ci <COMMIT|latest>  A build CI signed instead (#190): a commit on main, or `latest`. Downloaded here and taken only if signed in the release environment by a trusted key, for this installation's repository (`<data dir>/ci-builds.yaml`) and that commit, on main
      --sig <SIG>                The detached signature (default: <artifact>.sig)
      --nodes <NODES>            Also update these nodes after the control host: `all`, or names (comma-separated). The first is the canary
      --only-nodes               The control host already runs this build: only the nodes
      --window <WINDOW>          How long each new build is watched after its switch [default: 30s]
      --interval <INTERVAL>      How often within the window [default: 10s]
      --check <CHECK>            A command (sh -c) that must succeed each time; $WICKET is the new build's binary and $WICKET_UPDATE_TARGET `control` or `node:<name>`. Repeatable
      --canary <CANARY>          A task manifest the new build runs once on the control host; it must succeed
      --image <IMAGE>            The canary's image (default: the new build's own agent image, tagged with its build id)
      --no-prune                 Keep what the update leaves unneeded (by default it prunes as `wicket self prune` does, where it updated)
  -h, --help                     Print help
```

### `wicket self follow`

```text
Update to the newest build CI signed for main, if `<data dir>/ci-builds.yaml`'s follow policy lets it now (its window, soak time, only forward along main, never across a schema contract step or a failed build). Run by the wicket-follow timer

Usage: wicket self follow

Options:
  -h, --help  Print help
```

### `wicket self rollback`

```text
Switch back to the previous version: the control host (unless --only-nodes) and these nodes

Usage: wicket self rollback [OPTIONS]

Options:
      --nodes <NODES>  `all`, or node names (comma-separated)
      --only-nodes     
  -h, --help           Print help
```

### `wicket self prune`

```text
Remove what no rollback or running box needs: versions other than current and previous that no process runs, their agent images unless a container uses them, and ledger snapshots beyond the newest few (always keeping the newest of the current and previous versions')

Usage: wicket self prune [OPTIONS]

Options:
      --nodes <NODES>                    Also these nodes: `all`, or names (comma-separated)
      --only-nodes                       
      --keep-snapshots <KEEP_SNAPSHOTS>  How many snapshots to keep [default: 5]
      --dry-run                          Say what would go; remove nothing
  -h, --help                             Print help
```

### `wicket self trust-key`

```text
Trust a release public key (from `wicket self keygen`) for updates

Usage: wicket self trust-key <PUBLIC>

Arguments:
  <PUBLIC>  

Options:
  -h, --help  Print help
```

### `wicket self keygen`

```text
Make a release key pair: KEY (private, keep it offline) and KEY.pub

Usage: wicket self keygen <KEY>

Arguments:
  <KEY>  

Options:
  -h, --help  Print help
```

### `wicket self sign`

```text
Sign an artifact with a release key: writes <artifact>.sig

Usage: wicket self sign --key <KEY> <ARTIFACT>

Arguments:
  <ARTIFACT>  

Options:
      --key <KEY>  
  -h, --help       Print help
```

### `wicket self apply-units`

```text
Install this build's systemd units (#165) where they differ from the installed ones, and reload systemd; restarts nothing. Run as root with root's own copy of the version, as a refused `self update` says: `sudo /usr/local/lib/wicket/<id>/wicket self apply-units`

Usage: wicket self apply-units [OPTIONS]

Options:
      --dir <DIR>  Another units directory (default: /etc/systemd/system, which needs root)
  -h, --help       Print help
```

### `wicket self admit`

```text
Make root's own copy of the wicket build in ARTIFACT (a binary or a release archive), in /usr/local/lib/wicket/<id>/ (#261). Root runs only these: `sudo wicket self update ARTIFACT` makes one itself; this is for a build that came another way (`--from-ci`, `self follow`). /usr/local/bin/wicket moves to it if it is the current version. Refuses an artifact the wicket user could have written

Usage: wicket self admit <ARTIFACT>

Arguments:
  <ARTIFACT>  

Options:
  -h, --help  Print help
```

### `wicket self apply-update`

```text
Apply an agent's approved update request (#465): the file in its run's outbox with the sha256 the request names, as `self update <it> --nodes all` would, then tell the agent how it ended. The console runs it when an operator approves the request

Usage: wicket self apply-update <REQUEST>

Arguments:
  <REQUEST>  The approved request (`UPDATE wicket.internal/self/<sha256>`, from `request_update`)

Options:
  -h, --help  Print help
```

## `wicket daemon`

```text
wicketd: serve other users' commands over a unix socket, as the policy allows.

wicketd (#12): run as the wicket system user and serve other users' commands over a unix socket, letting each caller do what the policy grants its uid (from SO_PEERCRED). Approving, denying and other privileged commands need root over the socket, or a passkey in the console. Installed and started by deploy/install.sh.

Usage: wicket daemon [OPTIONS]

Options:
      --socket <SOCKET>
          [default: /run/wicket/wicketd.sock]

      --policy <POLICY>
          Who may read, run and revoke (YAML; default: the wicket-operators group)
          
          [default: /etc/wicket/wicketd.yaml]

  -h, --help
          Print help (see a summary with '-h')
```

## `wicket dev`

```text
Development helpers

Usage: wicket dev <COMMAND>

Commands:
  node-feed-probe  On a node: send `node serve` its own last freshness statement, tampered and then replayed, and print how each was refused (a check for ci/node-e2e.sh). The control connection stays up
  mock-llm         A scripted stand-in for the Anthropic Messages API: each turn runs one Bash command, then calls wicket's finish tool (or hibernate, or neither, as the command's output asks with a `wicket-mock: hibernate` or `wicket-mock: stay` line). Lets the whole path be tested without an API key
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket dev node-feed-probe`

```text
On a node: send `node serve` its own last freshness statement, tampered and then replayed, and print how each was refused (a check for ci/node-e2e.sh). The control connection stays up

Usage: wicket dev node-feed-probe [OPTIONS]

Options:
      --dir <DIR>  
  -h, --help       Print help
```

### `wicket dev mock-llm`

```text
A scripted stand-in for the Anthropic Messages API: each turn runs one Bash command, then calls wicket's finish tool (or hibernate, or neither, as the command's output asks with a `wicket-mock: hibernate` or `wicket-mock: stay` line). Lets the whole path be tested without an API key

Usage: wicket dev mock-llm [OPTIONS] --command <COMMAND>

Options:
      --listen <LISTEN>    [default: 127.0.0.1:9999]
      --command <COMMAND>  The Bash command the mock model asks the agent to run
  -h, --help               Print help
```

## Exit codes

Every command exits with one of these, through the daemon too, so a script can tell what happened
without reading the message (which goes to stderr, after `Error: `).

| Code | Means | For example |
| --- | --- | --- |
| 0 | Done. | |
| 1 | Failed, for any reason the others don't name. | The ledger can't be opened; a node doesn't answer; the daemon's policy file can't be read; asking for a spend's approval failed; `wicket run` whose box failed (a non-zero exit, out of memory, over a cap) or timed out (see below). |
| 2 | A usage error: the command line is wrong. Nothing was changed. | An unknown flag; a duration that isn't one (`--ttl 5q`; every duration flag takes `90s`, `10m`, `1h 30m` or a number of seconds); `wicket approve s-…` (a standing ask: `wicket standing approve`). |
| 3 | Refused: wicket won't do it as asked. | The daemon's policy doesn't allow this caller the command; a decision outside the decider's authority; deciding a request that is already decided; terms wider than the request; answering no at `approve`'s or `standing approve`'s confirmation; a spend an operator denied, or over the installation's money limit; a lease that is already ended; a session on a run that isn't running; `self update` of an artifact whose signature doesn't verify. |
| 4 | Not found: what the command names doesn't exist. | `no such request r-…`; no grant, link, lease, run, agent, node, service, trigger or identity by that name; no placement decision for the run. |
| 5 | It needs an approval nobody has given yet. | `wicket node create` whose spend no capacity grant covers and no operator decided within `--wait` (or `--wait 0`); `wicket self update` of an artifact no trusted key signed and no operator approved. |
| 6 | The run was revoked. | `wicket run` whose run an operator revoked (`wicket grant renew` can't bring it back). |
| 75 | Try again shortly: nothing was done. | wicketd is moving to a new build and took no command. |
| 128 + N | Ended by signal N. | `wicket run` interrupted by Ctrl-C (130) or SIGTERM (143, also a run its parent stopped); a command the daemon ran that a signal ended. |

`wicket run` exits by how its run ended: 0 when its box succeeded or hibernated; 1 when it failed
or timed out; 6 when it was revoked; 128 + the signal when it was interrupted. An agent that runs
out of turns (`agent.max_turns`) has failed: Claude Code exits non-zero then, and the run's last
`[agent] finished` line says `error_max_turns`. `wicket wrap` exits with the wrapped program's own
code when the program ended by itself with a non-zero one (a crash or an outside signal included),
and otherwise as `wicket run` does: a box wicket or its node stopped (a timeout, an expired
authority, out of memory) is 1. `wicket wake`, which wicket runs itself, exits 3 when the agent is
already being woken or is running, or its last activation may still be running on a node this host
can't confirm stopped (until that activation's authority ends).

A command the daemon runs passes its code back through it; one a signal ended exits 128 + the
signal's number, as a shell reports it. If the daemon restarts while a command
runs, the connection drops and the caller exits 1 with "wicketd closed the connection before the
command finished": the command may have done some or all of its work (a run it started goes on), so
look (`wicket top`, `wicket audit`) before running it again.

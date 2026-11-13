# Agents: identity, children, links, sessions and hibernation

What an agent is and can do inside wicket: its identity, its children and messages, links, sessions,
and hibernation. [Concepts](../explanation/concepts.md) explains the ideas; the
[manifest](manifest.md) and the [MCP tools](mcp-tools.md) have every field and argument; [the
box](box.md) is what the agent sees from inside.

## Agent identity and child agents

Every agent run gets an identity issued by the installation (`spiffe://<trust domain>/t/<tenant>/z/<zone>/a/<agent>`),
an EdDSA-signed document whose key is held by wicket, never by the box.

- The trust domain is set once per installation: `wicket identity init --trust-domain wicket.example.com`.
- Show it: `wicket identity issuer` (public key and trust domain for verifiers), `wicket identity list`, `wicket identity show <run>`.
- Pending requests show the requesting agent's verified identity. The console won't approve for an agent
  whose identity doesn't verify.
- Agents talk only through wicket: `send_message` and `await_message` in the gateway. wicket sets and signs the
  sender. Parent and child may always talk; other zones only if the recipient's zone lists them in
  `accept_from`.
- `max_children: N` in the agent spec allows `spawn`: an agent or a program in its own sandbox and identity, in a
  zone the agent writes. That zone must be a subset of the agent's own: reach, credentials, model budget (carved
  out), resources, time, isolation, images and `max_children` (a child's own count against the parent's). Otherwise `spawn` lists what exceeds it, and with `ask_human` puts
  exactly that zone to a human. `spawn_agent` is the shorthand for the agent's own zone narrowed by host. Set
  `in_box_subagents: false` to make wicket children the only kind of subagent.
- Boxes reach each other's ports only through links, which wicket relays (boxes still have no network):
  `expose(port)` offers a port, `connect(box, port)` returns `<name>.wicket.internal:<port>` in the caller's box,
  and `link(from, to, port)` wires two boxes the caller controls. A box's own children are connectable without
  `expose`; others need its `expose` and its zone's `accept_from`, or a human. The target's reach must be within
  the connector's, or a human approves. Every link is audited (`wicket links`, `wicket unlink <id>`), and closes
  when cut, when either end is revoked or when either run ends. See `examples/links/`.
- Identities are short-lived: valid 10 minutes, re-issued every 5 with a fresh key (`WICKET_IDENTITY_TTL` to change).
  `wicket identity revoke <run>` stops the run's box and everything it started, and refuses its messages
  and approvals.
- Every identity records who it acts for, back to the human: `acting for: alice (cli, unix-user) → lead → fetcher`.
- `wicket audit --verify` re-checks every identity ever issued (rotations included) and every message signature,
  offline.

## Longer sessions, volumes and in-place workspaces

These are general features for any workload:
- **`wicket run … --workspace-dir <dir>`** mounts a directory as the box's `/workspace`, in place, instead
  of copying it. `--task "…"` replaces the manifest's task.
- **`zone.volumes`** are named directories under `/volumes/` that persist between runs of a zone: caches,
  datasets, any state.
- **`agent.idle_timeout`** keeps the session open after each turn. **`wicket say <run> "…"`** sends the agent
  a follow-up, which becomes its next turn.
- **Long-lived agents hibernate and wake** (below; [how to](../how-to/hibernate-and-wake-an-agent.md)).
- **`agent.image`** names the image the agent's box starts from (default: the installation's current agent
  image), e.g. a project's own toolchain image. Any other image must be listed in `zone.images`, as for
  `spawn`; a manifest naming one outside it is refused. `wicket run` and runs started from the console use
  it, and `wicket run --image` overrides it.
- **`agent.env`** sets non-secret variables (wicket's own are refused). **`agent.adapter_settings`** passes
  allowlisted settings to the agent's adapter, e.g. turning off commit attribution.
- **`inject` rules can be `optional`:** while the secret isn't in the vault, the rule is as if it weren't
  there (requests go without the header, noted once per run in the audit log, and a host allowed
  wholesale is spliced). `{basic:USER}` renders an HTTP Basic credential (e.g. git over HTTPS with a token).

`examples/self-hosting/` uses all of these to run an agent on wicket's own source; see its README and
[run wicket in wicket](../how-to/run-wicket-in-wicket.md).

## Hibernate and wake

Every Claude Code agent wicket launches on this host is a long-lived agent with an id (`agt_…`), its own
Claude Code session, and a generation number. Each run is one activation of it. `wicket agents` lists them with
their state, generation and bundle size.

- **Idle.** With `agent.hibernate_after` set, the box is paused (`docker pause`) once `idle_timeout` has passed
  after a turn. Its processes and memory are kept, and a follow-up unpauses it.
- **Hibernated.** At `hibernate_after`, or when you run `wicket hibernate <run>`, the agent is hibernated if
  the box is at a quiet point: its turn has ended, and nothing but the agent runtime runs in it. Its box stops,
  and its whole writable state is bundled into wicket's object store: the workspace, all of `/wicket/state`
  (`$HOME` and the Claude Code config), `/tmp`, and the zone's `persist: durable` volumes. Each tree is tar +
  zstd, content-addressed, and its digest is checked again on restore. A box still running something else (a
  background build, a dev server) stays Idle instead, because a rebuild restores files, not processes.
- **Wake.** `wicket wake <agent> ["…"]`, `wicket say <run or agent> "…"`, or a message from another agent
  rebuilds the box. It gets a new identity, CA and placeholders, the state is restored, and Claude Code
  `--resume`s the agent's own session at the same workspace path. The agent's first turn says it was woken,
  and by what. A wake is a compare-and-set claim that bumps the generation, so of two concurrent wakes exactly
  one wins. The proxies refuse requests from a stale generation, and a push of state only commits under the
  current one.
- **Any node.** A long-lived agent can run on any node (`wicket run --node`), not only the control host's
  own (#146). On a node that lays out its own boxes, its state (workspace, `$HOME` and Claude Code's
  config, `/tmp` and durable volumes) is sent there as tar streams over the node's control channel
  before the box starts, and fetched back to be bundled when it hibernates; the node keeps none of it
  afterwards. Its bundle stays on the control host, so a wake isn't tied to a node: it is **bin-packed**
  onto the nodes available then (enrolled, active, answering, not held by a capacity lease, this host's
  own included) by best fit for the zone's `limits` (the fullest node it still fits on; where it last ran
  only breaks ties), and if none has room, onto the least loaded one.
- **Sealed at rest.** Every object of a bundle is encrypted with AES-256-GCM under a key that stays on
  the control host (`<data dir>/state.key`), in 64 KiB chunks bound to the object's key and their order,
  so a changed, swapped or shortened object fails to restore. Bundles written before sealing still
  restore, and the next hibernation writes them sealed. Object keys (content hashes, agent ids) and sizes
  aren't hidden. A store that encrypts at rest itself (S3 with server-side encryption) could do without
  this layer; it also keeps the state from whoever runs the store.
  **Back up `state.key` with the data directory**: without it no hibernated agent can be woken, and
  nothing can recover them. Keep the copy as private as the key (mode 0600, never in the object store).
- **Volumes by class** (`zone.volumes[].persist`):
  - `durable`: the agent's own, bundled;
  - `node` (the default): shared by the zone, kept on the node;
  - `cache`: never bundled, and may be empty after a wake on another node. On one node it behaves like `node`.
- **Budgets belong to the agent, over its whole life.** The zone's model budget (`max_requests`,
  `max_output_tokens`, `max_input_tokens`) and `limits.timeout` (total time in a box, Idle included) are
  recorded on the agent. A wake continues from what is left; it never resets them. Budget handed to children
  counts as spent. An agent that has spent a budget isn't woken again, by any source.
- At the timeout, an idle agent at a quiet point hibernates, and any other is stopped.
- Only a hibernated agent can be woken. If its session ends any other way (stopped, timed out mid-turn, or
  over its `/tmp` cap), the agent is `ended`.
- A long-lived agent's `/tmp` is a directory (in the run's directory, or the node's), so it is kept with the
  rest, and survives a crash of the supervisor. wicket stops the box if `/tmp` goes over 512 MiB, checking
  every 5 s (on a remote node, by asking it); the old tmpfs enforced that cap exactly.
- wicket sets Claude Code's `cleanupPeriodDays` itself, so a sleeping agent's sessions aren't swept, and a
  manifest can't set it.
- `ci/hibernate.sh` tests all of this end to end with the mock model; `ci/hibernate.sh --node` with the
  agents on an enrolled node.

Not yet: signing of bundles, an S3 backend, and the gVisor checkpoint fast path. Wrapped sessions
(`wicket wrap`) run only on the control host's own node: the box takes over its launcher's stdio protocol
and its working directory at the same path, and a node's channel may drop output while disconnected, which
that protocol can't survive.

## Remote sessions and wrapped agents

Two ways for the owner to drive an agent in a box from the vendor's apps: `agent.remote`, which
boots the harness's own remote-session feature in the box (#169), and `wicket wrap`, which boxes an
agent process another program launches. [Drive a box from the Claude apps](../how-to/drive-a-box-from-the-claude-apps.md)
has both, with what each protects.

Zones can also `forbid` hosts or paths outright, and `unlisted_hosts: hide` makes anything the zone
doesn't name look like it doesn't exist ([manifest](manifest.md#zone)). Agents ask ahead for reach
with `request_access`.

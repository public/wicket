# Agents: identity, children, links, sessions and hibernation

Reference for what an agent can do inside wicket. The README has the short version; [concepts.md](concepts.md) explains the ideas.

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
  out), resources, time, isolation and images. Otherwise `spawn` lists what exceeds it, and with `ask_human` puts
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
- **Long-lived agents hibernate and wake** (see below).
- **`agent.env`** sets non-secret variables (wicket's own are refused). **`agent.adapter_settings`** passes
  allowlisted settings to the agent's adapter, e.g. turning off commit attribution.
- **`inject` rules can be `optional`,** and `{basic:USER}` renders an HTTP Basic credential (e.g. git over
  HTTPS with a token).

`examples/self-hosting/` uses all of these to run an agent on wicket's own source; see its README.

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
- A local box's `/tmp` is a host directory in the run's directory, so it is kept with the rest, and survives a
  crash of the supervisor. wicket stops the box if `/tmp` goes over 512 MiB, checking every 5 s; the old tmpfs
  enforced that cap exactly.
- wicket sets Claude Code's `cleanupPeriodDays` itself, so a sleeping agent's sessions aren't swept, and a
  manifest can't set it.
- `ci/hibernate.sh` tests all of this end to end with the mock model.

Not yet: encryption and signing of bundles, an S3 backend, the gVisor checkpoint fast path, and hibernating
boxes on remote nodes or wrapped sessions.

## Inside the box

wicket's proxy, model route and MCP gateway are at `wicket.internal` (198.18.0.1, set up by the box's entry
script), so the agent has all of localhost for its own servers. Links to other boxes get addresses from
198.18.1.1 onward and names in the box's hosts file, which wicket owns and the box can only read. The entry script adds that address as root
with only the network-admin capability, then runs everything as the agent's user with no capabilities.

The box's resolver is wicket.internal:53: wicket answers every query itself, so a lookup can't carry data
out. Every host the zone can reach resolves to its own address in 198.19.0.0/16 (on the box's loopback);
QUIC sent there is relayed to wicket over a bind-mounted unix socket and served as that host. Under gVisor
each UDP datagram is costly (about 110 µs of CPU in the box), so HTTP/3 downloads run at 40–100 Mbit/s with
the usual 1452-byte packets. `WICKET_H3_BOX_MTU=16000` lets the box's leg (loopback and a unix socket, no
real link) use 16000-byte packets for clients that accept them: 430–460 Mbit/s in #92's measurements.
`WICKET_H3_HTTPS_RECORDS=0` stops wicket answering HTTPS (`alpn=h3`) DNS records.
The forwarder holds UDP port 443 on every address in the box (it catches QUIC to any synthetic address),
so a server in the box can't take UDP 443, even on 127.0.0.1; TCP 443 and every other port stay the agent's.

## Agents launched by something else, e.g. Remote Control

`wicket wrap --manifest <m> -- <agent command line>` runs an agent that another program launches inside a box,
with stdio connected through. `examples/remote-control/` uses it as Claude Code's `CLAUDE_CODE_PROCESS_WRAPPER`,
so a session you drive from the Claude app runs in gVisor. It holds only placeholder credentials, which the
proxy swaps for the real ones on `api.anthropic.com` alone. See its manifest for the reach a session needs.

Zones can also `forbid` hosts or paths outright, and `unlisted_hosts: hide` makes anything the zone doesn't name
look like it doesn't exist. Agents ask ahead for reach with `request_access`.

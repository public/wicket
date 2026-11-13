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
- **Long-lived agents hibernate and wake** (see below).
- **`agent.env`** sets non-secret variables (wicket's own are refused). **`agent.adapter_settings`** passes
  allowlisted settings to the agent's adapter, e.g. turning off commit attribution.
- **`inject` rules can be `optional`:** while the secret isn't in the vault, the rule is as if it weren't
  there (requests go without the header, noted once per run in the audit log, and a host allowed
  wholesale is spliced). `{basic:USER}` renders an HTTP Basic credential (e.g. git over HTTPS with a token).

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

## Remote sessions: a box you drive from the vendor's app (#169)

`agent.remote: { name: <session name> }` boots the harness in the box with its own remote-session
feature on, so the box registers a session with the vendor and the owner drives it from the vendor's
apps. The task is optional: the first message comes from the app. Harness adapters that have no such
feature refuse the manifest, saying so. For `kind: claude-code` it is Remote Control:
`claude remote-control --spawn session` in the box, which shows up in the Claude apps (desktop, web,
phone); `examples/remote-control-box.yaml` is a whole zone for it.

- **The account login never enters the box.** A remote session needs the owner's full login (for
  Claude, the claude.ai OAuth login: it can list and drive the account's sessions), not an inference
  token. Link it by reference, bound to the provider's hosts:

  ```sh
  wicket secret link claude-login --file ~/.claude/.credentials.json \
      --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt --hosts api.anthropic.com
  ```

  and name it as the zone's `llm.secret`. The box gets a placeholder login (a credentials file whose
  access token is a placeholder, expiring far ahead, and a refresh token that refreshes nothing).
  The egress proxy swaps the placeholder for the real access token on the hosts the secret is bound
  to, and only on the paths the zone's reach allows. The secret is read at each use, so the host's own
  Claude Code keeps it fresh; the refresh token never leaves the host. The per-session tokens the API
  hands the box for its session go up as the box sent them, since they aren't wicket's to hold.
  Only the login's non-secret account fields reach the box (scopes, plan, and the account and
  organization ids Claude Code checks before it starts Remote Control; not the holder's name).
- **Reach is the authority.** Everything the zone reaches on the provider's host is reached with the
  owner's login, so the example names only what a session needs (registering its environment, its
  work and worker channel, model calls, the profile), forbids the account's connectors
  (`mcp-proxy.anthropic.com`, `/v1/mcp_servers`) and token refresh outright, and leaves everything
  else (other sessions, triggers, memory) to a human's decision, as in any zone: deny those.
- **Inside the box** Claude Code is set up so nothing waits on a terminal that isn't there: the
  workspace is trusted, Remote Control's one-time prompt is answered, wicket's gateway is the only MCP
  server, and the sandbox notice is the user memory. Claude Code asks in the app before it acts
  (permission mode `default`); wicket decides what the box can reach either way.
- **Where to open it.** `wicket run` prints `[wicket] remote session: <url>` when the session is up,
  it is recorded as `run.remote_session`, and the console links it on the run's card.
- **Nodes.** It runs on any node: the node forwards the provider's host to the control host, where the
  login is swapped in, so the secret stays with the control host.
- **Not with hibernation.** The session lives in the vendor's apps, so `hibernate_after` is refused;
  the box ends with its session. A supervisor that is handed over (`wicket self update`, #151) rebuilds
  the swap from the manifest.

## Agents launched by something else, e.g. Remote Control

`wicket wrap --manifest <m> -- <agent command line>` runs an agent that another program launches inside a box,
with stdio connected through. `examples/remote-control/` uses it as Claude Code's `CLAUDE_CODE_PROCESS_WRAPPER`,
so a session you drive from the Claude app runs in gVisor. It holds only placeholder credentials, which the
proxy swaps for the real ones on `api.anthropic.com` alone. See its manifest for the reach a session needs.

Zones can also `forbid` hosts or paths outright, and `unlisted_hosts: hide` makes anything the zone doesn't name
look like it doesn't exist. Agents ask ahead for reach with `request_access`.

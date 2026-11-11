# wicket

A Rust meta-harness: it builds least-privilege environments for other agent processes (Claude Code first,
any agent in principle), brokers every boundary crossing (model API, HTTP egress, git, MCP tools) from
outside the sandbox, and shows humans the boundaries as zones and gates.

- Concepts (canonical): Claude Doc "wicket — core concepts"; pointer in [docs/concepts.md](docs/concepts.md).
- Detailed design: [docs/design.md](docs/design.md). Research notes: [docs/research/](docs/research/).
  Prior art: [docs/prior-art.md](docs/prior-art.md).

## Proof of concept

The PoC is a vertical slice of milestones M0 and M1: one Claude Code agent, one zone, one sandbox, single tenant
(`t0`, with tenant ids carried everywhere so platform mode can be added).

![PoC architecture: processes, trust boundaries and what runs where](docs/poc-architecture.svg)

What it does:
- runs Claude Code in a **gVisor** container with **no network** (`--network none`, read-only root, all
  capabilities dropped);
- the box's only way out is two unix sockets bind-mounted in: the **LLM proxy** (holds the Claude subscription
  token, strips the agent's placeholder, enforces request and token budgets, strips server-side tools; wicket never
  uses Anthropic API keys) and the **egress proxy**
  (per-run CA, TLS interception, canonicalize-or-reject, reach rules, a GitHub dangerous-pattern list, credential
  injection into one declared header slot);
- a minimal **MCP gateway** is the agent's only MCP server; its `await_grant` tool lets a blocked agent wait for
  the human's decision instead of sleeping and retrying;
- requests outside the zone's reach become **pending escalations** (HTTP 403 problem+json with a request id); a
  human approves or denies them with `wicket approve` / `wicket deny`, and the grant is single-use and expiring by
  default, recorded in a SQLite ledger;
- every decision goes into a **hash-chained audit log** (`wicket audit --verify`).
- if a `wicket run` process dies hard, its box is flagged by `wicket doctor` and stopped by `wicket reap`
  (each box is labelled with the process that owns it); the run ends as `lost`.

#### Agent identity and child agents

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
- Identities are short-lived: valid 10 minutes, re-issued every 5 with a fresh key (`WICKET_IDENTITY_TTL` to change).
  `wicket identity revoke <run>` stops the run's box and everything it started, and refuses its messages
  and approvals.
- Every identity records who it acts for, back to the human: `acting for: alice (cli, unix-user) → lead → fetcher`.
- `wicket audit --verify` re-checks every identity ever issued (rotations included) and every message signature,
  offline.

#### Remote nodes and enrolment

`wicket run --node <name-or-ssh-target>` runs the box on another machine over ssh (prepare one with
`deploy/vultr/node-setup.sh`). The proxies, ledger and keys stay on the control host; the run's sockets are
forwarded to the node. Enrol a node first, so its ssh host key is pinned:

```sh
wicket node token --name n1 --ttl 1h        # prints a one-time join token (stored hashed)
wicket node enrol wicket@203.0.113.7 --token wkt_… --host-key 'SHA256:…' --hosts 'api.example.com,*.example.org'
wicket run task.yaml --node n1
wicket node list
wicket node renew-ca n1                     # a fresh node CA (default 24 h)
wicket node revoke n1
```

- **Host key.** `--host-key` takes the node's key line or its `SHA256:` fingerprint, which should come from
  somewhere other than the network (the provider's console, cloud-init output, the image). Without it,
  `enrol` refuses unless you pass `--trust-first-use`, and then prints the fingerprint it pinned. After that, every
  ssh call uses a wicket-managed known_hosts (`<data dir>/nodes/<name>/known_hosts`) with
  `StrictHostKeyChecking=yes`, so a node with any other key is refused. A `--node` target that isn't enrolled
  still works the old way (trust on first use), with a warning. A revoked node is refused.
- **Join token.** It's single-use, expires, and names the node. The operator redeems it on the control host
  with `enrol`. It shows that whoever minted it meant that name to join, and it never goes to the node. Passed as `--token`,
  it shows up in `ps` and shell history, which is acceptable only because it's single-use and short-lived.
- **What the node gets** (in `~/.local/share/wicket-node`, mode 0600). It generates its own **Ed25519 node key**
  and a P-256 **node CA** key with `openssl`, and neither private key leaves the node. The control host signs the
  CA's request as a short-lived (24 h) intermediate under the installation CA (`ca.key`, next to the issuer key).
  The intermediate has path length 0 and is **name-constrained** to `--hosts`, with all IP addresses excluded.
  The node also gets the feed root's and the issuer's public keys.
- **Name constraints are subtrees.** `api.example.com` also permits names under it (`x.api.example.com`), and
  `*.example.org` permits every name under `example.org` but not `example.org` itself. X.509 can't express
  "exactly this host". The reach rules stay the exact gate, and the constraint bounds what a stolen node CA can
  do until it expires.
- **Revoking** deletes the pinned key and records the node CA's serials for the feed's revocation list (not
  distributed yet). Nothing runs on the node yet: egress decisions move there with `wicket node serve` (#57).

## Requirements

Linux with Docker and gVisor (`runsc`) registered as a Docker runtime with `--host-uds=open`:

```json
{ "runtimes": { "runsc": { "path": "/usr/bin/runsc", "runtimeArgs": ["--host-uds=open"] } } }
```

Rust (stable) to build.

### Quick start

```sh
cargo build --release -p wicket-cli
./target/release/wicket image              # builds wicket/claude-code:poc
./target/release/wicket identity init --trust-domain wicket.example.com   # once: your installation's domain
# the model credential is your Claude subscription (never an API key). Either reference the login already on this host
# (read at each use, never copied, refresh untouched):
./target/release/wicket secret link claude-oauth --file ~/.claude/.credentials.json \
    --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
# ...or store a long-lived token from `claude setup-token`:  ./target/release/wicket secret set claude-oauth
./target/release/wicket doctor
./target/release/wicket run examples/hello-github.yaml
# in another terminal, while the run waits:
./target/release/wicket pending
./target/release/wicket approve r-xxxxxxxx      # or: wicket deny r-xxxxxxxx
./target/release/wicket audit --tail 20
./target/release/wicket serve              # operator console on 127.0.0.1:8787; prints a one-time sign-in link
```

The console (`wicket serve`) shows what's waiting for you, runs, recent decisions and activity, and you approve
or deny from a browser or phone. It uses **passkeys**:
- the first passkey is enrolled through a one-time link printed at start-up (single use, 10 minutes, valid only
  while no passkey exists, and it can do nothing but enrol);
- sign-in is a passkey with user verification;
- **every approve or deny is signed again**, over a challenge that is the hash of exactly that decision
  (request, method, host, path, decision, uses, lifetime). The server checks it, uses it once, and stores the
  signed record, so `wicket audit --verify` re-verifies every decision offline;
- `wicket operator reset` (host only) revokes passkeys but keeps their public keys for verification.

Signed in, the console can also do what was CLI-only, each action signed with a fresh passkey assertion over
exactly its parameters, checked again when applied, audited with the passkey that signed it and re-verified by
`wicket audit --verify`:
- **start a run** from a manifest in an allowlisted directory, with an optional task override. The directories are
  the installation's `manifests/` (`$WICKET_HOME/manifests`, by default `~/.local/share/wicket/manifests`) and
  `examples/` of the directory `wicket serve` was started in. The browser picks a directory and a file name from
  the list the server offers (regular files named `*.yaml`/`*.yml` directly in them; no symlinks, subdirectories
  or paths), and the passkey signs the manifest's SHA-256, so a file changed after you saw it is not started. The
  run is a detached `wicket run` (it outlives the console; its log is `runs/<run>/console.log`), and its principal
  is you, the passkey-signed-in operator (`passkey:<name>, via console`), not the host's unix user;
- **send a follow-up** to a running agent (`wicket say`);
- **revoke an identity** with a reason (`wicket identity revoke`);
- **answer `request_access` asks**, including prefix asks: the passkey signs that the grant covers every path
  under the prefix, and, as for every approval, the agent's verified identity. An agent whose identity doesn't
  verify (or was revoked since you were shown the ask) can be denied, not approved.

Open it as `http://localhost:8787` (WebAuthn needs a secure context). `wicket approve` on the host remains a
break-glass path and is audited as such.

![console](docs/console-passkey.png)

**Programs** (deterministic workloads, no model): `examples/program-repo-stats.yaml` runs a script in the same
sandbox with the same egress control. Pin the approved source with `digest:` (from `wicket program digest DIR`), and
any change is refused until re-approved. Out-of-reach requests fail instead of escalating (`on_pending: fail`).

For testing without a model, `examples/mock-github.yaml` plus `wicket dev mock-llm --command '...'` drives the whole path
with a scripted model.

### Longer sessions, volumes and in-place workspaces

These are general features for any workload:
- **`wicket run … --workspace-dir <dir>`** mounts a directory as the box's `/workspace`, in place, instead
  of copying it. `--task "…"` replaces the manifest's task.
- **`zone.volumes`** are named directories under `/volumes/` that persist between runs of a zone: caches,
  datasets, any state.
- **`agent.idle_timeout`** keeps the session open after each turn. **`wicket say <run> "…"`** sends the agent
  a follow-up, which becomes its next turn.
- **`agent.env`** sets non-secret variables (wicket's own are refused). **`agent.adapter_settings`** passes
  allowlisted settings to the agent's adapter, e.g. turning off commit attribution.
- **`inject` rules can be `optional`,** and `{basic:USER}` renders an HTTP Basic credential (e.g. git over
  HTTPS with a token).

`examples/self-hosting/` uses all of these to run an agent on wicket's own source; see its README.

### Inside the box

wicket's proxy, model route and MCP gateway are at `wicket.internal` (198.18.0.1, set up by the box's entry
script), so the agent has all of localhost for its own servers. The entry script adds that address as root
with only the network-admin capability, then runs everything as the agent's user with no capabilities.

### Agents launched by something else, e.g. Remote Control

`wicket wrap --manifest <m> -- <agent command line>` runs an agent that another program launches inside a box,
with stdio connected through. `examples/remote-control/` uses it as Claude Code's `CLAUDE_CODE_PROCESS_WRAPPER`,
so a session you drive from the Claude app runs in gVisor. It holds only placeholder credentials, which the
proxy swaps for the real ones on `api.anthropic.com` alone. See its manifest for the reach a session needs.

Zones can also `forbid` hosts or paths outright, and `unlisted_hosts: hide` makes anything the zone doesn't name
look like it doesn't exist. Agents ask ahead for reach with `request_access`.

### Not in the PoC yet

Adapter-generated MCP tools and third-party MCP servers, multiple zones and gates, labels and handles, hibernation
and wake, Cedar policy, multi-tenant mode, other agents (Codex, pi). Response bodies are not scrubbed for
reflected credentials (headers are). See the milestones in docs/design.md.

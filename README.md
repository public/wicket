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

#### Remote nodes and enrolment

`wicket run --node <name>` runs the box on another machine (prepare one with `deploy/vultr/node-setup.sh`).
On an **enrolled** node, the node's own `wicket node serve` runs the box and decides its egress locally from
a signed policy feed, so the box keeps working, failing narrow, while the control host is unreachable (#57;
below). The ledger, the keys that matter, the LLM proxy and the MCP gateway stay on the control host. A
`--node` ssh target that isn't enrolled still works the old way: docker over ssh, the run's sockets forwarded.

```sh
wicket node token --name n1 --ttl 1h        # prints a one-time join token (stored hashed)
wicket node enrol wicket@203.0.113.7 --token wkt_… --host-key 'SHA256:…' --hosts 'api.example.com,*.example.org'
wicket node install n1                      # copies this wicket binary there, starts the wicket-node service
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
  distributed yet).

##### `wicket node serve`: boxes that outlive the control channel

- **Install.** `wicket node install <name>` copies the control host's own binary to `~/.local/bin/wicket` on the
  node over the pinned ssh connection, checks its sha256 there, and installs a `systemd --user` unit,
  `wicket-node`, that runs `wicket node serve`. `node-setup.sh` enables lingering for the `wicket` user so the
  unit runs without a login. `serve` refuses a control host running any other build (sha256 of the binary): run
  `install` again after upgrading.
- **The node owns the box.** It runs `docker run` itself and relays the box's stdin, stdout and stderr over one
  multiplexed, length-prefixed control channel: `ssh <pinned> <node> wicket node attach`, which joins the ssh
  session to `serve`'s unix socket (`~/.local/share/wicket-node/ctl/ctl.sock`, directory 0700). When the channel
  drops the box keeps running; the node keeps up to 4 MiB of output per stream (oldest dropped first, and the
  control host reports the gap), replays it when the control host reconnects (backoff 0.5 s to 5 s), and
  enforces the run's timeout itself. Unsent stdin is resent. Live egress events from the disconnected period
  aren't shown on the console, but are in the node's audit log.
- **Decisions on the node.** Each box's egress proxy decides from the node's verified replica of the feed
  (`wicket-feed`; the zone, and grants bound to the box), with the same proxy code as the control host (only
  the decision source differs, `wicket_proxy::decide`):

  | node's feed | allowed | out of reach |
  |---|---|---|
  | fresh (a statement within the TTL, 30 s) | reach rules and live grants | the control host raises a pending request (`wicket pending`, `wicket approve` as usual); 403 with its id |
  | narrow (up to the narrow window after, 120 s) | plain reads (R1) in reach only | 403 "the control plane is unreachable; retry later", no request id |
  | closed | nothing | 403, the same |

  Approved grants for the box's requests are pushed to the node as feed grants bound to the box, and the node
  counts their uses: the ledger hands them over and never consumes them too. A path-prefix grant is honoured on
  a node for the asked path only. `wicket grant revoke <id>` (picked up within 250 ms) and a run revocation
  (`wicket identity revoke`, within 2 s) are pushed to the node, which applies them as soon as they arrive; a node
  that hears nothing goes stale within the TTL anyway. A tampered, replayed or rolled-back
  feed frame is refused.
- **TLS.** The node terminates TLS with its own node CA, and the box's CA bundle holds the installation root (for
  the node CA's leaves) and the run's own CA on the control host. The node never terminates, and instead tunnels
  the raw CONNECT over the channel to the control host's egress proxy for the run (which decides and terminates
  it with the run CA), for: hosts with an `inject` rule or a credential swap (secrets stay on the control host),
  hosts outside the node CA's name constraints (e.g. hosts approved later under `unlisted_hosts: escalate`), and
  every host once the node CA has expired. Grants for those hosts stay in the ledger. While disconnected, they
  fail with a clear 403. The LLM proxy and the MCP gateway are reached the same way, through tunnels.
- **Audit and clock.** The node keeps its own hash-chained audit log (`audit.db`, wicket's ledger format) and
  ships it on every connect; the control host stores each record as `node.audit` and `wicket audit --verify`
  recomputes each node's chain. Feed decisions use the wall clock read once at start and advanced by a monotonic
  clock, so a clock step on the node can't stretch a freshness statement (after a deliberate clock step, restart
  `wicket-node` so it reads the wall clock again).
- **For now.** One run per node at a time (the run holds the node's feed; #38's reconciler will own it), child
  agents can't use a served node, plain `http://` to a forwarded host is refused, and the MCP gateway still
  decides on the control host. `ci/node-e2e.sh --local` runs the whole scenario with localhost as the node (only
  the ssh hop is replaced); `ci/node-e2e.sh <node>` runs it against a real enrolled node.

#### Provisioning nodes (`wicket place`)

`crates/wicket-placement` is the placement interface (#37): request capacity (CPU, memory, isolation tier,
region and plan hints, a price limit, an idempotency key) and get a node back; list, get and release owned
nodes. Backends are the operator's own machines (static hosts) and Vultr. `wicket place` drives the Vultr one:

```sh
wicket secret set vultr-api-key                     # read from the terminal; only ever sent as the API's bearer token
wicket place plans --region lhr                     # plans and their hourly price
wicket place create --name n2 --region lhr --vcpus 1 --memory-mib 2048 --lifetime 1h \
  --max-hourly 0.05 --max-total 0.50 --ssh-key-id <id of a key in the Vultr account> --ssh-key <its private key> \
  --hosts 'api.example.com'
wicket place list                                   # owned nodes, lease end and next paid hour
wicket place release <instance-id>                  # destroy now and revoke the enrolment
```

- **Money.** `--max-hourly` and `--max-total` are the envelope: every owned node's hourly rate together, and
  every owned node's cost through its lease plus the new node's worst case. Anything beyond it is refused, and
  everything inside it still waits for `yes` on the terminal, with the plan, rate and worst case shown. Vultr
  bills per started hour, each line rounded up to the cent, with a 672 h monthly cap, so a node's lease ends at
  minute 50 of its last hour and `list` shows when the next paid hour starts.
- **Ownership.** Instances are tagged `wicket-owner-<installation>` (`--owner`, default the trust domain).
  Nothing without that tag, or with `wicket-protected`, is listed or destroyed. A retried `create` with the same
  `--idempotency-key` finds the first instance by its tag instead of making a second one.
- **Host key.** wicket generates the node's ssh host key, installs it through cloud-init as the node's only
  host key, and pins it before the node boots. Then it waits for `node-setup.sh` to finish (over ssh, accepting
  only that key), enrols the node with `--host-key`, and replaces the instance's user data so the private key
  isn't left in the metadata service. There's no trust on first use: `wicket node enrol --trust-first-use` is
  only for nodes made some other way.
- **Not yet:** `spawn` with a placement hint, warm reuse across processes, and the reconciler daemon (#38,
  for which `wicket_placement::reconcile` is the pure decision function).

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
script), so the agent has all of localhost for its own servers. Links to other boxes get addresses from
198.18.1.1 onward and names in the box's hosts file, which wicket owns and the box can only read. The entry script adds that address as root
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

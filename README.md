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
- **HTTP/3** goes the same way: the box resolves names through **wicket's DNS** (reachable hosts get a
  synthetic address in 198.19.0.0/16, hidden and forbidden hosts NXDOMAIN), its forwarder relays QUIC to
  wicket, and wicket terminates it with the run's CA and decides each request exactly like an HTTP/1.1
  one, re-originating it over HTTP/3 when the origin offers it (else HTTP/2); 0-RTT is refused;
- a minimal **MCP gateway** is the agent's only MCP server; its `await_grant` tool lets a blocked agent wait for
  the human's decision instead of sleeping and retrying;
- requests outside the zone's reach become **pending escalations** (HTTP 403 problem+json with a request id); a
  human approves or denies them with `wicket approve` / `wicket deny`, and the grant is single-use and expiring by
  default, recorded in a SQLite ledger;
- every decision goes into a **hash-chained audit log** (`wicket audit --verify`).
- if a `wicket run` process dies hard, its box is flagged by `wicket doctor` and stopped by `wicket reconcile`
  (or `wicket reap`; each box is labelled with the process that owns it); the run ends as `lost`.

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
wicket node renew-ca n1                     # a fresh node CA and identity certificate (default 24 h each), over ssh
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
  The node also gets the feed root's and the issuer's public keys, and a **node identity certificate**
  (`node-cert.jwt`, below).
- **Node identity and mutual authentication.** The issuer certifies the node key as
  `spiffe://<trust domain>/node/<name>` in a short-lived (24 h, `--cert-ttl`) certificate, and the ledger
  records its serial. Every control connection starts with a handshake on top of ssh: the node signs a fresh
  challenge with its node key and shows its certificate; the control host signs one with the issuer key. The
  control host refuses a node whose certificate isn't this installation's, names another node, binds a key
  other than the enrolled one, has expired, was never recorded or is revoked. The node refuses a control host
  that can't prove the issuer key, and until one does, the connection it already has is left alone. At
  half-life the run renews the certificate over the channel; a node that was unreachable until its certificate
  expired gets a new one with `wicket node renew-ca`. The handshake doesn't depend on ssh: a QUIC or mTLS
  transport would reuse it, passing its TLS exporter as the channel binding (`wicket_identity::node`).
- **Name constraints are subtrees.** `api.example.com` also permits names under it (`x.api.example.com`), and
  `*.example.org` permits every name under `example.org` but not `example.org` itself. X.509 can't express
  "exactly this host". The reach rules stay the exact gate, and the constraint bounds what a stolen node CA can
  do until it expires.
- **Revoking** deletes the pinned key, revokes the node's identity certificates (a run connected to the node
  stops its box there and drops it within a second, and nothing reconnects), and records the node CA's serials
  for the feed's revocation list (not distributed yet).

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
- **Not yet:** warm reuse across processes.

#### Capacity leases and the reconciler

An agent asks for a machine of its own with the gateway's `request_capacity` tool (CPU, memory, isolation tier,
region, duration, an hourly price cap, a reason). Capacity is a **lease**, never a cloud credential:

1. The ask becomes a pending lease in the ledger with its worst case reserved (every started hour at the
   agent's own cap), atomically against `max_hourly_usd`/`max_total_usd` in `placement.yaml`
   (`examples/placement/placement.yaml`; without it the tool is off). Over budget is refused before a human sees it.
2. A human decides it like any escalation (`wicket pending`, `wicket approve`/`deny`, or the console). The
   approval is bound to that lease: the placer may spend only on its node, and only up to its reservation.
3. The reconciler acquires the node (a static host, or a fresh Vultr node with its host key pinned before it
   boots), enrols it and runs `wicket node install`. The agent waits with `request_capacity {lease}`, then
   starts children there with `spawn` and `placement: {"lease": "l-…"}` (or `{"node": "<name>"}` for the node
   it runs on, or a leased one). A child runs there through `wicket node serve`.
4. At the lease's end, or when its holder run ends, the runs placed on it stop and its node is destroyed (on
   Vultr, before the next paid hour); the lease records what the node billed.

```sh
wicket reconcile --dry-run        # what one pass would change
wicket reconcile                  # one pass
wicket reconcile --every 30s      # the daemon: run it beside `wicket serve`, e.g. as a systemd user service
wicket lease list                 # status, holder run, node, reserved, end, billed
wicket lease release <lease>      # end it now (one pass)
```

One pass (`wicket reconcile`, #38) compares the provider's instances, enrolled nodes and the boxes on this host
and on every node with the ledger's runs and leases, and makes them agree. `wicket approve` of a capacity ask runs
a pass at once; everything else (lease ends, approvals on the console) waits for the next `--every` pass.

- **Runs** whose `wicket run` process is gone end as `lost` (a run supervised on another machine is left to it).
- **Leases** end when their run has ended or their end has passed; denied or withdrawn asks give their
  reservation back.
- **Machines.** Only instances tagged `wicket-owner-<installation>` are ever listed. One no live lease needs is
  destroyed; one that matches a lease the ledger lost track of (a crash between create and record) is adopted,
  not created again. Ownership is checked again right before every destroy, so a tag changed or a
  `wicket-protected` tag added since the list saves the machine.
- **Boxes** (`wicket=1` containers) whose run ended or whose owner process died are stopped; a box whose run this
  ledger doesn't know is left alone, since Docker may be shared. This subsumes `wicket reap`.
- Every change is an audit record `reconcile.<what>`. One pass at a time per installation (a file lock).
- So killing every control-plane process mid-run and restarting leaves no orphaned machine or box after one
  pass. **Not yet:** the daily money reconcile against the provider's own charges (design §8.5).

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
- passkeys are enrolled only through one-time links from the host: `wicket serve` prints one at start-up while no
  passkey exists, and `wicket operator enrol-link [--ttl 10m] [--origin URL]` prints a fresh one at any time
  (single use, 10 minutes by default and at most 1 hour; the session it opens can only enrol one passkey). A
  signed-in console session can't add a passkey, so a stolen cookie can't either;
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

#### The console on the public internet

The console is built to be reachable directly from the internet, with no VPN or access proxy in front (#23).
Passkeys stay the only authentication.

```sh
# HTTPS from wicket itself, with a Let's Encrypt certificate validated over TLS-ALPN-01 on this listener:
wicket serve --listen 0.0.0.0:443 --acme-domain console.example.com --acme-agree-tos \
    --acme-contact mailto:ops@example.com          # --acme-staging to try it out first
# ...or with certificate files (re-read when they change, e.g. after certbot renews them):
wicket serve --listen 0.0.0.0:443 --origin https://console.example.com \
    --tls-cert /etc/wicket/fullchain.pem --tls-key /etc/wicket/privkey.pem
# ...or behind a TLS-terminating proxy (which then must be the only way in):
wicket serve --listen 10.0.0.5:8787 --behind-tls-terminator --origin https://console.example.com \
    --trusted-proxy 10.0.0.2
```

- **Transport.** A non-loopback listener refuses to start in plain HTTP unless `--behind-tls-terminator` is given
  with an `https://` `--origin`. TLS is rustls: TLS 1.3, and TLS 1.2 with ECDHE and AEAD suites only; HTTP/1.1
  only (no h2, so there is one HTTP implementation to bound). HTTPS responses carry
  `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (submitting the domain to the
  preload list is your step). ACME keeps its account and certificate in `$WICKET_HOME/acme` (0700/0600) and
  renews 30 days before expiry; binding :443 needs `CAP_NET_BIND_SERVICE` (or a port redirect).
- **Before sign-in** a client can fetch only the page, its static files (script, stylesheet, manifest, icons)
  and the passkey sign-in endpoints. Everything else, whatever the method or path, gets the same 401 and body:
  no runs, counts, passkey ids or version. Enrolment is only via a one-time link issued on the host (`wicket operator enrol-link`).
- **Sign-in** needs user verification; there is no password or fallback. Attempts are limited per client
  address (IPv4, or IPv6 /64; `X-Forwarded-For` is honoured only from a `--trusted-proxy`) and per passkey:
  20 a minute, and 5 failures lock out for 15 minutes, doubling up to a day. Pending challenges are bounded
  (1024 in all, 8 per client, 2-minute expiry). Every failure looks the same to the client, and every failure
  and lockout is in the audit log.
- **Sessions** are `__Host-wicket_sid` cookies (Secure, HttpOnly, SameSite=Strict, Path=/), new at every
  sign-in, ending after 15 minutes idle or 8 hours in any case. `wicket operator sessions` lists them on the
  host and `wicket operator revoke-session ID` (or `--all`) ends them. Every action is still separately
  passkey-signed, so a stolen cookie alone approves nothing.
- **Browser.** No inline script or style (the script and stylesheet are hashed static files with Subresource
  Integrity), `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src
  'self'; img-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  no CORS, `Referrer-Policy: no-referrer`, `nosniff`, `Cross-Origin-Opener-Policy: same-origin`. POSTs need the
  `x-wicket-csrf` header and the console's own `Origin`. Requests for another `Host` get the 401.
- **HTTP limits:** 256 connections (`--max-connections`), 16 per client address, 10 s each for the TLS
  handshake, the request headers and the body, 2 minutes per connection, 16 KiB and 64 header lines, 64 KiB
  bodies. A fuzz-style test throws random methods, paths, headers and bytes at the router and the wire and
  checks it never panics and never reaches a signed-in handler.
- **Installable:** the console has a web app manifest and icons, so it can be added to a phone's home screen.
- **Privilege separation** is #12: the console is meant to run as the unprivileged wicket system user. Nothing
  here needs root (bind :443 with `CAP_NET_BIND_SERVICE` instead), its TLS and ACME state is in its own files,
  and it starts runs through one launch callback (a detached `wicket run`), so moving launching behind a
  separate, more privileged process later changes only that callback.

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

The box's resolver is wicket.internal:53: wicket answers every query itself, so a lookup can't carry data
out. Every host the zone can reach resolves to its own address in 198.19.0.0/16 (on the box's loopback);
QUIC sent there is relayed to wicket over a bind-mounted unix socket and served as that host. Under gVisor
each UDP datagram is costly (about 110 µs of CPU in the box), so HTTP/3 downloads run at 40–100 Mbit/s with
the usual 1452-byte packets. `WICKET_H3_BOX_MTU=16000` lets the box's leg (loopback and a unix socket, no
real link) use 16000-byte packets for clients that accept them: 430–460 Mbit/s in #92's measurements.
`WICKET_H3_HTTPS_RECORDS=0` stops wicket answering HTTPS (`alpn=h3`) DNS records.

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

# Remote nodes, placement and leases

Reference for running boxes on other machines. The README has the short version; [concepts.md](concepts.md) explains the feed and leases.

## Enrolment

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

## `wicket node serve`: boxes that outlive the control channel

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
  recomputes each node's chain. The control host, not the node, decides where a shipped record is filed. It
  goes under the run's tenant, and under the run it names only if that run was placed on this node for
  that tenant. Any other record is filed under no run, with `"attributed": false`, and what the node
  claimed is kept in its body. A node that starts its chain again (its data was wiped) gets a
  `node.audit.restart` record. Feed decisions use the wall clock read once at start and advanced by a monotonic
  clock, so a clock step on the node can't stretch a freshness statement (after a deliberate clock step, restart
  `wicket-node` so it reads the wall clock again).
- **For now.** One run per node at a time (the run holds the node's feed; #38's reconciler will own it), so a
  child can't share its parent's served node (on a leased node it runs alone), plain `http://` to a forwarded host is refused, and the MCP gateway still
  decides on the control host. `ci/node-e2e.sh --local` runs the whole scenario with localhost as the node (only
  the ssh hop is replaced); `ci/node-e2e.sh <node>` runs it against a real enrolled node.

## Provisioning nodes (`wicket place`)

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

## Capacity leases and the reconciler

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

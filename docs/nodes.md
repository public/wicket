# Remote nodes, placement and leases

Reference for running boxes on other machines. The README has the short version; [concepts.md](concepts.md) explains the feed and leases.

## Enrolment

`wicket run --node <name>` runs the box on another machine (prepare one with `deploy/vultr/node-setup.sh`).
On an **enrolled** node, the node's own `wicket node serve` runs the box and decides its egress, its model
calls and its injected credentials locally, from a signed policy feed and the secrets it fetched, so the
box keeps working while the control host is unreachable, for exactly as long as its grants last (#57, #152,
#153; below). The ledger, the keys that matter and the MCP gateway's tools stay on the control host, which
issues authority (tokens, grants, leases, secrets), takes human approvals, and reconciles counts and audit
afterwards; it isn't asked during a request. A
`--node` target must be enrolled: there is no other way to run a box.

## The control host is a node too

Every box runs on a node through `wicket node serve` (#146). `wicket run` without `--node` places the box on
the control host's own built-in node, `local`, which is served by the same runtime and reached over its unix
socket instead of ssh. The control host makes and enrols it the first time a run needs it
(`<data dir>/local-node/`: its own node key, an identity certificate, and a node CA, each renewed by the
control host itself), and starts its `serve` on demand: one, detached, exiting after 10 minutes with no boxes
and no connections (`WICKET_LOCAL_NODE_IDLE_SECS`); `wicket self update` has it re-execute itself as the new
build, which adopts its boxes. `wicket node list` shows it;
`enrol` refuses the name.

**No code path distinguishes the control host's boxes but how their node is reached.** The local node
lays out its boxes, runs their egress proxy, DNS and HTTP/3, and decides from its replica of the feed (the
box's token and the grants published to it, splice-through included) exactly as a remote node does; its
audit records are shipped as `node.audit` like any node's. Its CA is the one difference in kind: a 24-hour
intermediate with no DNS name constraint (`*`; IP addresses still excluded), since it serves whatever its
boxes reach, while a remote node's is constrained to `--hosts`. What a node doesn't decide itself (hosts
with an `inject` rule or a credential swap, the model, the MCP gateway) goes to the run's own proxies
(`<run dir>/ctl/`) over the node's channel.

Sharing the filesystem is used only as transport:

- the local node lays boxes out in the runs' own directories (`<data dir>/runs/<run>`), so a run's
  workspace and state needn't be copied to it and back, and its zone volumes stay in `<data dir>/volumes`;
- its tunnels to a run's proxies are those sockets themselves, not frames over the channel;
- it can mount a directory of the control host's in a box: an in-place `--workspace-dir`, and a wrapped
  session's directory. Wrapped sessions (`wicket wrap`, which hands the box its launcher's own stdio
  protocol) are the one thing only the local node runs. Long-lived agents hibernate and wake on any
  node, their state moved over the channel (`PutTree`/`GetTree`; [agents.md](agents.md)), and an in-place
  `--workspace-dir` on a remote node is copied there before the box starts and synced back into the
  operator's directory when it ends (deletions included; its `out/` stays the operator's).

```sh
wicket node token --name n1 --ttl 1h        # prints a one-time join token (stored hashed)
wicket node enrol wicket@203.0.113.7 --token wkt_… --host-key 'SHA256:…' --hosts 'api.example.com,*.example.org'
wicket node install n1                      # copies this wicket binary there, starts the wicket-node service
wicket run task.yaml --node n1
wicket node list                            # each node, and what it holds for this host's runs (below)
wicket node renew-ca n1                     # a fresh node CA and identity certificate (default 24 h each), over ssh
wicket node revoke n1
```

- **Host key.** `--host-key` takes the node's key line or its `SHA256:` fingerprint, which should come from
  somewhere other than the network (the provider's console, cloud-init output, the image). Without it,
  `enrol` refuses unless you pass `--trust-first-use`, and then prints the fingerprint it pinned. After that, every
  ssh call uses a wicket-managed known_hosts (`<data dir>/nodes/<name>/known_hosts`) with
  `StrictHostKeyChecking=yes`, so a node with any other key is refused. A `--node` target that isn't enrolled
  is refused: boxes run only through an enrolled node's `serve`. A revoked node is refused.
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

- **Install.** `wicket node install <name>` copies the control host's current binary to the node over the pinned
  ssh connection as a version (`~/.local/share/wicket-node/versions/<build id>/wicket`, with `~/.local/bin/wicket`
  a link to its `current`), checks its sha256 there, and installs a `systemd --user` unit, `wicket-node`, that
  runs `wicket node serve`. `node-setup.sh` enables lingering for the `wicket` user so the unit runs without a
  login. `serve` talks to a control host whose protocol version is at most one away from its own (#162), so the
  control host and its nodes are updated one at a time: `wicket self update --nodes` ([operations.md](operations.md)).
- **The node owns the box.** It starts the box detached (`docker run -d`) and relays its stdin, stdout and
  stderr over one multiplexed, length-prefixed control channel: `ssh <pinned> <node> wicket node attach`, which
  joins the ssh session to `serve`'s unix socket (`~/.local/share/wicket-node/ctl/ctl.sock`, directory 0700).
  When the channel drops the box keeps running; the node keeps up to 4 MiB of output per stream (oldest dropped
  first, and the control host reports the gap), replays it when the control host reconnects (backoff 0.5 s to
  5 s), and enforces the run's timeout itself. Unsent stdin is resent. Live egress events from the disconnected
  period aren't shown on the console, but are in the node's audit log.
- **Boxes outlive `serve` too** (#151). Nothing of a box depends on the `serve` process: its output is read
  from `docker logs` (from its start), and an interactive box's stdin comes over `sock/stdin.sock`, read in
  the box by `wicket-fwd --stdin-from`, which reconnects when the node comes back and closes the agent's
  stdin only when the control host closes it. The node keeps a record of each box (`node-box.json` in its
  run directory), and a restarted `serve` **adopts** every running box it has a record for: its proxies
  start again, its output is replayed from a little before the last offset it recorded (lined up on the
  last bytes it read; the control host drops what it already has), its
  timeout is still counted from when it started. A box whose run has no authority in the feed any more is
  stopped. Exited boxes are kept until their exit is read, then removed.
- **A node works on its grants** (#153). A box's authority is its token in the feed, and every part of it
  has a lifetime: block 0 lasts the zone's `limits.authority` (default: the run's `timeout`, plus 30 s), counted from
  the run's start (a re-attach doesn't extend it); each grant lasts its `--ttl` (at most 24 h). The node
  works for the box, connected or not, for exactly as long as these are valid, and **stops the box when
  its authority expires**, whether or not it can reach the control host: the workload's grants decide, not
  the node (this replaces #151's run lease and `WICKET_NODE_LEASE_EXPIRY`). What the node reports for each
  box says when its authority ends (`authority_until`). **The wake fence:** while a box's authority is live
  on a node this host can't hear from, nothing replaces it. Its agent isn't woken anywhere (`wicket wake`
  says from when it can be: the authority's end plus 30 s of clock skew) unless the node has confirmed the
  box stopped (its exit, or it says it has no box for the run), and `wicket reconcile` reports the run as
  unreachable, "still authorized there until …", rather than lost, whatever the node's status. Two copies
  of an agent never act at once with separate budget slices and writes. The authority and the node's
  confirmation are kept beside the run (`ctl/authority.json`).
- **Secrets come to a node only when used, and stay in its memory** (#152). A secret reaches a node only
  when one of its runs first needs it: the run's model credential (`llm.secret`) on its first model call,
  an `inject` rule's secret on the first request to its host. The node asks over that run's own
  connection; the control host releases it only if the run's zone uses it, the vault holds it and its
  host binding covers the hosts the zone uses it for, and audits the release (`node.secret_fetch`). It is
  never prefetched, and never sent for another run, zone or node. The Claude login goes as its current
  **access token only**: the refresh token and refreshing stay on the control host. The node keeps each
  secret in `serve`'s memory only, never on disk, encrypted or not: locked against swap, zeroed when
  dropped, the process not dumpable (`PR_SET_DUMPABLE` 0), never logged. A run's use of a secret lasts
  until its authority ends, or the upstream token's own expiry if earlier; the node drops a secret when
  the last run that used it ends, and when the control host says it changed, was rebound or removed
  (checked every 2 s while connected; the next use fetches it again). While the node is cut off, the
  secrets it holds keep working; one first needed then fails with "credential … not cached on this node;
  control host unreachable" (audited as `node.secret_unavailable`) until the control host is back. A
  restart of `serve` while cut off loses the cache: model calls and injected hosts stop until reconnect,
  while plain egress the token allows goes on. A self-update's re-exec (`wicket self update`, #162) hands
  the cache to the new process through a sealed memfd, never a file. What this protects, and what it
  doesn't: [limits.md](limits.md).
- **What a node holds** shows in `wicket node list`, one line per run this host supervises there: when
  the box's authority ends (or that the node confirmed it stopped), the secrets released to the node for
  it (by name, never values) and its budget slice. It is this host's record of what it released and
  leased (`ctl/holdings.json` beside the run), so an upper bound: the node may have dropped a secret
  already, and never holds more.
- **Budget slices are leased to the node** (#152), per run: a quarter of the zone's model budget by
  default (`WICKET_NODE_BUDGET_SLICE` on the control host, a fraction), renewed while connected once less
  than half of it is left, and lowered at once when what is left shrinks (a spawn's carve-out). Offline, a
  node spends what is left of its slice and nothing more; a slice is kept on the node's disk
  (`slices/`), so a restart doesn't hand an offline node a fresh one.
- **Lifetimes** (#153). Everything a node holds that carries authority ends on its own:

  | what | lasts | set by |
  |---|---|---|
  | a box's base authority (its token's block 0) | the run's timeout plus 30 s (so the timeout itself ends the run), from the run's start | zone `limits.authority` (never longer than `limits.timeout`; a child's never longer than its parent's) |
  | a grant | its TTL, at most 24 h | `wicket approve --ttl` (default 10 min) |
  | a run's use of a secret its node fetched | the box's authority, or the upstream token's own expiry if earlier | the zone; the upstream |
  | a budget slice | until spent, renewed while connected | `WICKET_NODE_BUDGET_SLICE` on the control host (fraction, default 0.25) |
  | an agent identity | 10 min, re-issued every 5 by the run's supervisor | `WICKET_IDENTITY_TTL` |
  | the node's certificate and node CA | 24 h, renewed over the channel at half-life, or by `renew-ca` | `enrol --cert-ttl`, `--ca-ttl` |
  | the node feed key's certificate | 7 days, renewed when a run starts with less than a day left | (fixed) |
  | a capacity lease | its duration | `request_capacity`'s duration |
  | a join token | its TTL | `wicket node token --ttl` |

  Links and exposed ports have no clock of their own: they end with either run.
- **The model proxy runs on the node** (#151, #152), per box, and decides there: routes, models, server
  tools, the budget (starting from what the run already spent) and the node's **budget slice**. With the
  model credential in its cache it calls the model itself (no round trip to the control host),
  counts the call, keeps its count beside the box (`node-spend.json`, so a restarted `serve` doesn't reset
  it) and reports it; the run's own counters on the control host take the node's totals, so spawn
  carve-outs, a long-lived agent's budget and the console see what the node spent. A slice is a quarter of
  the zone's budget by default (`WICKET_NODE_BUDGET_SLICE` on the control host, a fraction), renewed while
  connected once less than half of it is left: offline, a node spends what is left of its slice and nothing
  more. With a control host on protocol 1 (#162's skew), the call is relayed to the run's own proxy there
  as in #151, which adds the credential and counts it.
- **The MCP gateway runs on the node** (#151), relaying each call whole to the run's gateway on the control
  host, which decides every tool (they read or write the ledger); while the control host can't be reached
  the node answers MCP's own handshake (`initialize`, `ping`) and refuses each tool call with a clear,
  retryable error.
- **Decisions on the node.** Each box's egress proxy decides from the node's verified replica of the feed
  (`wicket-feed`; the zone, and grants bound to the box), with the same proxy code as the control host (only
  the decision source differs, `wicket_proxy::decide`):

  | node's feed | allowed | out of reach |
  |---|---|---|
  | fresh (a statement within the TTL, 30 s) | the box's token and its live grants | the control host raises a pending request (`wicket pending`, `wicket approve` as usual); 403 with its id |
  | offline (no live statement) | the same, each until its own expiry | queued on the node (`asks.json`; a node-local id `q-…` in the 403) and raised when the control host is back, saying how old it is; no approvals on the node alone |
  | lagging (a live statement names deltas not yet held) | nothing, until they arrive (milliseconds) | 403, retry |
  | closed (no verified state, or the feed key's certificate expired) | nothing | 403 |

  Approved grants for the box's requests are pushed to the node as feed grants bound to the box, and the node
  counts their uses: the ledger hands them over and never consumes them too. A path-prefix grant is honoured on
  a node for the asked path only. `wicket grant revoke <id>` (picked up within 250 ms) and a run revocation
  (`wicket identity revoke`, within 2 s) are pushed to the node, which applies them as soon as they arrive; a node
  that hears nothing keeps what it holds until it expires: for a cut-off node, revocation takes the
  remaining lifetime of what was revoked. A tampered, replayed or rolled-back
  feed frame is refused.
- **TLS.** The node terminates TLS with its own node CA, and the box's CA bundle holds the installation root (for
  the node CA's leaves) and the run's own CA on the control host. The node never terminates, and instead tunnels
  the raw CONNECT over the channel to the control host's egress proxy for the run (which decides and terminates
  it with the run CA), for: hosts with a credential swap (an `inject` rule's host is terminated and injected on the node, its
  secret fetched on first use, #152, unless the control host speaks protocol 1),
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
- **Many runs per node.** Each run has its own control connection, named by its run (a newer connection for
  the same run replaces the older one, and no other); the node sends each box's output, events, asks and
  tunnels to the connection that owns it, and audit records over one of them, handing that over when it
  goes. Runs share the node's feed: each commit takes `<data dir>/nodes/<name>/feed.lock` and first reloads
  the delta log if another process appended to it. A run drops its own token from the feed when its box
  exits; the next run to start drops those of runs that ended without doing so.
- **Links across nodes.** A link's ends may be on any nodes. Its relay socket is the node's (each connection
  is tunnelled over the control channel to the process that opened the link); the in-box listener and each
  connection into the target box are execs on that box's node; its hosts file is rewritten there. A box on
  another node than the relaying run's is reached over a connection of the relay's own (scope
  `links:<run>`), so the bytes pass through the control host. Reach, approval and audit are those of any link.
- **For now.** Plain `http://` to a forwarded host is refused, and every gateway tool is still decided on the
  control host. `ci/node-e2e.sh --local` runs the whole scenario with localhost as the node (only
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

- **Runs** whose supervisor is gone (#151) are asked about on their node. If it still has the box, the run
  is **adopted**: `wicket attach <run>` takes it over (logged in `<run dir>/ctl/attach.log`), the box
  untouched. If the node says the box is gone, the run ends as `lost`; if the node can't be reached, the run is
  left for the next pass. A run supervised on another machine is left to it.
- **A restart of the control host** is a pass away from normal: kill every wicket process on it, start
  again, and one `wicket reconcile` restarts this host's own node (whose `serve` adopts its boxes) and takes
  every run over, on every node. What a supervisor needs for that is in the run's `ctl/` directory: the run's
  record (`run.json`), its run CA's key, its model spend and output offsets as it goes (`progress.json`); its
  identity is re-issued and its box's token re-minted with the grants already on the node.
  `ci/acceptance.sh` checks it, on this host's node and (`--nodes local`) another.
- **Leases** end when their run has ended or their end has passed; denied or withdrawn asks give their
  reservation back.
- **Machines.** Only instances tagged `wicket-owner-<installation>` are ever listed. One no live lease needs is
  destroyed; one that matches a lease the ledger lost track of (a crash between create and record) is adopted,
  not created again. Ownership is checked again right before every destroy, so a tag changed or a
  `wicket-protected` tag added since the list saves the machine.
- **Boxes** (`wicket=1` containers) whose run ended are stopped; a running run's box is left to its run (above);
  a box whose run this ledger doesn't know is left alone, since Docker may be shared. This subsumes
  `wicket reap`, which now leaves a running run whose supervisor is gone to `wicket reconcile`.
- Every change is an audit record `reconcile.<what>`. One pass at a time per installation (a file lock).
- So killing every control-plane process mid-run and restarting leaves no orphaned machine or box after one
  pass, and every run whose box still runs is supervised again. **Not yet:** the daily money reconcile against the provider's own charges (design §8.5).

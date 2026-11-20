# Remote nodes, placement and leases

What happens when boxes run on other machines: enrolment, `wicket node serve`, placement and leases.
[Concepts](../explanation/concepts.md) explains the feed and leases. To set a node up, see [add a
remote node](../how-to/add-a-remote-node.md) and [create nodes on Vultr](../how-to/create-nodes-on-vultr.md).

## Enrolment

`wicket run --node <name>` runs the box on another machine (prepare one with `deploy/vultr/node-setup.sh`;
the node also needs the agent image, `~/.local/bin/wicket image` there, unless it is pinned by digest:
the control host then sends it, [below](#images-on-nodes)).
On an **enrolled** node, the node's own `wicket node serve` runs the box and decides its egress, its model
calls and its injected credentials locally, from a signed policy feed and the secrets it fetched, so the
box keeps working while the control host is unreachable, for exactly as long as its grants last (#57, #152,
#153; below), and the MCP gateway's tools too (#164): it answers them from the box's token, starts
narrower children itself and carries links between its own boxes. The ledger and the keys that matter
stay on the control host, which issues authority (tokens, grants, leases, secrets, identities), takes
operators' approvals, and reconciles counts and audit afterwards; it isn't asked during a request. A
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
boxes reach, while a remote node's is constrained to `--hosts`. What a node doesn't decide itself (the
control host's gateway tools: links, `decide`, `finish` and `hibernate`, operator-held requests,
messages, capacity and update requests, spawns it doesn't start) is asked of the run's supervisor as a
typed call over the node's channel (`Msg::Call`, protocol 13, #257). No egress goes there: since #257's slice 3 the node decides every request itself.

Sharing the filesystem is used only as transport:

- the local node lays boxes out in the runs' own directories (`<data dir>/runs/<run>`), so a run's
  workspace and state needn't be copied to it and back, and its zone volumes stay in `<data dir>/volumes`;
- its tunnels to a run's proxies are those sockets themselves, not frames over the channel;
- it can mount a directory of the control host's in a box: an in-place `--workspace-dir`, and a wrapped
  session's directory. Wrapped sessions (`wicket wrap`, which hands the box its launcher's own stdio
  protocol) are the one thing only the local node runs. Long-lived agents hibernate and wake on any
  node, their state moved over the channel (`PutTree`/`GetTree`; [agents](agents.md#hibernate-and-wake)), and an in-place
  `--workspace-dir` on a remote node is copied there before the box starts and synced back into the
  operator's directory when it ends (deletions included; its `out/` stays the operator's).

The commands, in order ([add a remote node](../how-to/add-a-remote-node.md) has the walk-through):

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
- **One connection per node** (#287). An enrolled node's ssh calls share one connection: the first opens a
  master (`ControlMaster=auto`), with its control socket in `<data dir>/ssh/` (the wicket user's, 0700), and
  each later call for 10 minutes after the last (`ControlPersist=10m`) is a session over it. A run's channel,
  link relays, health checks, `self update` and `renew-ca` all use it. So a box start after the first skips
  ssh's connect, key exchange and authentication: about 0.39 s to 0.05 s on pc5800. The master is opened with
  the pinned host key like every connection. Keepalives (every 10 s, 3 missed) end a master whose connection
  died; a channel that gets no answer over one closes it (`ssh -O exit`) and dials once more, fresh.
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
- **Node CA renewal** (#416, protocol 14). Like the identity certificate, the node CA is renewed over the
  channel at half its life by whichever run is connected to the node: the node makes a new P-256 key (in memory
  until certified) and sends its signing request; the control host signs it for the same hosts and lifetime;
  the node checks it is for that key, signed by its installation root and unexpired, writes `ca.key`, `ca.pem`
  and `ca-chain.pem`, and swaps it in for every box it runs, running ones included (their next connection is
  served by the new CA). Then the ledger records it, revokes the CA it replaced early, and audits
  `node.ca_renewed` (new serial, end, the revoked serials). One renewal per node at a time; a failed step is
  retried a minute later. A node that was unreachable through its CA's end is renewed as soon as a run
  connects, and the box's start waits for that (up to 30 s). A node at protocol 13 isn't asked: renew it with
  `wicket node renew-ca`, which still works for any node over ssh.
- **An expired node CA** is a node health alert (`<node>/ca-expired`; and `<node>/ca-expiring` once less than
  a quarter of its life is left), in `wicket top`, the console's health panel and push, and the health summary
  shows the CA's end. Such a node refuses to start a box whose zone needs the CA (a model route, or a reach or
  inject host inside its name constraints), saying why, instead of starting one whose every request fails.
- **Widening the node CA at runtime** (#573). `wicket node set <node> --ca-hosts auto` (or a list such as
  `api.example.com,*.example.org`) lets the control host add hosts to a node's CA when its boxes need them:
  - before a box starts, the inspected hosts its zone reaches, injects into, swaps a credential for or calls as
    its model host, and the hosts of its live grants, are compared with the operator's hosts (`nodes.hosts`,
    from enrolment or `wicket node renew-ca`), not with the CA as it is now, so a host two runs need stays while
    either runs; a grant's host is wanted again when it is handed to the node;
  - what's missing and allowed is recorded as wanted by that run, and the box's start waits (up to 60 s) for a
    renewal over the channel;
  - every renewal signs the operator's hosts plus the live runs' wants (under `fixed`, the operator's hosts
    alone), so what no run wants any more goes at the next one; a run's wants end with it, however it ends;
  - only what a node CA may be constrained to is ever wanted: never `*`, an IP, a single label (`intranet`, or
    `*.com`), or a label outside letters, digits, `-` and `_`; names are canonical (punycode). `--ca-hosts`
    refuses the same;
  - at most 64 name constraints: the operator's hosts are always kept, and the room left is shared a run at a
    time; what doesn't fit is audited `node.ca_wants_dropped`. If the widened CA can't be signed, the operator's
    hosts are (`node.ca_widen_failed`), so the CA never lapses for a want;
  - the renewal is audited `node.ca_renewed` and `node.ca_widened` (hosts added and removed, and the runs that
    wanted them); `wicket node set` is audited `node.ca_policy`, with who set it;
  - a box's `request_access` for an https host outside the CA is asked for when the policy (as it was when the
    box started) lets the CA be widened to that host: its approval's grant is wanted like the box's reach. A
    grant whose host the policy keeps out by the time it is published is said in the run's output and audited
    `node.ca_want_refused`. Otherwise the node answers "not requested", naming
    `wicket node set <node> --ca-hosts` (#571);
  - revoking a node, or enrolling a machine under its name again, clears its policy and wants.

  The default is `fixed`: the CA keeps the operator's hosts, as before, and a box start says which hosts it would
  need. The local node's CA is unconstrained, so none of this applies to it.
- **Name constraints are subtrees.** `api.example.com` also permits names under it (`x.api.example.com`), and
  `*.example.org` permits every name under `example.org` but not `example.org` itself. X.509 can't express
  "exactly this host". The reach rules stay the exact gate, and the constraint bounds what a stolen node CA can
  do until it expires.
- **Revoking** closes the node's shared ssh connection (it would carry commands without checking a host
  key), deletes the pinned key, revokes the node's identity certificates (a run connected to the node
  stops its box there and drops it within a second, and nothing reconnects), and records the node CA's serials
  for the feed's revocation list (not distributed yet), as a renewal over the channel does for the CA it replaces.

## `wicket node serve`: boxes that outlive the control channel

- **Install.** `wicket node install <name>` copies the control host's current binary to the node over the pinned
  ssh connection as a version (`~/.local/share/wicket-node/versions/<build id>/wicket`, with `~/.local/bin/wicket`
  a link to its `current`), checks its sha256 there, and installs a `systemd --user` unit, `wicket-node`, that
  runs `wicket node serve`. `node-setup.sh` enables lingering for the `wicket` user so the unit runs without a
  login. `serve` talks to a control host whose protocol version is at most one away from its own (#162), so the
  control host and its nodes are updated one at a time: `wicket self update --nodes` ([update and roll back](../how-to/update-and-roll-back.md); [protocol](protocol.md#versions-and-skew)).
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
  on a node this host can't hear from, nothing replaces it. Its agent isn't woken anywhere (the wake's log,
  which `wicket session` names, says from when it can be: the authority's end plus 30 s of clock skew) unless the node has confirmed the
  box stopped (its exit, or it says it has no box for the run), and `wicket reconcile` reports the run as
  unreachable, "still authorized there until …", rather than lost, whatever the node's status. Two copies
  of an agent never act at once with separate budget slices and writes. The authority and the node's
  confirmation are kept beside the run (`ctl/authority.json`, synced to disk before the node is asked
  to start the box); a run without that record (lost, or from before #153) is fenced until its timeout,
  from its run record.
- **Secrets come to a node only when used, and stay in its memory** (#152). A secret reaches a node only
  when one of its runs first needs it: the run's model credential (`llm.secret`) on its first model call,
  an `inject` rule's secret on the first request to its host, and a credential swap's (a remote or wrapped
  session's, #257) on the first request that presents its placeholder. The node asks over that run's own
  connection; the control host releases it only if the run's zone or one of its swaps uses it, the vault holds it and its
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
  doesn't: [limits](../explanation/limits.md#remote-nodes).
- **What a node holds** shows in `wicket node list`, one line per run this host supervises there: when
  the box's authority ends (or that the node confirmed it stopped), the secrets released to the node for
  it (by name, never values) and its budget slice. It is this host's record of what it released and
  sent (`ctl/holdings.json` beside the run), so an upper bound: the node may have dropped a secret
  already, and never holds more.
- **Budget slices are sent to the node** (#152, the `BudgetSlice` message), per run: a quarter of the zone's model budget by
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
  | the node's certificate and node CA | 24 h, each renewed over the channel at half-life (the CA from protocol 14), or by `renew-ca` | `enrol --cert-ttl`, `--ca-ttl` |
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
  more.
- **Decisions at the edge** (#164; protocol 5, the list of what a node still asks the control host and why:
  [design §9.2.1](../explanation/design.md)). The node answers `whoami`, `request_access`, `await_grant` and
  `pending_requests` from the box's token, connected or not. Cut off, what needs an operator
  (`request_access` beyond the token, `request_capacity`, `request_update`, a spawn beyond the box's
  zone) is queued on the node (`edge.json`, `q-…` ids, like #153's asks) and made when the control host
  is back; `await_grant` on a `q-…` id then follows the request it became.
  - **Spawn.** A child within the box's authority starts on the node: its token attenuated there from
    the box's base token (`derived.json` beside it, so a restarted `serve` keeps it), never wider or
    longer-lived than its parent's and revoked with it, its budget carved from the parent's slice. The
    node reports it (`Spawned`, until answered); the control host checks it again, records it and
    supervises it (in the parent's supervisor's process), or refuses it and the node stops it. Spawns elsewhere
    (placement), beyond the zone, or under an org policy that decides differently a level down go to the
    control host.
  - **Same node.** Messages between boxes on the node are decided there from both tokens and, cut off,
    delivered there (attested by the node, not signed); links between them are carried by the node and
    outlive the control channel, closed when either box's authority ends.
- **The MCP gateway runs on the node** (#151); calls it doesn't decide (#164) are relayed whole to the run's gateway on the control
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
  counts their uses: the ledger hands them over and never consumes them too. A path-prefix grant covers its
  directory and every path under it, whole segments of the canonical path only, on a node at protocol 16 or
  later (#257); a node at 15 honours it for the asked path only. `wicket grant revoke <id>` (picked up within 250 ms) and a run revocation
  (`wicket identity revoke`, within 2 s) are pushed to the node, which applies them as soon as they arrive; a node
  that hears nothing keeps what it holds until it expires: for a cut-off node, revocation takes the
  remaining lifetime of what was revoked. A tampered, replayed or rolled-back
  feed frame is refused.
- **TLS.** The node terminates TLS with its own node CA, and the box's CA bundle holds the installation root (for
  the node CA's leaves) and nothing else: the control host terminates no TLS, so a run has no CA of its own. An `inject` rule's host and a credential swap's host are
  terminated on the node, which injects or swaps the credential itself, its secret fetched on first use
  (#152, #257). A host the node CA can't cover (outside its name constraints, e.g. one approved later under
  `unlisted_hosts: escalate`; or every host once the node CA has expired, or without one) is never terminated
  and, since protocol 11 (#257's slice 3), never forwarded to the control host either: the node splices it
  through if the box's token allows the host wholesale, and otherwise refuses the CONNECT with a 403 that says
  so (`Blocked by wicket box: host not served on this node`, logged as a `forbidden` egress line,
  `not served on this node (<why>)`). To serve such a host, widen the node's CA (`wicket node renew-ca <node>
  --hosts …`). Plain `http://` needs no certificate, so the node decides it like any request. Grants are all
  published to the node, which alone counts their uses; the ledger records them. A box that a node before
  protocol 11 would forward one of its known hosts for (its zone's reach, inject or swap hosts outside that
  node's CA, or any host without a live CA) doesn't start there: update the node. The MCP gateway's relayed
  tools are reached through a tunnel.
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
- **For now.** Gateway tools beyond #164's are still decided on the control host. `ci/node-e2e.sh --local` runs the whole scenario with localhost as the node (only
  the ssh hop is replaced); `ci/node-e2e.sh <node>` runs it against a real enrolled node.

## Limits

A node runs every box's relays in one process, `wicket node serve`, a systemd user service of the
`wicket` user, and the control host reaches each box over its own ssh session
([#582](https://github.com/public/wicket/issues/582) step 4). `deploy/vultr/node-setup.sh` (and
so every node `wicket node create` makes) sets what that needs on a new node. Don't re-run that
script on a live node: it restarts Docker, which stops every box, and rewrites the wicket user's
`authorized_keys`. On a node you set up yourself, or one made before these settings, apply each of
these on its own:

- **sshd**: `/etc/ssh/sshd_config.d/60-wicket.conf`, checked with `sshd -t`, then
  `sudo systemctl reload ssh` (`sshd` on some distributions):

  ```
  MaxStartups 64:30:256
  Match User wicket
      MaxSessions 512
  Match all
  ```

  - `MaxSessions 512`, for the wicket login only: the control host multiplexes every run's session
    on one connection per node, and the default of 10 refuses the eleventh box on a node. A
    connection already open keeps the limit it started with: the control host's shared connection
    to the node gets the new one once it reconnects (after its idle timeout, or when the control
    host restarts).
  - `MaxStartups 64:30:256`: bursts of new connections, such as every run reattaching after a
    control-host restart, aren't dropped. sshd takes it only outside a `Match` block.
  - `sshd -t` needs `/run/sshd`, which only a running sshd makes: `sudo install -d -m 755 /run/sshd`
    first if it's missing.
- **The unit**: `wicket node install` writes it (run it again to update one): `LimitNOFILE=524288`
  (the user manager's own hard limit) and `TasksMax=infinity`.
- **The wicket user's slice**: `/etc/systemd/system/user-<uid>.slice.d/60-wicket.conf` with
  `[Slice]` `TasksMax=infinity`, so the user manager's default doesn't cap the node's threads.
- **The wicket user's manager**: `/etc/systemd/system/user@<uid>.service.d/60-wicket.conf` with
  `[Service]` `LimitNPROC=infinity`. `RLIMIT_NPROC` counts every thread of the user, and the unit
  can't raise it past its user manager's, so it's set there; it applies from the manager's next
  start (`sudo systemctl daemon-reload`, then `sudo systemctl restart user@<uid>.service`, which
  restarts `wicket node serve`: its boxes carry on and it adopts them).
- **The kernel**, for thousands of boxes: `kernel.pid_max` and `kernel.threads-max`, as on the
  control host ([daemon limits](daemon.md#limits)).

Once supervisors are tasks in a few processes, with one channel per node (step 5), the session
count stops growing with boxes.

## Health, admission and disk ([#377](https://github.com/public/wicket/issues/377))

- **Health.** Every 30 s, on each control connection that speaks protocol 12 or later, a node reports its
  health (`Msg::Health`). The report covers the disk and inodes of its data directory, its memory
  (total, available, and the limits committed to running boxes), its feed's mode and freshness, the
  boxes killed for memory since `serve` started, and its failures to persist its own state (feed
  frames, spend journal). The control host keeps each node's latest in the ledger (`node_health`).
  `wicket top` shows a DISK column and the alerts below the node table. `wicket node top` and the
  node's status socket show the same report. The console shows it under Nodes.
- **Alerts.** The console pushes to every registered device when a node's disk or inodes pass 85%
  used, its feed has been stale for more than 5 min, a box was killed for memory, or it couldn't persist
  its state. The control host's own disk past 85% alerts too, and so does a state store or audit sink that
  lags ([console](console.md#the-state-store-and-the-audit-export)). Each condition is pushed once when it
  appears, and again only after it has cleared, under its own notification tag (`wicket-health`).
  A device registered without details is told how many alerts there are, not what they say. A report
  older than 10 min raises no disk or feed alert, and nothing is reported by a node with no
  control connection.
- **Admission.** A node refuses to start a box it can't fit, and says why. The box's memory limit
  must fit in what the kernel says is available (MemAvailable), less what the running and starting
  boxes may still take up to their limits (each one's limit less its last sampled use), less a
  margin of 5% of memory, at least 256 MiB. Limits are never overcommitted against what is actually
  free. The disk must have at least 5% (at least 1 GiB) free, and 1% of its inodes. The refusal
  (`no room on this node for the box: …`) is audited as `box.refused` on the node, and `wicket run`
  reports it. A node's `Welcome`, and since #579 its health report, carry its size and use, the room
  it has now (`room_mib`) and whether it starts no box at all (`full`). Placing a waking agent uses
  them, and refuses the wake when no node has room, rather than overcommitting one.
- **Reserve.** A node holds a disk reserve, `reserve` in its directory: preallocated space box
  volumes can't use, 2% of the disk (at least 256 MiB, at most 2 GiB), or `WICKET_NODE_RESERVE_MIB`
  (0 for none). When a feed frame can't be persisted, the node releases the reserve and tries the
  frame again. If it still can't, the feed is stalled. Every 5 s the node checks whether the feed's
  directory can be written again; once it can, it asks each control connection for what it missed (a
  catch-up), audited as `feed.recovered`. No restart is needed. The node takes the reserve back once
  the disk has room for it above the floor. Health counts the reserve as free.
- **Volumes.** A volume the zone doesn't `keep` is the run's own cache, under `runs/<run>/cache/<name>`.
  It is deleted when the control host forgets the run (its work collected), on every node including
  this host's own. If the run's work is never collected, an hourly sweep deletes the cache once its
  retention after the run's end has passed (default 7 days). A kept volume lives under
  `volumes/<tenant>/<zone>/<name>` and is deleted by the sweep once it has gone unused for its
  `retention`, if it has one, and only while no running box has it. Each sweep deletion is
  audited as `volume.expired`. The sweep never deletes a workspace.
- **Collection.** The ledger records when a run's work was collected (`run_collected`): its files
  fetched back to the control host, its outbox taken, a git push it made allowed, or its state
  bundled as it hibernated. A remote node's workspace for a run with nothing collected isn't
  forgotten at the run's end. Instead the refusal is printed and audited as `run.cleanup_refused`,
  and the node keeps the files until `wicket node forget <run> --force` (audited as
  `run.cleanup_forced`). The node audits the deletion as `run.files_deleted`.

## Placement

Where a box goes ([#579](https://github.com/public/wicket/issues/579)): `wicket run --node` or a spawn's
placement hint names a node; otherwise a run goes on this host's own node. A woken agent is placed by the
scheduler, `wicket-placement::schedule`, a pure function of what the control host knows when it decides:

- **Capacity, from the ledger.** Each node's latest health report (every 30 s, on every connection to it;
  stored once per node at most every 20 s) carries its capacity, and a wake reads it there. A node with no
  report under 90 s old, or one from a node before #579, is asked over its control channel instead (within
  10 s): an idle node, with no run connected to it, reports nothing. A report may still count a box that
  ended since it (one that just hibernated), so before a wake is refused for room, the nodes read from
  reports are asked too.
- **Reservations.** Choosing a node and reserving what the box asks for there are one ledger transaction
  (`placements`), so two starts never count the same room: a node's room is its report less what boxes
  chosen since hold on it. A reservation counts until the node reports the box (after it starts), or is
  given back when the start fails or the run ends; one never confirmed stops counting after 2 minutes.
  A node named for the box (`wicket run --node`, a lease's node) passes the same filters when its last
  report is fresh: the start is refused, saying why, for a label, taint or CA it fails; for room, the
  node's own admission decides, since the report may count a box that has ended.
- **The queue.** A wake that no node may take now waits instead of failing: `queued: no node may take agent
  … now (n1: …; n2: …)`, then it tries again every 2 s, asking the nodes with no fresh report every 30 s,
  for up to `wicket wake --wait` (default 30 minutes; `--wait 0` fails at once, as before). Waiting wakes
  are served first come, first served across tenants (`placement_waits`); within a tenant, its own wakes
  fill the places in line it took by their manifest's [`placement.priority`](manifest.md#placement),
  highest first, and first come, first served within one. A priority is the manifest's own word, so it
  never moves another tenant's wakes. One is placed only when no wake ahead of it fits a node now, so a
  wake that fits nowhere doesn't hold up the ones behind it. A wake behind another tenant's says so
  without naming that run. A waiting wake keeps its
  claim on the agent, and holds its place only while its process is alive. The queue never creates
  capacity: `request_capacity` and `wicket node create` stay the only ways.
- **Why here.** Every decision is recorded (`placement_decisions`, a run's latest, kept a week): what the box
  asked for, the node chosen, the nodes it may go on in order, and every reason each other node was out (at
  most 10 of each), or the waiting run it went behind. `wicket why-here <run>` prints it (`--json` too):

  ```text
  run_01J…: on node n1, the best fit of 2 it may go on (of 4 candidates), decided 30 s ago
    asked for: 1 vCPU, 2048 MiB; labels gpu=a100; its node's CA must cover api.example.com
    ranked (bin-packed, best first): n1, n3
    refused:
      n2: 0.5 vCPU, 512 MiB free
      n4: no label gpu (wanted gpu=a100)
  ```

- **Labels and taints.** `wicket node set <node> --label gpu=a100 --taint dedicated=ci` records them in the
  ledger (`key-` removes one; audited `node.labels`). A box goes on a node only if the node has every label
  its manifest's [`placement.node_selector`](manifest.md#placement) names, with that value, and the box
  tolerates every taint the node has (`placement.tolerations`: `key` for any value, or `key=value`). A
  taint keeps a node for the boxes that say they belong there.
- **Public addresses** (#575). `wicket node set <node> --public-ipv4 <address> --public-ipv6 <address>`
  records where a public name of a box on the node points (`none` clears one; audited `node.addresses`,
  ledger schema 34). Only addresses on the public internet are taken: for a node behind NAT that forwards
  its port range one to one, the router's. They are the operator's alone: a node never sets its own, since
  a node that could name its address could point a name at someone else's server. A node with neither
  can't publish.
- **Filter.** Out are: a node that starts no box (`full`); one without the vCPUs and memory the box's limits
  ask for, by its report and its admission's room ([above](#health-admission-and-disk-377)); a label or
  taint mismatch; and a node whose CA doesn't cover the box's inspected hosts and whose policy keeps them
  out ([#573](https://github.com/public/wicket/issues/573); a node it may be widened to is in).
- **Affinity.** A box's [`placement.affinity`](manifest.md#placement) names a service its zone uses or a
  kept volume; its `anti_affinity` a zone or a principal. A node is seen with the boxes of the box's own
  tenant running there (their zones and principals), the live instances of the services it may use there
  (its tenant's, or a shared one), and, for a kept volume, whether a box of the box's zone runs there or
  ran there within the volume's retention. A box being started counts from its reservation (whose box it
  is is recorded with it, `placement_owners`, ledger schema 30), so two wakes placed at once see each
  other. Another tenant's boxes are never seen. A box's tenant is its manifest's, which an operator vouches
  for. A required term that fails puts a node out (`no service npm-cache here,
  which the box requires`, `runs a box of zone research, which the box requires to be away from`); a
  preferred one ranks the nodes meeting the most first.
- **Preemption.** A waiting wake which no node may take now may stop long-lived agents to make room. It
  defers to a wake ahead of it in the queue only if that one fits a node now or could make room this way
  itself, so a wake that can't be served doesn't hold preemption up. It stops only active long-lived agents
  of its own tenant whose manifest marks them [`placement.preemptible`](manifest.md#placement), whose
  priority is below its own, and **which have no live child**: on one node, each one needed to make the
  room, the lowest priority first.
  - **How.** Each agent is stopped the normal way an agent stops: it is asked to hibernate at its next
    quiet point, as `wicket hibernate` asks, so it keeps its work and can be woken again. Nothing is
    revoked. Hibernating ends the agent's run, which stops its children, so an agent with a child still
    running is never chosen. Each is audited as `placement.preempted` (the run, its agent, node and
    priority, and the run it made room for). An operator's own `wicket hibernate` request stands; the
    preemption's request is tagged, so it alone is ever withdrawn.
  - **The room.** The wake reserves the room on that node while they hibernate, renewing the reservation,
    so another start doesn't take it. Room is all it makes: a node out for a label, a taint, its CA or an
    affinity stays out. The wake is placed once the node's report shows the room, and the node's admission
    still decides. An agent that has hibernated counts as gone until a node report from after its end
    arrives, so a second agent isn't stopped for the same room.
  - **The deadline.** An agent asked counts as gone for 5 minutes, so nothing more is stopped for the same
    room. One that hasn't hibernated by then (a hibernate request can be declined) is left alone for the
    rest of that wait: preemption's request is withdrawn (and its supervisor, if it has taken the request
    already, drops it before hibernating), the room released, and it is audited as
    `placement.preempt_abandoned`. A wake that is placed, gives up waiting or fails, while agents it asked
    still run asks them no more in the same way, and releases any room it held.
  - **The agent's side.** Before it hibernates for preemption (at its quiet point, and again before it
    stops what lingers in its box), the agent's supervisor checks the request is still wanted. It declines
    if preemption gave up, the request is older than the deadline, the wake that asked no longer waits or
    holds a reservation (it ended, failed or was killed), or the agent has started a child since (which
    hibernating would stop). A decline is audited as `placement.preempt_declined`, and the wake gives up
    on that agent at once. An operator's own `wicket hibernate`, and the agent's own request, always go
    ahead.
  - **Cost.** The wake works out what it would stop from the nodes' last reports first, without a write
    lock; only then does it ask every node for its room (a report may still count a box that has ended),
    at most every 30 s, and always after a preemption completes. It doesn't preempt with under 30 s of its
    wait left.
  - **Programs are never preempted.** That's a decision: a program has no stop that keeps its work, so
    stopping one for room would lose it.
  - Each box's limits and priority are recorded at its start (`run_terms`, ledger schema 33); a box
    started by an older build has none and is never preempted. A named node (`--node`) and a spawn never
    preempt.
- **Score.** Of the nodes left, those meeting the most preferences first; then bin-pack: the one left with the least memory, then the fewest vCPUs, once
  the box is on it. Where the agent ran before breaks a tie, then the name, so the same inputs always give
  the same node. A spread strategy exists in the function for later.
- **Refusal.** With no node left the wake is refused, naming every node and every reason it was out
  (`n1 (tainted dedicated=ci, not tolerated), n2 (0.5 vCPU, 512 MiB free)`). The node's own admission
  stays the last word: it may still refuse the box it was given.

A queue, reservations for starts in flight, and placing new runs (not only wakes) come next, on #582's
cached capacity index.

## Images on nodes

A box on a node starts from an image its node has. A box whose image is pinned by digest (#192,
[manifest](manifest.md#image-pins)) starts as exactly that image, and a remote node that lacks it gets it
from the control host first (#191):

- **Asked first.** Before the box starts, the control host asks the node whether it has the digest; only
  if it hasn't does anything move. The control host's own node shares its runtime and is never sent one.
- **Sent as an OCI image layout.** The control host's runtime exports the image by digest as an [OCI image
  layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) archive, streamed over the
  node channel in a window of 16 MiB that the node acknowledges as it takes it, so neither end holds the
  image in memory.
- **Verified on the node, as it arrives.** The node takes only `oci-layout`, `index.json` and
  `blobs/sha256/<hex>` as regular files, each once (anything else refuses the image), and hashes every blob
  as it writes it: a blob that doesn't match its name refuses the image. The pin must be a blob of the
  archive, an image index or manifest; every manifest under it must have its config and layers there, at the
  sizes it gives, and at least one must be complete (an index may name other platforms' images the archive
  lacks). The sender's `index.json` and tags (`manifest.json`) are dropped, and so is every blob the pin
  doesn't reach.
- **Imported as checked.** The node writes its own layout naming the pin alone, as `repository@digest` (no
  tag moves), and its runtime imports that; the box then starts by the image's id, which must be the pin.
  The image is never fetched from inside a box.
- **Or pulled by the node from a registry.** If the image's registry is listed in `images.yaml`
  (`registries`, [files](files.md)), the node pulls it itself, host-side, by digest, before the control host
  sends anything. It falls back to being sent if the pull fails and the control host has the image.
  - **Only the listed hosts.** The node talks only to the registry's host, its token service's
    (`auth_hosts`) and where it redirects blob downloads (`blob_hosts`); any other host, a redirect
    included, is refused. HTTPS only, except for a registry on a loopback address. Never from inside a box.
  - **By digest.** The manifest is fetched by the pin and must hash to it. From an index, only the node's
    own platform is fetched. Every blob is hashed as it is written and must match its descriptor's digest
    and size. The layout is then checked and rebuilt as for a sent image.
  - **Credentials.** A registry's `secret` is a vault secret (`user:password`, or a token), bound to the
    registry's host and its `auth_hosts`. The node fetches it for the run over the run's own connection, as
    it fetches any secret (#152), holds it in memory for the pull only, and never writes or logs it. The
    control host releases it only while that run's image pull is under way, and audits it
    (`node.secret_fetch`, with `image_pull`); it isn't among the secrets the node keeps for the run.
- **Recorded.** The node's audit records `image.received` (digest, name, bytes, `via` `channel` or
  `registry`) or `image.refused` (why).
- **What it needs.** Both ends talking protocol 7 (8 to pull), and a runtime that ids images by their manifest digest
  (Docker's containerd image store): a pin that is a config digest is refused with that reason. An image
  of at most 64 GiB, with room for it under the node's data directory (`images/`, cleared when `serve`
  starts) while it is imported.
- **Not yet.** Images for children a node starts itself (#164) are not sent ahead: a child's image must be
  on its node. Tagged images are not sent: a tag is resolved where the box starts. `wicket self update`
  still loads its own agent image onto nodes by tag.

## Creating nodes (`wicket node create`)

`crates/wicket-placement` is the placement interface (#37): request capacity (CPU, memory, isolation tier,
region and plan hints, a price limit, an idempotency key) and get a node back; list, get and release owned
nodes. Backends are the operator's own machines (static hosts) and Vultr. `wicket node create`, `release` and
`plans` drive the Vultr one; `wicket node enrol` is for machines you already have:

```sh
wicket secret set vultr-api-key                     # read from the terminal; only ever sent as the API's bearer token
wicket node plans --region lhr                     # plans and their hourly price
wicket node create --name n2 --region lhr --vcpus 1 --memory-mib 2048 --lifetime 1h \
  --ssh-key-id <id of a key in the Vultr account> --ssh-key <its private key> \
  --hosts 'api.example.com'
wicket node list                                   # every node, a leased one with its lease end, provider and cost
wicket node list --provider                        # and the provider's owned instances, next paid hour
wicket node release n2                             # destroy now (by name or instance id), revoke the enrolment
```

- **Money.** `create` needs `placement.yaml`: its `max_hourly_usd` and `max_total_usd` are the limits, shared
  with capacity leases (#256). Before anything is asked, the node's hourly rate and worst case are reserved in the
  ledger as a pair of money quota grants, `QUOTA wicket.internal /quota/money.hourly/node-<name>` and
  `/quota/money.reserved/node-<name>`, made by `wicket:node-create`, in the same transaction as the one spend
  check (see [capacity leases](#capacity-leases-and-the-reconciler)); over the limits, it is refused. The
  reconciler renews the pair while the node bills; it is given back when the node is released, or when the
  create is denied or fails. `--max-node-hourly` caps this one node's price. Within the limits, the node is a
  `CAPACITY wicket.internal /capacity/node/<name>` request from the operator who runs `create`, its reason
  saying what is reserved with it (`Reserved with it: $X/h, $Y (limit $A/h, $B total)`): approved at once by a live [capacity grant](console.md#capacity-grants) of theirs that covers it
  (plans, regions, hourly and daily money, nodes at once), otherwise pending for an operator for up to `--wait`. Vultr
  bills per started hour, each line rounded up to the cent, with a 672 h monthly cap, so a node's lease ends at
  minute 50 of its last hour and `list --provider` shows when the next paid hour starts.
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
   agent's own cap) as two money quota grants bound to the asking run (#256):
   `QUOTA wicket.internal /quota/money.hourly/<lease>` (the hourly cap) and `/quota/money.reserved/<lease>` (the
   worst case), micro-USD, made by `wicket:lease-budget`, lasting the lease's duration plus an hour (at most 24h,
   renewable), and revoked when the lease ends. `wicket grant list` shows them; they never go to a node.
   The money quota grants are the only spend check (#256): `max_hourly_usd` and `max_total_usd` in
   `placement.yaml` (`examples/placement/placement.yaml`; without it the tool is off) are recorded as one
   tenant grant, `QUOTA wicket.internal /quota/money.limit` made by `wicket:placement.yaml`, renewed (or
   replaced, if the limits changed) at every check. In the transaction that records the new pair, the sums of
   every live pair (every lease's and every node `wicket node create` made), plus the new one, must fit it.
   Over budget is refused before an operator sees it. A claim from the warm pool goes through the same check.
   An owner-tagged machine the ledger doesn't know isn't counted: it is the reconciler's to destroy or adopt.
2. An operator decides it like any request (`wicket pending`, `wicket approve`/`deny`, or the console). The
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
wicket reconcile --every 30s      # the daemon: installed, the wicket-reconcile unit runs it (--every 1m)
wicket lease list                 # status, holder run, node, reserved, end, billed
wicket lease release <lease>      # end it now (one pass)
```

One pass (`wicket reconcile`, #38) compares the provider's instances, enrolled nodes and the boxes on this host
and on every node with the ledger's runs and leases, and makes them agree. `wicket approve` of a capacity ask runs
a pass at once; everything else (lease ends, approvals on the console) waits for the next `--every` pass.

- **Runs** whose supervisor is gone (#151) are asked about on their node. If it still has the box, the run
  is **adopted**: `wicket attach <run>` takes it over (logged in `<run dir>/ctl/attach.log`), the box
  untouched. If the node says the box is gone, the run ends as `lost`; if the node can't be reached, the run is
  left for the next pass. A run supervised on another machine is left to it. A child whose supervisor
  is **stuck** (it runs in its parent's process, and hadn't ended 30 s after its parent asked it to
  stop, #409) is reported as `run_stuck` on every pass while that process lives, and taken over like any
  other once it ends. `wicket top` shows its status as `stuck`, and counts it apart from the running runs.
- **A restart of the control host** is a pass away from normal: kill every wicket process on it, start
  again, and one `wicket reconcile` restarts this host's own node (whose `serve` adopts its boxes) and takes
  every run over, on every node. What a supervisor needs for that is in the run's `ctl/` directory: the run's
  record (`run.json`), its model spend and output offsets as it goes (`progress.json`); its
  identity is re-issued and its box's token re-minted with the grants already on the node.
  `ci/acceptance.sh` checks it, on this host's node and (`--nodes local`) another.
- **Leases** end when their run has ended or their end has passed; denied or withdrawn asks give their
  reservation back.
- **Machines.** Only instances tagged `wicket-owner-<installation>` are ever listed. One no live lease needs is
  destroyed; one that matches a lease the ledger lost track of (a crash between create and record) is adopted,
  not created again. Ownership is checked again right before every destroy, so a tag changed or a
  `wicket-protected` tag added since the list saves the machine.
- **Boxes** (`wicket=1` containers) whose run ended are stopped; a running run's box is left to its run (above);
  a box whose run this ledger doesn't know is left alone, since Docker may be shared. (It replaced
  `wicket reap`, removed in 0.0.2.)
- Every change is an audit record `reconcile.<what>`. One pass at a time per installation (a file lock).
- So killing every control-plane process mid-run and restarting leaves no orphaned machine or box after one
  pass, and every run whose box still runs is supervised again. **Not yet:** the daily money reconcile against the provider's own charges (design §8.5).

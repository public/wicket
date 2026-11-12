# 24 — De-SPOFing the control plane

Research date: 2026-11-12. Scope: everything the control host does today, what stops when it is gone, and how
to make it stop being a single point of failure. The owner's direction: the model proxy and the MCP gateway
should run on each node, and nodes must be able to run on their own for some time while the control host is
unavailable. This is research and design; no code changes.

Context: design §3.1 (process layout), §3.2 (identity, node identity), §8.5 (leases and money), §9.2–§9.4
(gateway, model proxy, upstream credentials), §13.5 (durability), §14.1.3 (console); [nodes.md](../nodes.md),
[limits.md](../limits.md), [concepts.md](../concepts.md); research [18](18-authorization-landscape.md) §5.1
(the signed feed) and [22](22-pause-resume-hibernate.md) (hibernate); `crates/wicket-feed`; issues #57 (feed),
#16 (node identity), #70 (hibernate), #146 (the control host is a node too).

Confidence tags: **[H]** verified against a primary source (official docs, source code at HEAD of `main` for
wicket, a named page for prior art). **[M]** a secondary source, or a primary one only partly checked.
**[L]** inference, not checked.

---

## 0. Summary

- **The control host is three different single points of failure, and they fail differently.**
  - A **partition** (the run processes live, the network to a node doesn't) is what #57 designed for: the
    node decides egress from its feed for 30 s, plain reads for 120 s more, then refuses everything. But the
    model and the MCP gateway stop at once, because they are tunnelled to the run process [H].
  - A **control-host restart** is worse than a partition. Every box's supervisor is a `wicket run` process
    *on the control host*. When it dies, the restarted reconciler ends its run as `lost` and stops its box,
    on every node [H]. Today a reboot of the control host ends every run in the installation.
  - **Losing the control host's disk** loses the ledger, the vault, every key (the issuer, the feed root,
    the authority root, the installation CA, the state key) and every hibernated agent. Nothing is
    replicated; the only off-host copy is an audit export, if one is configured [H].
- **Recommendation: move the run to the node, then lease it what it needs to run alone, then replicate
  what is left.** Concretely, in five phases (§6, one issue each: #151–#155):
  1. **The run lives on its node.** Per-run supervision, the model proxy, the MCP gateway and the run's
     budgets move into `wicket node serve`; the control host keeps policy, keys and the ledger, and
     re-attaches after a restart instead of ending runs. *Survives:* a control-host restart, with a partition
     shorter than the feed window. Doesn't yet survive a long outage: credentials are still relayed.
  2. **Credential and budget leases.** Each secret gets a residency: `control` (relayed, as today) or
     `node` (sealed to the node's key, held in memory, short-lived). Budgets are leased to nodes in slices.
     *Survives:* model calls and credentialed hosts through an outage, up to the lease.
  3. **Bounded autonomy.** Per-zone offline windows in the signed feed, queued asks, and self-fencing (a
     node stops its own boxes when its window closes). *Survives:* hours, as configured per zone.
  4. **State off the host.** The ledger streamed to S3-compatible storage, bundles and audit there too, the
     root key offline, and a documented restore onto a standby. *Survives:* losing the control host for good.
  5. **A replicated control plane.** Three control hosts with Raft (`openraft`) over the ledger's commands;
     only the leader publishes the feed, and frames carry its term. *Survives:* losing one control host with
     no human involved.
- **The core trade-off is one number.** Anything a node is given so it can run alone (a feed window, a
  credential, a slice of budget, a CA) is something an attacker who owns that node keeps until it expires.
  The autonomy window *is* the revocation latency for a compromised or partitioned node. wicket should let
  the operator set it per zone and show it, not hide it (§5).
- **Decisions for the owner** (§6.6): how long a node may run alone (default proposal: 1 h for reads and
  already-granted work, 15 min for model calls), and whether model calls continue offline at all (which
  needs the Claude access token on the node).

---

## 1. Inventory: what the control host does

Everything below was checked against the code at the merge of #150 [H] unless tagged otherwise.

### 1.1 Who holds what

| Responsibility | Where it lives | State | Who depends on it |
|---|---|---|---|
| **Run supervision** (`wicket run`) | One process per run on the control host; its owner label is `<machine>:<pid>:<start>` (`reconcile.rs`) | The run's proxies, budgets, identity keys, the node connection | Every box, on every node |
| **Model proxy** (`wicket-proxy/src/llm.rs`) | Inside each `wicket run` | Request and token counters (atomics in `Budget`), reservations for calls in flight, children's carve-outs | Every model call; nodes reach it through a tunnel |
| **MCP gateway** (`gateway.rs`) | Inside each `wicket run` | None of its own; every tool reads or writes the ledger | `spawn`, `send_message`/`await_message`, `request_access`/`await_grant`, `request_capacity`, `link`/`expose`/`connect`, `whoami`, `pending_requests` |
| **Egress for credentialed hosts** | The run's egress proxy on the control host | The run CA; injected credentials | Hosts with `inject` or a credential swap, hosts outside a node CA's name constraints, every host once a node CA expired |
| **Vault** (`vault.rs`) | One 0600 file per secret, plus `<name>.hosts`; `claude-oauth` is a reference to the host's Claude login, re-read on every use | Secrets; the host's Claude Code refreshes its own login | The model proxy, injection, credential swaps, `wicket place` (Vultr key) |
| **Feed publishing** (`noderun.rs`, `wicket-feed`) | One publisher per node, its delta log under `<data dir>/nodes/<name>/feed`; statements are signed by whichever run is connected | The node's online feed key (Ed25519, on the control host), its certificate from the feed root (7 days, renewed when a run starts with less than a day left) | Every node's egress decisions |
| **Authority** (`wicket-authz`, `wicket-feed/token.rs`) | The authority root key mints each box's block 0; the approver key signs grant blocks | Ed25519 keys, 0600 files | Every box's token; every grant |
| **Identity issuer** (`wicket-identity`) | One Ed25519 key | Agent identities (10 min, re-issued at half-life by the run), node certificates (24 h, renewed at half-life by a connected run), the control host's proof in the node handshake | Agent messages and envelopes, the console's checks, node mutual authentication |
| **Installation CA** (`ca.key`) | P-256 X.509 | Signs each node CA (24 h, path length 0, name-constrained), renewed with `wicket node renew-ca` over ssh | TLS termination on nodes |
| **Ledger** (`wicket-store`) | One SQLite database in WAL mode | Runs, identities and their history, requests and grants, messages, leases, nodes and their certificates, agents (generation, head bundle, spend), console sessions, passkeys, enrol links, the audit chain | Everything |
| **Audit chain** | The ledger, plus each node's own `audit.db`, shipped on connect | Hash chain (v2); signed checkpoints if exported (#91) | Verification, the console's activity |
| **Placement and reconciler** (`wicket-placement`, `reconcile.rs`) | `wicket place`, `wicket reconcile --every` on the control host, one pass at a time by file lock | The Vultr key (vault), owner tags, leases and reservations | Capacity leases, cleanup of lost runs and orphaned machines |
| **Hibernate store** (`hibernate.rs`) | A directory store under the data directory, sealed under `state.key` | Bundles (content-addressed trees), the agent rows | Wake on any node |
| **Console** (`wicket serve`) | On the control host, direct access to the ledger | Passkeys and sessions in the ledger; ACME certificates | Approvals, starting runs, revocation, from any device |
| **wicketd** (`wicket daemon`) | The control host's unix socket | Its policy file | Every local command under the daemon install |

### 1.2 What fails, and for how long

Three failure classes, per responsibility. "Partition" means the run processes are alive and a node can't
reach them; "restart" means every control-plane process died and came back within minutes; "loss" means the
control host's disk is gone.

| Responsibility | Partition | Restart | Loss |
|---|---|---|---|
| Egress (reach rules, splice) | Fresh 30 s, then plain reads (R1) for 120 s, then closed [H] | Same, then the next reconcile pass ends the run as `lost` and stops the box [H] | Closed after 150 s; the box runs to its timeout with no egress; nobody stops it [L] |
| Egress with credentials | Refused at once (tunnelled) [H] | Refused, then the box is stopped | Refused |
| Model calls | Refused at once (tunnelled) [H] | Refused, then stopped | Refused; and the subscription login is gone with the host |
| MCP gateway | Unreachable at once [H] | Unreachable, then stopped | Unreachable |
| Approvals and asks | A node can't raise an ask; its 403 has no request id [H] | Pending requests survive in the ledger; their runs don't | Lost |
| Spawn, links, messages | Stop [H] | Stop; the runs end | Lost |
| Grants already pushed | Usable while fresh (30 s) [H] | Same | Same |
| Revocation | Applied as soon as a delta arrives; a node that hears nothing goes stale in 30 s [H] | Same | Same, and nothing can revoke anything again |
| Node certificate (24 h) | Renewed only by a connected run; lapses 24 h after the last renewal [H] | Same | Lapses |
| Node CA (24 h) | Renewed only by `renew-ca` over ssh; once expired every host is forwarded, so refused [H] | Same | Lapses |
| Feed key certificate (7 days) | Renewed when a run starts [H] | Same | Lapses; the node closes |
| Output and stdin | Node buffers 4 MiB per stream and replays [H] | The new process can't re-attach; the box is stopped | Lost |
| Audit | Buffered on the node, shipped on reconnect [H] | Same | The control host's chain is lost unless exported |
| Hibernate and wake | Stop (the store and `state.key` are central) [H] | Resume after restart | Every hibernated agent is lost with `state.key` |
| Placement, leases, reconciler | Stop; machines keep billing [H] | Resume; one pass cleans up | Machines keep billing until someone finds them by tag |
| Console, wicketd | Unaffected for local users | Down for the restart | Gone, with every passkey registration |

Three things the brief's list leaves out:
- **A restart kills runs.** `reconcile.rs` ends a run whose supervising process is gone *on this machine*,
  and then stops its boxes here and on every enrolled node over ssh. `nodesrv.rs` likewise stops boxes a
  previous `serve` started when it restarts (`reap_previous`). So the box survives a lost network, not a
  lost process on either end.
- **The real ceilings on running alone are 24 h, not 150 s, once the feed is solved.** The node certificate
  and node CA last 24 h and are renewed only from the control host. Any autonomy longer than that needs them
  renewed differently (§3.5).
- **Budgets are per run, in memory.** The counters are atomics in the run process, with a long-lived agent's
  lifetime spend written to its agent row at the end of an activation. There is no global budget today; the
  "global budget" problem in §3.3 is about keeping a per-run or per-agent budget correct once its proxy is
  on a node, and about any future tenant-wide cap.

---

## 2. Options per responsibility

Five families of options, with where each one fits.

- **(a) Run it on every node.** For things whose state is per box: run supervision, the model proxy's
  accounting, the gateway's local tools, the egress proxy (already there). No consensus needed, and the
  failure domain becomes the node.
- **(b) Replicate it.** For the ledger and anything that needs one answer: grant use counts, lease
  reservations, the agent generation. Options:
  - **Raft in-process (`openraft`)**: commands are ledger operations, applied to SQLite on each replica. The
    application owns determinism (the leader stamps time and ids into the log entry). Most work, best fit.
  - **rqlite**: SQLite behind Raft as a separate server, statement replication over HTTP. wicket's ledger
    code uses `rusqlite` transactions directly, so moving to rqlite means rewriting the store against its
    API and reasoning about non-deterministic SQL (`now()`, `random()`) [M].
  - **LiteFS / Litestream**: single-writer SQLite with WAL shipping. Litestream streams to object storage
    and gives point-in-time restore, which is design §13.5's plan for a single host. Neither gives automatic
    failover with a quorum: they are durability, not availability.
  - **etcd**: a strongly consistent key-value store; would mean leaving SQLite for the ledger. Too large a
    change for what it buys here.
- **(c) Threshold or multi-signer keys.**
  - **FROST** (RFC 9591, Ed25519 ciphersuite) produces ordinary Ed25519 signatures, so every verifier wicket
    has (the feed's JWS, Biscuit blocks, identity JWS) would accept them unchanged. But signing is a two-round
    protocol among a threshold of signers, and the feed re-signs a freshness statement every 5 s. FROST fits
    keys that sign rarely and matter most: the feed root and the authority root, held by the operator's
    devices or the control hosts, 2-of-3. It does not fit the installation CA, which is P-256 X.509: FROST's
    P-256 ciphersuite yields Schnorr signatures, not ECDSA, so X.509 verifiers can't check them.
  - **Several signers, each certified**: each control host has its own online feed key and issuing key,
    certified by the (offline or threshold) root. Verifiers accept any certified key. Cheaper and simpler
    than FROST for online keys; the risk is two signers disagreeing (split brain), which §2.1 fences.
- **(d) External durable stores.** S3-compatible storage for bundles (research 22 already recommends it),
  audit segments with signed checkpoints (#91 has the format), and the ledger's WAL. This is the cheapest
  large gain: it turns "loss" into "restart from a backup" without any consensus.
- **(e) Offline-bounded autonomy.** Give the node what it needs for a bounded time: a longer feed window per
  zone, short-lived credentials sealed to its key, slices of budget, a queue for asks, local hibernation.

### 2.1 Per responsibility

| Responsibility | Recommended | Alternatives and why not first |
|---|---|---|
| Run supervision | (a) on the node; the control host re-attaches | Keeping it central and making it survive restarts (re-attach only) helps restarts but not partitions |
| Model proxy | (a) on the node, plus (e) a credential lease and a budget lease | Relay through a replicated control plane: survives a control-host loss, not a partition |
| MCP gateway | (a) on the node; local tools local, ledger tools queued or refused | A central gateway behind (b): same limits as the model proxy |
| Credentialed egress | (a) + (e) for secrets marked `node`; relay for the rest | All relayed: no autonomy for those hosts |
| Vault | (b) replicated with the ledger; (e) leases out | An external KMS or Vault: a new dependency with its own HA story |
| Feed publishing | Leader-only publishing, frames carry the Raft term (b)+(c, several signers) | FROST per statement: a two-round protocol every 5 s |
| Authority root, feed root | (c) FROST 2-of-3, or offline; online issuing keys certified under them | A single offline root: fine for one owner, and the first step |
| Identity issuer | Per-control-host issuing keys under the root; per-node issuing keys for agent identities, constrained to the node's own runs | One central issuer: agent identities (10 min) then bound autonomy to 10 min |
| Installation CA | Per-control-host intermediates; node CAs renewable by any control host | Threshold ECDSA (multi-round, rarely implemented in Rust): not worth it |
| Ledger | (d) Litestream-style streaming first, then (b) Raft | rqlite or etcd: a store rewrite |
| Audit chain | Node chains already independent; (d) export segments and checkpoints | — |
| Placement, reconciler | Leader-only, with fencing; (e) a provider-side lifetime on every machine | — |
| Hibernate store, state key | (d) S3-compatible store; per-agent data keys wrapped to the tenant key and to the node holding the agent | One central `state.key` (today): its loss loses every agent |
| Console, passkeys | Stateless console on every control host behind one name; passkeys in the replicated ledger | Approvals verified on the node (§3.4) as a later step |
| wicketd | One per control host and one per node (already a local socket) | — |

---

## 3. The model proxy and the MCP gateway on each node

This is the owner's direction, designed in full. It depends on phase 1 (the run lives on its node): the
proxies are per run today, and the process that holds a run's budgets and identity is the natural owner of
its proxies.

### 3.1 Shape

`wicket node serve` already owns the box, its egress proxy (with the same `wicket_proxy` code as the
control host) and its feed replica. It gains, per box:
- **the model proxy** (`wicket-proxy/src/llm.rs`, unchanged in what it checks: model allowlist, server-side
  tool stripping, body pre-parse, token and request budgets, liveness, events);
- **the MCP gateway** (`gateway.rs`), with each tool marked by what it needs (§3.4);
- **the run's supervision**: identity renewal (from a node issuing key, §3.5), the timeout (already there),
  output buffering (already there), and the audit of all of it in the node's chain.

The control host keeps the ledger and the keys, and becomes a client of the node for the run: it attaches
for stdio and events, pushes the feed, takes asks and audit, and *re-attaches* after its own restart. The
run is ended by the node (timeout, exit), by an operator, or by the control host's reconciler only when the
node says the box is gone, or the node's lease of the run (§5.1) has expired.

### 3.2 The model credential

The model credential is the owner's Claude subscription login, used only by Claude Code, per Anthropic's
terms; wicket never uses an API key. Today `claude-oauth` is a *reference*: the model proxy re-reads the
current access token from the host's Claude login on every request and never touches the refresh token, so
the host's own Claude Code keeps refreshing it (`vault.rs`) [H]. The proxy only ever relays requests that
Claude Code in the box made; that stays true on a node.

What wicket can and can't give this credential:

| Property | Possible? | How |
|---|---|---|
| Short-lived | Only as short as the upstream access token; wicket can't mint a narrower one | The node gets the *access* token only, with its upstream expiry, and drops it at that time or at the lease end, whichever is first. The refresh token never leaves the control host. The access token's lifetime is the upstream's choice; a few hours is our observation, not a documented figure [L] |
| Scoped | No: a subscription access token can't be narrowed by wicket | wicket's own scope stays in the proxy (models, server-side tools, budgets), which on a rooted node is advisory |
| Wrapped to the node | Yes | HPKE (RFC 9180, X25519) to a node encryption key made at enrolment beside the Ed25519 node key, certified in the node certificate; delivered over the authenticated channel; held in memory only (never written to the node's disk), zeroed on drop |
| Revocable | Only by the upstream (signing the login out, which also ends the host's Claude Code session) | wicket stops renewing it to a node at once; the node drops it on revocation; a rooted node keeps it until it expires |

Two residency modes for `claude-oauth` (and any secret, §3.3):
- **`control` (default, today's behaviour)**: the node's model proxy does all its checks locally and
  forwards the request over the channel to the control host, which adds the bearer and sends it. The node
  never holds the token. Model calls stop during an outage.
- **`node` (opt-in per zone)**: the control host pushes the current access token sealed to the node, renews
  it as the host refreshes, and never pushes it to a node whose feed is stale. Model calls continue for the
  zone's model offline window (§5.1) or until the token expires, whichever is first.

The token broker stays single: only the control host's Claude Code refreshes the login. Several control
hosts (phase 5) need one of them to own the refresh and replicate the *access* token, never the refresh
token, to the others [L: whether two concurrent refreshers of one login invalidate each other is not
documented; assume they do].

### 3.3 Budgets across nodes

Today a budget is per run (or per long-lived agent, over its life), counted by the run's model proxy, and a
child's share is carved out of its parent's at spawn [H]. On nodes:
- **A run's budget moves with the run.** The node's model proxy owns the counters; the run's total is
  known at start (zone budget minus the agent's prior spend). No coordination is needed while the run and
  all its children are on one node.
- **Children on other nodes get their carve-out as today.** Spawn needs the control plane anyway; the
  parent's node reserves the child's share before the spawn is sent, and gets nothing back (as today:
  limits.md, "a child's reservation counts as spent").
- **Shared budgets (a tenant's monthly cap, a team's pool) use budget leases**, the escrow pattern from
  the demarcation protocol [M]: the ledger holds the account; a node holds a lease of a slice (say 10% of
  what is left, or a fixed number of tokens) with an expiry; it spends locally, asks for more at half
  spent, and returns the remainder when the lease ends. Spend reports go with the audit stream.
  - Overspend is bounded by the sum of outstanding slices, and only if a node is lost with its usage
    unreported, since a node reports actual usage on reconnect.
  - Offline, a node can spend its current slice and nothing more.
  - A **rooted node isn't bounded by any of this**: budgets are enforced by the proxy, and a node that holds
    the bearer can call the upstream directly. Budget leases bound an *honest* node offline. Only the
    credential's own lifetime bounds a compromised one.

### 3.4 The gateway's tools, and MCP servers' credentials

| Tool | Needs | Offline behaviour |
|---|---|---|
| `whoami`, `pending_requests` (local view), `links` | The node's own state | Works |
| `request_access`, `await_grant` | The ledger and a human | Queued: the node records the ask with a node-local id, the agent's `await_grant` waits on it, and it is raised on reconnect. Approval still needs the control plane (the approver key). A later option: approvals verified on the node from a passkey assertion over the ask's digest, with operators' public keys in the feed, so any control host's console can approve without the ledger being reachable from the node |
| `send_message`, `await_message` | The recipient's node; ordering; the ledger | Same-node messages could be delivered locally; otherwise queued with a deadline |
| `spawn`, `request_capacity`, `link`, `expose`, `connect` | Placement, budgets, the ledger | Refused with "the control plane is unreachable", like egress in closed mode. A spawn on the same node within the parent's carve-out could be allowed later |

Credentials for MCP servers and injected hosts (design §9.2 kinds 3–4, §9.4) fall in three classes:
1. **Mintable, scoped and short-lived** (GitHub App installation tokens scoped to repositories and
   permissions, AWS STS sessions, Cloudflare scoped tokens). Mint per run and lease to the node, sealed to
   its key, for the token's own lifetime. These are the best case: the upstream enforces scope and expiry.
2. **Static secrets** (PATs, API keys). Default `control`: relayed, never on a node. `node` only by an
   explicit operator choice, with the same hosts binding as today.
3. **OAuth tokens for remote MCP servers**, audience-bound per agent × route × upstream. The access token
   can go to the node as in class 1; the refresh token stays central.

Third-party MCP servers (design §8.2) run as their own workloads beside the box, on the same node, with
their credentials leased the same way.

### 3.5 Identities on the node

Agent identities live 10 minutes and are re-issued by the run every 5 [H]. If the run is on the node, the
node needs to issue them. Two options:
- **A node issuing key**, certified by the issuer for the node's own runs only
  (`spiffe://<install>/node/<name>/…`, or the run ids placed on it), valid for the node's autonomy window.
  Verifiers check the chain. This is SPIRE's shape inverted: the server certifies a node-scoped signer.
- **Pre-issued identities**: the control host issues a batch covering the autonomy window. Simpler, but every
  key in the batch exists at once, which defeats rotation.

Recommended: the node issuing key. The node certificate and node CA (24 h) are renewed by whichever control
host is reachable, over the channel (not only `renew-ca` over ssh), so the hard ceiling on autonomy stays
24 h unless the operator raises it.

### 3.6 What an attacker who owns one node gets

Today (limits.md): the boxes' workspaces and decrypted traffic on that node, and any request to hosts within
its CA's name constraints until the CA expires (24 h). Never: injected credentials or the model token.

With per-node proxies, additionally:
- **with secrets in `control` residency: nothing more.** The proxies' checks were already on a machine the
  attacker controls for traffic they could already see; budgets are advisory against them, but every call
  still goes through the control host, which counts it again (the relay is a second meter).
- **with `node` residency:** the model access token until its upstream expiry (they can use the owner's
  subscription for anything, at the owner's quota and reputational risk), each leased secret until its
  lease or upstream expiry, the node's budget slices, and the node issuing key until its certificate
  expires (identities for runs on that node only).

So `node` residency for the model token should be opt-in per zone, offered only to nodes the operator
trusts more (their own hardware, or later an attested runtime), and shown in `wicket node list` and on the
console as "holds the model credential until …".

---

## 4. Prior art: what keeps working when the control plane is down

What each system keeps working when its control plane is down, and for how long. Tags carry over from the
pages read; "not found" means the behaviour could not be confirmed from a primary source.

| System | Control-plane HA | Data plane while it's down | Bound | Revocation while it's down |
|---|---|---|---|---|
| **Nomad** | 3 or 5 servers per region, Raft [H] | Allocations keep running; without a `disconnect` block they are never stopped on the client [H] | `disconnect.stop_on_client_after`: the client stops its own allocations after this; `lost_after` lets the servers wait before replacing; `heartbeat_grace` 10 s, `failover_heartbeat_ttl` 5 min [H] | Not possible: servers can only stop what they reach |
| **Consul** | Raft on servers, 3 tolerate 1 failure, 5 tolerate 2 [H] | Agents serve cached results (`stale-if-error`, background refresh) [H] | ACL `token_ttl`/`policy_ttl`/`role_ttl` 30 s; `acl.down_policy` default `extend-cache` uses cached entries past their TTL [H] | Lags by the TTL; with `extend-cache`, indefinitely while servers are down [H] |
| **Kubernetes** | etcd quorum, 3 or 5 members [H] | Pods keep running; nothing can be started, stopped or updated; kubelets keep serving the same pods even if storage is lost [H] | Node marked unhealthy after `--node-monitor-grace-period` (50 s), pods evicted after the default `tolerationSeconds` 300; clusters of ≤50 nodes in a mostly unhealthy zone stop evicting [H] | Not possible; the kubelet keeps running pods (the opposite of Nomad's `stop_on_client_after`) |
| **Vault** | One active node holding a lock, standbys forward; integrated Raft storage, 5 servers recommended [H] | Vault Agent caches tokens and leased secrets and renews them; entries go at max TTL or failed renewal [H]. Explicit outage behaviour: not found | Each secret's lease TTL | Revocations made directly on the server can go unnoticed by the agent's cache [H] |
| **Boundary** | Several controllers sharing Postgres [H] | **Workers cancel every proxied session** once they have gone `successful_status_grace_period` (15 s) without reaching a controller [H, source] | 15 s | Immediate: a cut-off worker fails closed |
| **Teleport** | Auth instances behind a load balancer, over an HA backend (etcd, Postgres, DynamoDB, Firestore); SQLite isn't HA [H] | SSH sessions continue with async recording, uploaded later; agents cache roles and configuration [H]. New logins with Auth down: not found | User certificates 12 h by default [H] | Locks: `best_effort` (default) keeps the last known locks; `strict` ends interactions when locks can't be shown fresh [H] |
| **SPIRE** | Several servers on a shared SQL datastore, each with its own CA [H] | Agents keep SVIDs and rotate them early so they outlast an outage [H] | `availability_target` (minimum 24 h) is the outage the agent is sized for; X.509 SVIDs 1 h by default, JWT 5 min, CA 24 h [H] | At SVID expiry |
| **Tailscale** | One coordination service [H] | Existing devices keep talking with stored keys and cached ACLs; no new devices, ACL changes or revocations [H]. A client that restarts used to lose its network map; an on-disk cache is rolling out [H] | Node keys 180 days by default [H] | None while it's down [H] |
| **Cloudflare Access** | A global edge with a separate control plane [H] | A 40 h control-plane outage (2023-11): security services kept working, configuration changes failed [H]. A 2025-06 storage outage: identity logins failed, by design closed; service tokens, mTLS and IP policies kept working [H]. 2025-11: existing sessions unaffected, new logins failed [H] | Sessions default to 24 h [H] | Per-application "revoke existing tokens" is immediate; logout takes 20–30 s [H] |

What wicket takes from them:
- **Two schools, and wicket needs both, per zone.** Consul, Kubernetes, Tailscale and Teleport (`best_effort`)
  keep the data plane running on cached policy, and revocation waits. Boundary and Teleport's `strict` mode
  fail closed in seconds. wicket's feed is the second school today (150 s). The proposal (§5.1) is to let a
  zone choose its place between them, with defaults near Boundary's for writes and near SPIRE's for reads.
- **Size autonomy explicitly.** SPIRE's `availability_target` is the best model: a declared outage the
  data plane must survive, from which rotation is derived. wicket's `offline` windows are the same idea,
  per zone.
- **The node fences itself, the control plane waits.** Nomad's `stop_on_client_after` (client side) with
  `lost_after` (server side) is exactly §5.2's pair.
- **Restarting the data plane must not lose the cache.** Tailscale's restart problem is wicket's
  `reap_previous`: a node or run process that restarts during an outage must come back from what it
  persisted, not empty.
- **Hidden central dependencies cause the outages.** Both Cloudflare write-ups trace failures to a store
  everything quietly depended on. wicket's equivalents are the ledger and `state.key`.
- **Credential caches are where revocation goes to die.** Vault Agent's cache can miss revocations made on
  the server, and Consul's `extend-cache` serves revoked tokens while servers are down. Leased credentials
  on a node must be pushed revocations and must expire on their own.

Supporting tools:
- **openraft** 0.10 (stable, active, breaking changes possible before 1.0), with a Jepsen suite and a
  deterministic simulation fuzzer in CI; used by Databend [H].
- **rqlite**: Raft over SQLite, writes through its HTTP API, up to about 11 voters [H].
- **Litestream** 0.5 moved to the LTX format with compaction, and uses S3 conditional writes as a
  single-writer lease without a separate coordinator [H]. **LiteFS** is pre-1.0 and "outside [Fly's] scope of
  support", and LiteFS Cloud was retired [H]/[M].
- **FROST** (RFC 9591, June 2024, Informational) has Ed25519, ristretto255, Ed448, P-256 and secp256k1
  ciphersuites; the Zcash Foundation's `frost-ed25519` is at 3.0, described as stable, with an audit of an
  earlier version [H].
- **Anthropic's terms** for subscription OAuth: it is for "ordinary use of Claude Code and other native
  Anthropic applications", and allows an end user signing in to the unmodified Claude Code binary with their
  own subscription; third parties may not route requests through subscription credentials on behalf of
  their users [H]. A per-node model proxy that relays the box's own Claude Code requests for the owner keeps
  to that, as the control host's does; the token must never serve any other client.

---

## 5. Threat model changes

### 5.1 Revocation latency against autonomy

Every bound is the minimum of what the node is told and the maximum of what it was given. For a node that
stops hearing from the control plane (partitioned, or cut off deliberately by an attacker who owns the path
or the node):

| What | Today | Proposed default | Who bounds it |
|---|---|---|---|
| Reach-rule removal, grant and run revocation | 30 s | The zone's `offline.fresh` (default 30 s) | The feed |
| Plain reads after that | 120 s more | The zone's `offline.reads` (default 1 h) | The feed |
| Grants already pushed, writes in reach | 30 s | The zone's `offline.work` (default 15 min) | The feed |
| Model calls | 0 | `offline.model` (default 0 = relay only; 15 min when the zone opts in) | The credential lease, capped by the upstream token |
| Credentialed hosts | 0 | 0 for `control` secrets; the secret's lease for `node` ones | The credential lease |
| Node identity and node CA | 24 h | 24 h | Certificates |
| A compromised node | 24 h within its CA's constraints | max(24 h CA, every lease it holds) | Certificates and leases; nothing else |

The zone's offline windows travel in the signed feed with its policy, so a partitioned node can't stretch
them, and `wicket zone` shows them. Revoking a node today revokes its certificates in the ledger; with
leases, it also stops renewing them, and the latency for a node that is *already* cut off is the right-hand
column. Distributing node CA revocations (limits.md: recorded, not distributed) matters more once nodes run
alone, because other nodes and control hosts are the verifiers.

### 5.2 Partitions: "down" or "cut off"

The control host cannot tell a dead node from one that is partitioned, or one an operator revoked that is
still running. Rules:
- **A node fences itself.** When its window for a zone closes, it stops that zone's boxes (pausing them first
  if they can hibernate locally, §5.5). Nomad's `stop_on_client_after` and Kubernetes' behaviour of *not*
  stopping pods are the two choices; wicket should take Nomad's, because a box that can't be supervised
  shouldn't keep acting.
- **The control plane waits out the fence before replacing.** A long-lived agent on an unreachable node is
  woken elsewhere only after the node's longest window for it has passed (plus the clock-skew tolerance).
  Until then a wake is refused. The agent's generation (#70) already makes the *proxies* refuse a stale
  copy; with proxies on the node, the time fence is what keeps two copies from acting at once.
- **Asks queued offline are raised with their original time and the node's chain position**, so the
  approver sees that the ask is old.

### 5.3 Split brain among control hosts

With several control hosts (phase 5), two could believe they lead. Rules:
- Only the Raft leader publishes feed frames, issues grants, and runs the reconciler. Every frame carries the
  leader's term; a node refuses frames from a lower term than the highest it has seen, and treats a higher
  term as a new publisher whose snapshot must chain to state it verified (or a re-genesis).
- Placement and destroys are fenced by the term too: `Placer::release` refuses if the caller's term is no
  longer current (a check against the ledger right before the call, as ownership is checked today).
- Two control hosts can't form a quorum; three can. With two sites, the third member can be a witness
  that votes but stores nothing.

### 5.4 Clock skew

Today the node reads the wall clock once at start and advances it with a monotonic clock, and the feed
tolerates a bounded future skew [H]. Longer windows make skew matter less as a fraction, and the bounds stay
"window + tolerance". Leased credentials carry two expiries: wicket's (checked on the node's clock) and the
upstream's (checked on the upstream's clock); the node drops at the earlier of its own. The control plane
judges anything shipped later (audit, spend) at its own record time, as it does now.

### 5.5 A stolen node, and local hibernation

A stolen node (disk taken, or root on it) has: its node key and node encryption key, any sealed leases on
disk (none, if leases are memory-only), the boxes' workspaces, and any locally hibernated bundles. So local
hibernation must not use the installation's `state.key`. Instead each agent gets its own data key (design
§13.5), wrapped to the tenant key (central) and, while the agent is on a node, to that node's encryption key.
The node can hibernate and wake the agent locally while offline. Stealing the node exposes only the agents
it held. Revoking the node drops its wrapping, and the control plane re-wraps when the agent moves.

---

## 6. Recommendation

### 6.1 Target architecture

```
              ┌──────────── control plane: 1 host, later 3 (Raft) ────────────┐
              │ ledger (SQLite, streamed to S3) · vault · placement · console │
              │ issuing keys under an offline/threshold root · feed publisher │
              └──────┬────────────────────────────────────────────┬───────────┘
        signed feed, │ leases (credentials, budget, identity),     │ bundles, audit,
        asks, audit  │ re-attach after restart                     │ WAL segments
              ┌──────▼──────────────────────────────┐        ┌────▼─────────────┐
              │ node: wicket node serve             │        │ S3-compatible    │
              │  per box: supervision, model proxy, │        │ object storage   │
              │  MCP gateway, egress proxy          │        └──────────────────┘
              │  feed replica with per-zone windows │
              │  node issuing key, sealed leases    │
              │  ask queue, local hibernate         │
              └─────────────────────────────────────┘
```

### 6.2 Phases

Each phase says what keeps working during an outage once that phase alone has shipped.

1. **The run lives on its node** ([#151](https://github.com/public/wicket/issues/151)). Per-run supervision, the model proxy, the MCP gateway and the
   run's budgets move into `wicket node serve`. The control host relays credentials as today, and on restart
   re-attaches to the boxes nodes report instead of ending their runs; the reconciler ends a run only when its
   node says the box is gone or the node's lease of the run has expired. `reap_previous` on a node keeps boxes
   whose run is still leased. *Keeps working:* every run through a control-host restart (up to the feed
   window), and the gateway's local tools during a partition. *Not yet:* model calls and credentialed hosts in
   a partition (still relayed). This phase alone does not buy outage tolerance for the model; it is the base
   for phase 2, and it fixes the worst failure (a reboot ends every run).
2. **Credential and budget leases** ([#152](https://github.com/public/wicket/issues/152)). Secret residency (`control` | `node`), a node encryption
   key, HPKE-sealed memory-only leases, the access-token-only rule for `claude-oauth`, budget leases for any
   shared budget, and `node list` showing what each node holds until when. *Keeps working:* model calls and
   `node`-resident credentialed hosts for the life of their leases, which is still capped by the feed window
   until phase 3.
3. **Bounded autonomy** ([#153](https://github.com/public/wicket/issues/153)). Per-zone `offline` windows in the feed (§5.1), queued asks with
   node-local ids, self-fencing, node issuing keys for agent identities, certificate renewal over the
   channel from any control host, distributed node CA revocations, and local hibernation with per-agent
   data keys. *Keeps working:* configured work for hours with no control host; the node stops what it can't
   supervise.
4. **State off the host** ([#154](https://github.com/public/wicket/issues/154)). Stream the ledger's WAL to S3-compatible storage (Litestream or our
   own, with point-in-time restore), the hibernate store and audit segments on the same store, the feed root
   and authority root offline (or FROST 2-of-3) with online issuing keys under them, and a tested restore onto
   a standby host. *Keeps working:* the installation survives losing the control host, after a restore of
   minutes, with seconds of RPO; nodes ride through the gap on phase 3.
5. **A replicated control plane** ([#155](https://github.com/public/wicket/issues/155)). Three control hosts, `openraft` over the ledger's commands
   (deterministic: the leader stamps time and ids), the vault replicated with it, leader-only feed
   publishing and reconciling with term fencing, a stateless console behind one name, and one Claude login
   refresher. *Keeps working:* everything, through the loss of one control host, without a human.

Phase 1 and 2 together are the owner's direction and the biggest gain; phase 4 is cheap and independent and
can go in parallel. Phase 5 is only worth it once phases 1–4 have shown how much the control plane still
matters day to day: with nodes running alone for an hour and a restore in minutes, a single control host
plus a standby may be enough.

### 6.3 Not recommended

- **FROST for online signing** (feed statements, grants, identities): a two-round protocol on every signature
  with signers that must be online together. Use it, if at all, for roots.
- **rqlite or etcd for the ledger**: a rewrite of `wicket-store` for consensus we can get in-process.
- **LiteFS for failover**: single-writer with a lease service is availability only if the lease service is
  itself HA; Litestream covers the durability half with less.
- **Keeping the model proxy central and only replicating it**: it fixes control-host loss, not partitions,
  and partitions are what remote nodes see most.

### 6.4 Open decisions for the owner

1. **How long a node runs alone.** Proposal: per zone, defaults `fresh` 30 s (as now), `work` 15 min,
   `reads` 1 h, hard cap 24 h (the certificates). Longer windows mean slower revocation for a cut-off node.
2. **Whether model calls continue offline.** That needs the Claude access token on the node (§3.2): a
   rooted node can then use the subscription until the token expires, and wicket can't revoke it short of
   signing the login out. Proposal: off by default; opt-in per zone and per node.
3. **Whether static secrets may ever be node-resident.** Proposal: only by an explicit per-secret choice,
   never by default.
4. **Whether a node stops its boxes when its window closes** (Nomad's choice) **or keeps them running
   without egress** (Kubernetes'). Proposal: stop, hibernating locally where it can.
5. **Whether to build phase 5 at all**, or stop at a single control host with streamed state and a standby.

---

## 7. Sources

wicket: `crates/wicket-cli/src/{reconcile,noderun,nodesrv,run,hibernate}.rs`, `crates/wicket-proxy/src/{llm,gateway,vault}.rs`,
`crates/wicket-feed/src/lib.rs`, `crates/wicket-cli/src/serve/mod.rs`, at the merge of #150.

Prior art (read 2026-11-12):
- Nomad: https://developer.hashicorp.com/nomad/docs/concepts/architecture ·
  https://developer.hashicorp.com/nomad/docs/configuration/server ·
  https://developer.hashicorp.com/nomad/docs/job-specification/disconnect
- Consul: https://developer.hashicorp.com/consul/docs/concept/consensus ·
  https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl ·
  https://developer.hashicorp.com/consul/api-docs/features/caching
- Kubernetes: https://etcd.io/docs/v3.5/faq/ · https://kubernetes.io/docs/tasks/debug/debug-cluster/ ·
  https://kubernetes.io/docs/concepts/workloads/pods/static-pods/ ·
  https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/ ·
  https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ ·
  https://kubernetes.io/docs/tasks/tls/certificate-rotation/
- Vault: https://developer.hashicorp.com/vault/docs/concepts/ha ·
  https://developer.hashicorp.com/vault/docs/internals/integrated-storage ·
  https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/caching
- Boundary: https://developer.hashicorp.com/boundary/docs/configuration/controller ; source
  `internal/daemon/worker/session_info.go`, `internal/server/repository.go` (hashicorp/boundary main)
- Teleport: https://goteleport.com/docs/reference/deployment/backends/ ·
  https://goteleport.com/docs/reference/architecture/session-recording/ ·
  https://goteleport.com/docs/reference/deployment/scaling/ ·
  https://goteleport.com/docs/identity-governance/locking/
- SPIRE: https://spiffe.io/docs/latest/deploying/spire_server/ ·
  https://spiffe.io/docs/latest/deploying/spire_agent/ · https://spiffe.io/docs/latest/planning/scaling_spire/
- Tailscale: https://tailscale.com/kb/1091/what-happens-if-the-coordination-server-is-down ·
  https://tailscale.com/kb/1508/control-data-planes · https://tailscale.com/blog/making-tailscale-faster ·
  https://tailscale.com/kb/1028/key-expiry
- Cloudflare: https://blog.cloudflare.com/post-mortem-on-cloudflare-control-plane-and-analytics-outage/ ·
  https://blog.cloudflare.com/cloudflare-service-outage-june-12-2025/ ·
  https://blog.cloudflare.com/18-november-2025-outage/ ·
  https://developers.cloudflare.com/cloudflare-one/identity/users/session-management/
- FROST: https://www.rfc-editor.org/rfc/rfc9591.html · https://github.com/ZcashFoundation/frost
- openraft: https://github.com/databendlabs/openraft · rqlite: https://rqlite.io/docs/faq/
- LiteFS: https://docs.fly.io/litefs · Litestream: https://github.com/benbjohnson/litestream/releases/tag/v0.5.0 ·
  https://fly.io/blog/litestream-revamped/
- HPKE: RFC 9180. Demarcation protocol: Barbara and Garcia-Molina, "The Demarcation Protocol: A Technique for
  Maintaining Constraints in Distributed Database Systems", VLDB Journal 1994 [M].
- Anthropic: https://code.claude.com/docs/en/legal-and-compliance

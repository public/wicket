# Concepts

This page explains the concepts behind what wicket builds (0.0.1, and 0.0.2 as it lands) and how they
fit together. The [tutorials](../tutorials/first-box.md) show them at work, and the
[reference](../README.md#reference) has every command and field. [design.md](design.md) has the design
and the reasons for it, and lists what is [deferred](design.md#22-deferred).
[Security model](security-model.md) and [limits](limits.md) say what wicket protects and what it doesn't.

## The nouns

One word for each thing, used the same way in the CLI's help, the docs and wicket's messages
(`ci/check-terms.sh` checks the commonest slips).

- A **principal** is anyone who acts: a human, an agent, a program or a node. Each has an identity,
  an authority, and audited, signed actions.
- An **operator** is a human principal of an installation: someone who runs `wicket` on the control
  host or signs in to the console, and decides requests within the authority `operators.yaml` gives
  them ([configuration](../reference/configuration.md#operatorsyaml)).
- A **workload** is what runs in a box: an **agent**, or a **program**, which is an agent with no
  model that may not ask for more.
- A **box** is the isolated environment one workload runs in: a container with no network, a
  read-only root and no secrets ([the box](#the-box-and-the-control-host), [box reference](../reference/box.md)).
  Say "box", not "sandbox" or "container": **sandbox** names only the gVisor layer under it, and
  **container** only the runtime object a box is made of.
- A **harness** is the agent program a box runs and how wicket talks to it: Claude Code or an ACP
  agent (`agent.harness`). The harness decides when its run is done.
- A **node** is a machine that runs boxes and decides their requests ([nodes](../reference/nodes.md)).
  A machine leased from a provider (`wicket node create`) and one you already had (`wicket node
  enrol`) are both nodes, and `wicket node list` lists both. Don't say "placement" for a node:
  placement is the interface that gets one.
- The **control host** is the machine wicket's state lives on: the node that also runs the control
  plane. The **control plane** is the role, not the machine: the ledger, the vault, the keys,
  approvals and the feed ([#197](https://github.com/public/wicket/issues/197) would let it run
  elsewhere).
- A **host** is a machine. A **host name** is a name in HTTP: what a zone's `reach`, `forbid` and
  `inject` match ([manifest](../reference/manifest.md#reach)).
- A **request** is what a box asks for that its zone doesn't already allow: reach, a child zone, a
  link, capacity or an update. **Escalation** is the act of asking, not a thing of its own (the
  zone's `escalation` field says who may). A request is **pending** until it is decided, by a grant
  or a denial; its id is `r-…` ([grants](#grants), [the 403 a box sees](../reference/protocol.md)).
- A **grant** is authority one principal gives another, within its own: a resource, a principal, a
  lifetime, and an amount or a number of uses. Every approval is a grant, and so is a box's own
  authority.
- **Standing reach** is the feature by which an agent asks once for a reach rule for its later
  runs, and a human approves it once ([#572](https://github.com/public/wicket/issues/572)). The agent
  asks with `request_access` and `scope: standing`
  ([`request_access`](../reference/mcp-tools.md#request_access)):
  - a **standing request** is one such ask while it is pending (`s-…`): the rule, the agent's reason,
    and the ledger's evidence (the blocked requests it covers, from the last 14 days). An operator
    decides it once, in the console or with `wicket standing approve` or `deny`;
  - a **standing rule** is an approved one: the reach rule (as asked, or narrowed to the evidence),
    for the agent that asked or for every agent of its zone, lasting 30 days by default until
    renewed or revoked. Each later run takes it up when it starts, as a block of its token, and its
    node decides requests by it, within the zone's ceiling and the org layer.

  Say "standing request" and "standing rule", not "standing ask". A standing rule is not a
  **standing grant**: that is a grant which lasts beyond one run, as a release key's
  ([updates](updates.md)) or a [capacity grant](../reference/console.md#capacity-grants) does.
- A **lease** is a grant of capacity: a node for a time, its worst-case cost reserved
  ([placement and leases](#placement-and-leases)). Nothing else is a lease, and "lease" is the only word for a node's rented time: a long-lived agent's
  holder has a **claim** on it, and a node has a budget slice.
- A **quota grant** is a grant of an amount, not of reach: a run's model budget and box slots, a
  lease's or a created node's money, or the installation's money limit (`QUOTA wicket.internal/quota/…`,
  `wicket grant list`). A child's are carved from its parent's ([#256](https://github.com/public/wicket/issues/256), [agents](../reference/agents.md#agent-identity-and-child-agents)).
- A **budget slice** is the part of a run's model budget the control host sends to the node the run
  is on, a quarter at a time by default, so the node can decide model calls while it is cut off. The
  node spends what is left of it and nothing more ([nodes](../reference/nodes.md#wicket-node-serve-boxes-that-outlive-the-control-channel)).
- A **delegation** is the task a parent agent gives a child agent it spawns (`d-…`). Its task is the
  first **brief**, and `continue_child` gives it another; the child's result on each brief comes back
  as its **report**, a message of kind `report`. A brief and a report are messages: they grant
  nothing. `spawn` returns the child's **handle**: its principal, delegation, run and name
  ([delegation](../reference/mcp-tools.md#delegation)).
- A **receipt** is what became of a message, for its sender only: delivered, read, held, refused or
  expired ([receipts](../reference/mcp-tools.md#receipts)).
- A **device** is a browser an operator registered for push notifications of waiting requests; adding
  one is a signed action ([notifications](../reference/console.md#notifications)).
- A **run** is one box running one workload, from start to end, with its own id (`run_…`). For a
  long-lived agent (`agt_…`), each run is one **activation** of it: starting and every wake begin a
  new one. Its **generation** counts those activations; a stale one is refused
  ([hibernate and generations](#hibernate-and-generations)).
- A **session** is always qualified, because the word names four things:
  - a **harness session**, the harness's own conversation, which a wake resumes;
  - a **Remote Control session**, that conversation registered with the vendor's apps
    ([drive a box from the Claude apps](../how-to/drive-a-box-from-the-claude-apps.md));
  - a **console session**, an operator signed in to the console with a passkey
    ([console](../reference/console.md#passkeys));
  - an **ACP session**, an ACP agent's `session/new` ([ACP agents](../reference/agents.md#acp-agents)).

  A **session page** is the console's live page for one running ACP agent's ACP session
  (`/session?run=…`), where an operator reads it, prompts it and decides its requests
  ([console](../reference/console.md#sessions)).

## The box and the control host

wicket is a meta-harness: it runs no agent loop of its own. It builds the environment an agent runs in
(Claude Code first), and decides everything the agent tries to do outside it.

- **The box** is a gVisor container with no network (`--network none`), a read-only root and no
  capabilities. Everything inside it, including the agent and its own settings, is treated as hostile.
  The box holds no secrets, only placeholders.
- **The control host** is the node that also runs the control plane: the ledger (SQLite), the vault,
  the keys, approvals and the feed. Per run there are three proxies
  the box reaches over bind-mounted unix sockets:
  - the **LLM proxy** swaps the placeholder for the Claude subscription token and enforces the model
    budget;
  - the **egress proxy** terminates TLS with its node's CA (the installation root signs it), decides
    each HTTP request (HTTP/1.1, and HTTP/3 through wicket's DNS and QUIC relay), and injects
    credentials into one declared header;
  - the **MCP gateway** is the agent's only MCP server, with wicket's own tools (`await_grant`,
    `request_access`, `spawn`, `send_message`, `expose`, `connect`, `request_capacity`, …).
- Inside the box, wicket is at `wicket.internal` (198.18.0.1). The box's resolver is wicket too, so a
  DNS lookup can't carry data out.

## Zones and the subset rule

A **zone** is the boundary a box runs in. It is declared in the manifest:

- **reach:** the host names, methods and paths requests may go to without asking;
- **forbid:** hosts or paths refused outright, with no request and no grant (forbid paths match ignoring
  ASCII case, since many upstreams fold it; request paths with another spelling of a path, such as
  `%64` for `d`, a `;` parameter or a dot segment, are refused before any decision);
- **`unlisted_hosts`:** what happens to a host name the zone doesn't name (`escalate`, or `hide` to make it
  look like it doesn't exist);
- **inject:** credentials added to requests for a host, from the vault (only ever over HTTPS: plain HTTP
  to a host with a credential is refused with a 403);
- **llm:** the model budget (requests, input and output tokens). Each call reserves its `max_tokens` up
  front (lowered to what is left if it asks for more), and is charged what its final usage reports. A
  call is read to its end even if the agent hangs up, and one whose final usage never arrives is charged
  its whole reservation. Model requests are vetted too: only `POST /v1/messages` and
  `/v1/messages/count_tokens` take a body, which must be uncompressed JSON; only known request fields and
  client tools (custom, bash, text editor, memory, computer use) are forwarded, and URL sources in content
  blocks are refused, since server tools, URL sources, the MCP connector and containers make the provider
  reach hosts the zone never allowed (`llm.allow_server_tools` lets them through). The call's `[llm]` line
  and its `op` audit record name what was stripped (field names and tool types, never their values). A wrapped Claude Code session's model calls, which reach the model host through the
  egress proxy, get the same budget, checks and accounting there;
- **limits, isolation, images, volumes:** memory, CPUs and time; how much of the box's output its
  node's host and the control host's transcript keep (`limits.output`, default `64m` of each, the newest
  kept; `on_output_full: stop` stops the box instead); the isolation tier; the images the zone's boxes may start from besides the installation's agent image
  (`agent.image` and a child's image); named directories that persist between
  runs;
- **accept_from:** the zones whose agents may message this one.

Every request from the box is decided one of three ways: allowed by reach, forbidden, or **needs a
grant**. A request that needs a grant becomes a pending request. The agent gets a 403 with a request id,
can wait with `await_grant`, and an operator approves or denies it in the console or with `wicket approve`. A
grant is bound to the exact request, single-use and expiring by default, and kept in the ledger.

Whatever the zone says, some destinations are **never reachable**: cloud metadata endpoints, `localhost`
and every non-public address (private, loopback, link-local, CGNAT, multicast, reserved, and IPv6 forms
that carry an IPv4 address, such as NAT64 and 6to4). A host is parsed as a URL parser would, so
`2852039166` or `0xa9fea9fe` is 169.254.169.254, and IP addresses aren't proxied at all. wicket resolves
every upstream name itself and connects only to addresses it has checked; a name with any non-public
address is refused, and the checked address is the one dialled, so DNS rebinding can't move a connection.
The model proxy dials its zone's model route the same way; a route the zone names by address (a local
model on `127.0.0.1`, say) is the operator's choice, and is dialled as named.

A request goes upstream as it was decided. Only allow-listed request headers are forwarded (content
negotiation, caching, conditional requests, the body's type and encoding, `git-protocol`, and a
provider's own, such as `x-github-api-version` to GitHub's API), and wicket adds the credential itself.
Requests that could run as something else are refused: methods other than GET, HEAD, POST, PUT, PATCH,
DELETE and OPTIONS (so TRACE, and CONNECT inside a tunnel), method-override and URL-rewrite headers
(`X-HTTP-Method-Override`, `X-Original-URL` and the like), and bodies on GET and HEAD.

**The subset rule.** An agent with `max_children` can `spawn` a workload (an agent or a program) in a
zone it writes.
That zone must be within the agent's own (`wicket_core::subset`):

- reach covered rule by rule (host, method and path), and every parent `forbid` kept;
- only the parent's own credentials and model route;
- a model budget carved out of what the parent has left;
- memory, CPUs, PIDs and time at least 1 and no larger than the parent's, isolation no weaker, and images
  from the parent's list;
- `max_children` within the parent's: a child's own `max_children` counts against the parent's.

A zone that isn't within it is refused, with every violation listed. With `escalate`, it goes to an
operator as exactly that zone, on an R4 card that lists what the child gets (its model route, credential
injections, reach and limits). A different model route or credential is refused outright, with no
approval path. Globs whose containment can't be proven (a character class under `*`, for example) are
refused, so the check errs on the side of refusing. A spawned zone is named `<parent zone>.<name>.<parent
run>`, so no other run can create the same zone.

A grant belongs to the run that asked for it, and ends with it; `wicket approve --zone-wide` lets any run in
the zone use it until it expires. `wicket approve` prints the request as wicket recorded it, and at a
terminal asks before approving (`--yes` skips the question).

## Grants

A grant answers one pending request, and is kept in the ledger. An operator decides with `wicket approve`
or in the console. An ancestor agent may decide a descendant's request with the gateway's `decide`
tool, but only within its own authority, if its zone has `escalation.grant` (on by default). Either way
it goes through one decide function:

- **Bound to the request.** It covers the method, host and path asked (or, with `--prefix` or a
  `request_access` prefix ask, every path under a prefix, in whole segments), and nothing riskier than
  the request shown ([risk classes](../reference/risk-classes.md)).
- **Small by default.** One use, ten minutes, for the run that asked (`wicket approve --uses`,
  `--unlimited`, `--ttl` up to 24 h, `--zone-wide`). It ends with the run, and lapses if the run's
  identity is revoked first.
- **Recorded before it exists.** The approval's audit record is committed before the grant is
  usable; a console approval carries the passkey's signature over exactly that decision.
- **Revocable.** `wicket grant revoke` ends it, on the control host at once and on a node within
  250 ms of its push.
- **Renewable, never unlimited.** `wicket grant renew <id> --ttl` gives a live grant a new end,
  up to 24 h from now, as a new decision on the audit record ([#56](https://github.com/public/wicket/issues/56)).
  An agent may renew what it could grant (the `decide` tool). A running box's authority is
  renewed the same way, by its run id: its token is minted again with the later end, up to its
  run's `timeout`, and its node keeps it past the old one. A box nobody renews stops when its
  authority ends.

wicket's own approvals are grants too, and stay with operators: a child zone beyond its parent's
(`SPAWN`), a link beyond the default policy (`LINK`), a lease (`CAPACITY`), and an agent's build
(`UPDATE`). A lease is a grant of capacity: see [placement and leases](#placement-and-leases). An
operator may also give a principal a standing **capacity grant** from the console: plans, regions,
hourly and daily money and nodes at once, for at most 24 h, renewable and revocable. A `wicket node
create` it covers is approved at once, through the same decide function, and audited against it
([capacity grants](../reference/console.md#capacity-grants)). A zone
with `escalation: { request: false }` may not ask at all, and anything outside its reach is "never
allowed".

## Identities: agents and nodes

- **Agents.** Every box gets an identity from the installation's issuer:
  `spiffe://<trust domain>/t/<tenant>/z/<zone>/a/<agent>`, an EdDSA-signed document whose key wicket
  holds, never the box. Identities last 10 minutes and are re-issued every 5 with a fresh key. Each
  names who it acts for, back to the operator (`acting for: alice (cli, unix-user) → lead → fetcher`). The
  trust domain is set once per installation (`wicket identity init`).
- **What identity is for.** Messages between agents go through wicket, which sets and signs the sender.
  Approvals show the requesting agent's verified identity, and the console won't approve for one that
  doesn't verify. `wicket identity revoke` stops a box and everything it started.
- **Nodes.** An enrolled node has its own Ed25519 key, generated on the node, and a 24-hour identity
  certificate (`spiffe://<trust domain>/node/<name>`). Every control connection starts with a mutual
  handshake: the node proves its key, the control host proves the issuer's. The node also has a
  short-lived node CA, name-constrained to the hosts it may serve.

## Authority: Biscuit tokens and the feed

On the control host, the proxies decide from the zone (compiled once per run) and the ledger's grants.
On a served node, each box's authority is a **Biscuit token**:

- block 0 is the box's zone ceiling, minted by the control host when the run starts;
- third-party blocks, signed by the approver key, add the grants approved for it (at most 10 live per
  box).

A Biscuit block can only add checks, so a token can only narrow. Revoking a block's id revokes every
token that contains it.

A child's token is built one of two ways, depending on who decides its spawn:

- **On the parent's node** (#164): a spawn within the parent's authority, placed on the same node, is
  decided there from the parent's token. The child's token is the parent's base token plus a
  **spawn block** with the child's ceiling (`Replica::derive_child`), so it is never wider or longer-lived
  than the parent's, and revoking any of the parent's blocks revokes it too. The node reports the child;
  the control host checks it again (`subset::check`, the org policy, slots) and adopts it as a run of its
  own, from then on with its own block 0.
- **On the control host**: everything else (a placement elsewhere, a zone beyond the parent's that an
  operator approves, a parent whose authority was renewed, an org policy that decides differently a
  level down, an ACP agent's children). The control host runs `subset::check` and mints the child a
  fresh **block 0** from its zone, as for any run. Revoking the parent's block doesn't by itself revoke
  that child; revoking the parent's run does.

wicket checks tokens with a vendored, patched `biscuit-auth` (see
[limits](limits.md#authority-and-the-biscuit-fork)). It runs a structural check before loading, and uses a step budget instead of a wall-clock
limit, so a decision doesn't depend on load.

### Deciding at the edge

A request is decided where the box runs, not on the control host. On the control host's own node and
on remote nodes alike, the node's egress proxy decides from what it already holds: the box's token,
its grants, the secrets it fetched and a slice of the model budget. The control host issues
authority, takes approvals, and reconciles counts and audit afterwards; it isn't asked during a
request. That keeps the request path short, and it means a node that loses the control host keeps
working, narrowly, instead of failing open or stopping everything. Each piece of authority it holds
has its own lifetime, so working alone ends on its own ([lifetimes](../reference/nodes.md)).

### The signed feed

The control host sends these tokens to each node in a **signed policy feed**. The feed has snapshots,
hash-chained deltas and freshness statements, all signed by a per-node feed key that the feed root
certifies. The node decides from its verified replica of the feed:

| mode | when | allowed |
|---|---|---|
| **fresh** | a freshness statement within its TTL (30 s) | the box's token and its live grants; anything else raises a pending request on the control host |
| **offline** | no live statement: the control host is unreachable | the same, each until its own expiry; anything else is queued on the node and raised when the control host is back |
| **lagging** | a live statement names deltas the node hasn't got yet | nothing, until they arrive |
| **closed** | no verified state, or the feed key's certificate has expired | nothing |

So a box on a node keeps working while the control host is unreachable, for exactly as long as its
grants last: every grant has a lifetime, the box's own authority (its token's block 0, the zone's
`limits.authority`, by default the run's timeout) included, and the node stops the box when that ends.
The node also keeps, in memory only, the secrets its runs have used (their model credential and
injected secrets, fetched on first use) and a slice of each run's model budget, so model calls go on
too ([nodes.md](../reference/nodes.md)). Revocations are pushed to the
node: a grant revoke is picked up within 250 ms and a run revocation within 2 s. A node that hears nothing
keeps what it holds until it expires. Tampered, replayed and rolled-back frames are refused.

## Links

Boxes have no network, so they reach each other's ports only through **links**, which wicket relays:

- `expose(port)` offers a port;
- `connect(box, port)` returns `<name>.wicket.internal:<port>` in the caller's box;
- `link(from, to, port)` wires two boxes the caller controls.

A box's own children can be connected to without `expose`. Anyone else needs the target's `expose` and
its zone's `accept_from`, or an operator. Connecting carries authority, so the target's reach must be within
the connector's, or an operator approves. Every link is recorded and audited. It closes when it is cut
(`unlink`), when either end or an ancestor is revoked, or when either run ends.

## Placement and leases

- **Placement** (`wicket-placement`) gets nodes from a backend: the operator's own static hosts, or
  Vultr. Every node carries the installation's owner tag; nothing without it, or tagged
  `wicket-protected`, is ever listed or destroyed. Spending stays inside `placement.yaml`'s hourly and total limits,
  one budget for leases and created nodes alike, checked against the ledger's money quota grants
  (#256), and each paid create is confirmed. An operator leases a node by hand with `wicket node create` and
  ends it with `wicket node release`.
- **A lease**, a grant of capacity, is how an agent gets a machine without holding a cloud credential. The agent asks with
  `request_capacity`. The ask becomes a pending lease with its worst-case cost reserved against
  `placement.yaml`'s budget, and only an operator approves it. The approval is bound to that lease. The
  agent then places children on it with `spawn` and `placement: {"lease": "l-…"}`.
- **The reconciler** (`wicket reconcile`, or `--every 30s` as a service) makes the world match the
  ledger. It ends runs whose process died, ends leases at their end or when their holder ends, destroys
  owned machines no live lease needs (on Vultr, before the next paid hour), adopts machines after a
  crash, and stops orphaned boxes.

## Hibernate and generations

Every Claude Code agent wicket launches on the control host is **long-lived**: an id (`agt_…`), its own
harness session, and a **generation** number. Each run is one activation of it.

- **Active:** the box runs, during a turn and between turns. wicket never ends, pauses or hibernates
  it on a turn boundary (#249): the agent's harness decides, and the run ends when it exits, at its
  timeout, or when its authority ends. The agent ends its harness session with wicket's `finish` tool.
- **Active → Hibernated:** when the agent asks (`hibernate` tool) or on `wicket hibernate`, at the end
  of its turn. Anything else still running in the box (a build, a dev server) gets the zone's
  `limits.exit_grace` to end, then is stopped (#293). The box stops, and its whole writable state is bundled into
  wicket's object store: the workspace, `$HOME` and the agent's config, `/tmp`, and `persist: durable`
  volumes. Files only: no process or memory survives hibernation.
- **Wake:** opening its session (`wicket session`, or a prompt in the console), or a message from another agent, rebuilds the box with a new
  identity, restores the state, and resumes the harness session at the same path.

A wake is a compare-and-set claim that bumps the generation, so of two concurrent wakes exactly one wins.
The proxies, wicket's DNS and the state push all refuse a stale generation, so a box woken twice can't
act or split the agent's state. Budgets belong to the agent over its whole life: a wake continues from
what is left, and a spent agent isn't woken.

## Audit and export

- Every decision, approval, identity, message, link, lease and reconcile action is a record in a
  **hash-chained audit log** in the ledger. Nodes keep their own chain and ship it on every connect.
- `wicket audit --verify` checks offline: the chain, every identity ever issued, every message signature,
  every passkey-signed console action, and each node's chain.
- Records are written in group commits off the request path. A record an action depends on, such as a
  grant use or an approval, is committed before the action happens; if it can't be, the action fails.
- **Export** sends the records to JSON lines files or OTLP collectors, with signed chain-head checkpoints.
  `wicket audit --verify --against FILE` checks the ledger against what was exported
  ([audit-export.md](../reference/audit.md)).

## Designed, not built

These are in [design.md](design.md) but not built: provider adapters and adapter-generated MCP tools,
platform (multi-tenant) mode, other harnesses (Codex, pi), microVM isolation, memory restore on wake
(gVisor checkpoint, [#365](https://github.com/public/wicket/issues/365)), warm boxes, memory promotion
and garbage collection. Labels and handles, service zones, crews, mandates, Kubernetes placement, other
clouds and the LLM manifest proposer are [deferred](design.md#22-deferred).

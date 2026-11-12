# wicket — core concepts (0.0.1)

This page explains the concepts behind what wicket 0.0.1 builds and how they fit together. The README
shows the commands. [design.md](design.md) has the full design, much of which is not built yet; the
Claude Doc "wicket — core concepts" (https://claude.ai/artifact/AATnju2Q7j6j2TvpCJ8XuP) gives that
design-level overview. [limits.md](limits.md) lists what 0.0.1 doesn't protect.

## The box and the control host

wicket is a meta-harness: it runs no agent loop of its own. It builds the environment an agent runs in
(Claude Code first), and decides everything the agent tries to do outside it.

- **The box** is a gVisor container with no network (`--network none`), a read-only root and no
  capabilities. Everything inside it, including the agent and its own settings, is treated as hostile.
  The box holds no secrets, only placeholders.
- **The control host** runs `wicket`: the ledger (SQLite), the vault, the keys, and per run three proxies
  the box reaches over bind-mounted unix sockets:
  - the **LLM proxy** swaps the placeholder for the Claude subscription token and enforces the model
    budget;
  - the **egress proxy** terminates TLS with a per-run CA, decides each HTTP request (HTTP/1.1, and
    HTTP/3 through wicket's DNS and QUIC relay), and injects credentials into one declared header;
  - the **MCP gateway** is the agent's only MCP server, with wicket's own tools (`await_grant`,
    `request_access`, `spawn`, `send_message`, `expose`, `connect`, `request_capacity`, …).
- Inside the box, wicket is at `wicket.internal` (198.18.0.1). The box's resolver is wicket too, so a
  DNS lookup can't carry data out.

## Zones and the subset rule

A **zone** is the boundary a box runs in. It is declared in the manifest:

- **reach:** the hosts, methods and paths requests may go to without asking;
- **forbid:** hosts or paths refused outright, with no request and no grant;
- **`unlisted_hosts`:** what happens to a host the zone doesn't name (`escalate`, or `hide` to make it
  look like it doesn't exist);
- **inject:** credentials added to requests for a host, from the vault;
- **llm:** the model budget (requests, input and output tokens);
- **limits, isolation, images, volumes:** memory, CPUs and time; the isolation tier; the images a child
  may use; named directories that persist between runs;
- **accept_from:** the zones whose agents may message this one.

Every request from the box is decided one of three ways: allowed by reach, forbidden, or **needs a
grant**. A request that needs a grant becomes a pending request. The agent gets a 403 with a request id,
can wait with `await_grant`, and a human approves or denies it in the console or with `wicket approve`. A
grant is bound to the exact request, single-use and expiring by default, and kept in the ledger.

**The subset rule.** An agent with `max_children` can `spawn` an agent or a program in a zone it writes.
That zone must be within the agent's own (`wicket_core::subset`):

- reach covered rule by rule (host, method and path), and every parent `forbid` kept;
- only the parent's own credentials;
- a model budget carved out of what the parent has left;
- memory, CPUs, PIDs and time no larger, isolation no weaker, and images from the parent's list.

A zone that isn't within it is refused, with every violation listed. With `ask_human`, it goes to a
human as exactly that zone. Globs whose containment can't be proven are refused, so the check errs on the
side of refusing.

## Identities: agents and nodes

- **Agents.** Every box gets an identity from the installation's issuer:
  `spiffe://<trust domain>/t/<tenant>/z/<zone>/a/<agent>`, an EdDSA-signed document whose key wicket
  holds, never the box. Identities last 10 minutes and are re-issued every 5 with a fresh key. Each
  names who it acts for, back to the human (`acting for: alice (cli, unix-user) → lead → fetcher`). The
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
- third-party blocks, signed by the approver key, add the grants humans approved (at most 10 live per
  box).

A Biscuit block can only add checks, so a token can only narrow. Revoking a block's id revokes every
token that contains it. The library also builds spawn blocks, which narrow a parent's token for its
children so that revoking a parent's block revokes the whole subtree. In 0.0.1 that is tested at library
level only: a child run on a node gets its own block 0 from its zone, which `spawn` has already checked
is a subset of its parent's. wicket checks tokens with a vendored, patched `biscuit-auth` (see
limits.md). It runs a structural check before loading, and uses a step budget instead of a wall-clock
limit, so a decision doesn't depend on load.

The control host sends these tokens to each node in a **signed policy feed**. The feed has snapshots,
hash-chained deltas and freshness statements, all signed by a per-node feed key that the feed root
certifies. The node decides from its verified replica of the feed, in one of three modes:

| mode | when | allowed |
|---|---|---|
| **fresh** | a freshness statement within its TTL (30 s) | reach rules and live grants; anything else raises a pending request on the control host |
| **narrow** | up to the narrow window after that (120 s) | plain reads in reach only |
| **closed** | after that | nothing |

So a box on a node keeps working, failing narrow, while the control host is unreachable. Revocations
are pushed to the node: a grant revoke is picked up within 250 ms and a run revocation within 2 s. A node
that hears nothing goes stale within the TTL anyway. Tampered, replayed and rolled-back frames are refused.

## Links

Boxes have no network, so they reach each other's ports only through **links**, which wicket relays:

- `expose(port)` offers a port;
- `connect(box, port)` returns `<name>.wicket.internal:<port>` in the caller's box;
- `link(from, to, port)` wires two boxes the caller controls.

A box's own children can be connected to without `expose`. Anyone else needs the target's `expose` and
its zone's `accept_from`, or a human. Connecting carries authority, so the target's reach must be within
the connector's, or a human approves. Every link is recorded and audited. It closes when it is cut
(`unlink`), when either end or an ancestor is revoked, or when either run ends.

## Placement and leases

- **Placement** (`wicket-placement`) gets nodes from a backend: the operator's own static hosts, or
  Vultr. Every node carries the installation's owner tag; nothing without it, or tagged
  `wicket-protected`, is ever listed or destroyed. Spending stays inside an hourly and a total envelope,
  and each paid create is confirmed.
- **A lease** is how an agent gets a machine without holding a cloud credential. The agent asks with
  `request_capacity`. The ask becomes a pending lease with its worst-case cost reserved against
  `placement.yaml`'s budget, and only a human approves it. The approval is bound to that lease. The
  agent then places children on it with `spawn` and `placement: {"lease": "l-…"}`.
- **The reconciler** (`wicket reconcile`, or `--every 30s` as a service) makes the world match the
  ledger. It ends runs whose process died, ends leases at their end or when their holder ends, destroys
  owned machines no live lease needs (on Vultr, before the next paid hour), adopts machines after a
  crash, and stops orphaned boxes.

## Hibernate and generations

Every Claude Code agent wicket launches on the control host is **long-lived**: an id (`agt_…`), its own
session, and a **generation** number. Each run is one activation of it.

- **Active → Idle:** after a turn and `idle_timeout`, the box is paused (`docker pause`), keeping its
  processes and memory.
- **Idle → Hibernated:** at `hibernate_after`, or on `wicket hibernate`, if the box is at a quiet point
  (turn ended, nothing else running). The box stops, and its whole writable state is bundled into
  wicket's object store: the workspace, `$HOME` and the agent's config, `/tmp`, and `persist: durable`
  volumes.
- **Wake:** `wicket wake`, `wicket say`, or a message from another agent rebuilds the box with a new
  identity, restores the state, and resumes the session at the same path.

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
  ([audit-export.md](audit-export.md)).

## Designed, not built

These are in [design.md](design.md) but not in 0.0.1: labels and handles, typed gates between zones,
provider adapters and adapter-generated MCP tools, isolated third-party MCP servers, Cedar policy,
platform (multi-tenant) mode, mandates, other inner agents (Codex, pi), microVM isolation, memory
promotion and garbage collection.

# Security model

What wicket protects, from whom, and what it trusts to do so. [Limits](limits.md) lists, item by
item, what 0.0.1 doesn't protect; this page is the frame those items fit in.

## The threat

wicket assumes the agent may be compromised: by a prompt injection in something it read, a
malicious dependency, or its own mistakes. Everything inside the box is treated as hostile,
including the agent's own settings and any subagents it runs there. The goals are that such an agent:

- can't get a credential: the box holds none, only placeholders;
- can't reach anything outside its zone without a human deciding it, and never reaches what the zone
  forbids, metadata endpoints or non-public addresses;
- can't approve its own requests, or forge who asked;
- can't spend more than its budget, or start boxes with more authority than its own;
- leaves a record of everything it did that can be checked offline.

## The boundaries

| boundary | what enforces it |
|---|---|
| box ↔ host | gVisor, no network, a read-only root, no capabilities ([why gVisor](why-gvisor.md)) |
| box ↔ the world | the egress proxy, the model proxy and the gateway: every request decided against the zone, credentials added outside the box |
| box ↔ box | separate boxes and identities; ports only through audited links |
| agent ↔ human | approvals by root on the host, or by a passkey in the console signing exactly that decision |
| operator ↔ operator | `wicketd`, which names each caller from the kernel and allows commands by class ([daemon](../reference/daemon.md)) |
| control host ↔ node | the pinned ssh host key, a mutual handshake, a signed feed the node verifies, and authority that expires on its own |

## What is trusted

- **The control host, and root on it.** It holds the ledger, the vault and the keys. Root can mint
  any identity or grant with the keys that stay there, and rewrite the audit chain; export with signed
  checkpoints to catch the latter ([export audit](../how-to/export-audit.md)). The roots that sign
  boxes' authority and the feed can be moved offline.
- **Docker.** Whoever can talk to Docker is root on the host; on an installed host only the `wicket`
  user can.
- **Each node, for the boxes it serves.** A node terminates their TLS and holds, in memory, the
  secrets their runs use. Its name constraints and short certificate lifetimes bound what a stolen
  node can do, and for how long.
- **The human who approves.** wicket shows exactly what a grant covers, the requester's verified
  identity and on whose behalf it acts; it can't judge whether the request is wise.
- **Development mode trusts the whole user account.** Without the daemon, anything running as you can
  approve, read the vault and claim another principal.

## The main limits

- wicket decides **where** a request goes, not **what it carries**: anything a zone can reach is a way
  out for whatever the agent has read. There is no taint tracking yet. Keep reach narrow, and write
  access away from untrusted reads.
- Risk is judged from method, host and path, with a short pattern list for GitHub only.
- The Biscuit fork nodes decide with has had no external audit.

Everything else is in [limits](limits.md), with the design section or issue for each. The 0.0.1
security review is [security-review-0.0.1](security-review-0.0.1.md).

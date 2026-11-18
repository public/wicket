---
area: Operations and audit
type: Added
---
- Kani now checks three more decisions in `wicket-core`
  ([#325](https://github.com/public/wicket/issues/325)):
  - **The SSRF guard (`is_public_ip`):** for every IPv4 and every IPv6 address, an address is
    public exactly when none of the never-public blocks holds it. Those blocks are written as a
    separate table of prefixes: private, loopback, link-local and cloud metadata, CGNAT,
    documentation, multicast, reserved, and every IPv6 form that carries an IPv4 address.
  - **A push's grant (`git::grant_terms`, `is_push`):** a grant never lasts longer than the
    approver picked. A grant that isn't for a push is made exactly as picked. A push's grant is
    uncounted only for its window of at most 5 minutes.
  - **A grant's end in a node's token (`quota::not_after_for`, #342):** the token and the ledger
    end a grant at the same millisecond, for every end and every clock reading. `wicket-authz`'s
    `Grant::not_after_for` and the node's request time now call these functions.

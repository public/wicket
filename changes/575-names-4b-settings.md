---
area: Identity, spawn and links
type: Added
---
- Public names ([#575](https://github.com/public/wicket/issues/575), step 4b, first part):
  - `wicket.yaml` has a `names:` section: the internal-name limit, and for public names the
    provider (`noop` for now), the boxes zone, the owner id, the TTL, the per-workload limit (1 by
    default), reserved labels, the console's host name (its first label is reserved too), the node
    labels and the host port range. It is checked when a run starts.
  - Without `names.public`, asks for public names are refused. An ask beyond the per-workload limit
    is refused too.
  - A human's approval is decided under the settings as they are then: the boxes domain is part of
    the effect approved, a label reserved since the ask isn't approved, and the limit holds.
    `wicket names show` and `approve` show the full name.
  - A standing name is taken up by each later run it is for when that run starts (`name.claimed`).
  - `wicket node set --public-ipv4 … --public-ipv6 …` records a node's public addresses (public
    ones only, audited `node.addresses`; ledger schema 34). `wicket node list --json` shows them.
  - `wicket pending --json` documents its `kind: "name"` objects. `wicket pending` says "no pending
    requests" only when nothing at all waits.
  - A name past its lifetime ends when names are next swept or decided (`name.lapsed`), so it holds
    neither its label nor a place in its agent's limit.
  - A public name records the boxes domain it was approved under (`names.domain`, schema 34).
  - A node's public addresses go when it is revoked or enrolled again, can be set only on an active
    node, and no two active nodes have the same one.
  - With `console_host` under the boxes zone, the label directly under the zone is reserved too.

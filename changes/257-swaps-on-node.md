---
area: Nodes
type: Changed
---
- A box's credential swaps are made on its node. These are a remote session's login and a wrapped
  session's credentials, and this is the second step of
  [#257](https://github.com/public/wicket/issues/257), one decision path. The box's start names
  each swap: its host, its placeholder, and the vault secret it uses (or, for a value the launcher
  handed wicket, a key to fetch it by). The value is never in the start or the node's box record.
  The node fetches the credential from the control host on first use, as it does injected secrets
  (#152). The control host releases it only for the swap's hosts, if the secret's binding covers
  them, and audits the release as `node.secret_fetch`. The node keeps it in memory only.
- The node then decides swapped hosts itself, from the box's token in its feed replica, and
  forwards to the control host only the hosts its CA can't cover. Grants on swapped hosts are
  handed to the node and counted there. The egress lines and audit records are the same, but the
  node writes the ones for swapped hosts: a decision reads `(node)`, a grant's
  `(counted on the node)`, and each first fetch adds a `node.secret_fetched` record to the node's
  audit log. A wrapped session's model calls, which reach the model host through egress, are
  budgeted, filtered and counted by the node's model proxy, as they were by the control host's.
- Protocol 10. A box with credential swaps starts only on a node talking protocol 10 or later. An
  older node is refused, with a message saying to update it (`wicket node install <node>`). A node
  at 10 still forwards the swapped hosts of a box that a control host at 9 started.

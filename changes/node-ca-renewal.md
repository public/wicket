---
area: Nodes
type: Fixed
---
- A node's CA is renewed over the control channel at half its life, like its identity certificate,
  instead of lapsing after 24 h unless an operator ran `wicket node renew-ca`. The node makes a new
  key, the control host signs it with the same name constraints, and the node swaps it in for every
  box, running ones included. A node that was offline through its CA's end is renewed when a run
  reconnects, before its box starts. The ledger audits `node.ca_renewed` and revokes the replaced
  CA. An expiring or expired node CA is a node health alert (in `wicket top`, the console and push),
  and a node with an expired CA refuses a box that needs it, saying why. Channel protocol 14
  ([#416](https://github.com/public/wicket/issues/416)).

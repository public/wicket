---
area: Identity, spawn and links
type: Changed
---
- One gateway, on the node ([#257](https://github.com/public/wicket/issues/257) slice 4b,
  protocol 13). The tools only the control host can answer (links, `decide`, `finish` and
  `hibernate`, operator-held requests, messages while connected, capacity and update requests,
  spawns the node doesn't start, `principals`, `receipts`, `delegations`, `continue_child`) reach
  it as typed calls over the run's channel (`Msg::Call`), answered in the run's supervisor. They
  are no longer JSON-RPC relayed through a tunnel to the run's `ctl/gateway.sock`, which is gone,
  along with the gateway tunnel target and the gateway's HTTP server. A box starts only on a node at
  protocol 13 or later; update nodes with `wicket node install`.

---
area: Development
type: Changed
---
- The control host's gateway tools (links, `decide`, `finish` and `hibernate`, messages,
  `principals`, `receipts`, delegations, capacity, update, `await_grant` and `pending_requests`)
  moved from wicket-proxy to wicket-control, next to the run supervisor that answers a node's
  typed calls. wicket-proxy's gateway keeps MCP's handshake, the tool list and a spawn's arguments,
  which the node reads. The deterministic simulation and the gateway fuzz target call the tools
  from wicket-control ([#257](https://github.com/public/wicket/issues/257)).

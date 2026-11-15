---
area: Nodes
type: Changed
---
- A box's model proxy runs only on its node (the first step of
  [#257](https://github.com/public/wicket/issues/257), one decision path). The run on the control
  host no longer listens on `ctl/llm.sock`; it keeps the run's model budget and the spend its node
  reports. Since protocol 3 (#152) a node calls the model itself with the credential it fetched, so
  nothing used that socket. A node's tunnel to `llm` is now refused. The protocol version is
  unchanged, and model call events, egress lines and audit records stay the same.
- [One decision path](../docs/explanation/one-decision-path.md) maps where the
  control host still decides per request (forwarded egress through `Central`, the relayed gateway
  tools) and the staged plan that moves each of them to the node.

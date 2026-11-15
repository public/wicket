---
area: Approvals and the console
type: Changed
---
- What a spawn carves for a child is recorded as grants: its model budget (`model.requests`,
  `model.output_tokens`, `model.input_tokens`), its box slots (`children`) and its memory (`bytes`),
  each a `QUOTA wicket.internal /quota/<resource>` grant with an amount, bound to the child, made by
  the parent agent, and lasting the child's timeout (at most 24h, renewable with `wicket grant
  renew`). They are a record: enforcement stays where it was (the model proxy's counters, the spawn
  slots and the box's limits on its node), and a quota grant never decides a request nor goes to a
  node. They are revoked with the child's other grants when it ends
  ([#256](https://github.com/public/wicket/issues/256)).
- New `wicket grant list [--all] [--tail N]` lists grants, approvals and quotas, newest first: what
  each grants, to which run, its uses or amount, when it ends, and who made it.
- An approved `request_update` is now found by the same grant lookup as every other request kind.
- "Lease" names one thing, a grant of capacity. The control/node message carrying a run's budget
  slice is now `BudgetSlice` (it was `Lease`): protocol version 9, with no alias, so a node talking 8
  is sent no slice and a box with a model budget doesn't start on it until the node is updated. The
  feed replica's `Escalation::Lease` and `Allowed::Lease` are now `GrantHold`.
- The ledger's schema goes to version 3, an expand step: `grants.amount`.

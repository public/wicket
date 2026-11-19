---
area: Development
type: Changed
---
- The control host keeps a run's model budget without a model proxy
  ([#257](https://github.com/public/wicket/issues/257)): a `Budget` (the counter and its quota)
  that merges the node's spend, carves children's budgets out and leases the node its slices. It
  used to build a whole model proxy, HTTP client included, that called no model since the box's
  node became the only one. No behaviour change.

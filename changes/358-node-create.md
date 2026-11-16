---
area: Placement
type: Changed
---
- `wicket place` is now part of `wicket node`, so nodes have one noun: `wicket node create` leases a
  machine from a provider and enrols it, `wicket node release` destroys it (by its name now, as well
  as its instance id), and `wicket node plans` lists a provider's plans. `wicket node enrol` stays,
  for machines you already have. There are no aliases
  ([#358](https://github.com/public/wicket/issues/358)).
- `wicket node list` now shows each node's lease, provider and cost, if it has a lease: a node from
  `wicket node create` (its lease end, instance and hourly price), or a run's capacity lease (its
  holder, price cap and reservation). Leased nodes that aren't enrolled are listed too. `wicket node
  list --provider` adds what `wicket place list` showed: the provider's owner-tagged instances, with
  their state, cost and next paid hour. That form reads the provider's API key, so it is privileged
  through wicketd, like `create`, `release` and `plans`.
- The how-to is now [create nodes on Vultr](../docs/how-to/create-nodes-on-vultr.md).
- The ledger's schema goes to version 7, an expand step: `placed_nodes.hourly`.

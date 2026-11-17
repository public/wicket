---
area: Development
type: Changed
---
- The control host's gateway tools (#257) are a library crate of their own, `wicket-gateway`, which
  wicket-control re-exports as `gateway`. The deterministic simulation and the gateway fuzz target
  depend on it instead of on all of wicket-control, so a change to the control host's other
  modules, to the node's or to the node channel no longer runs the simulation or that fuzz target.
  The files the simulation's stand-ins follow (a run's supervisor, `node create`, the node's run
  loop and gateway, the channel's framing, the reconciler) still select it.

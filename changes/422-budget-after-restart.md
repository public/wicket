---
area: Nodes
type: Fixed
---
- After a control-host restart, a run's model calls no longer get "Model token budget exhausted" with nothing spent ([#422](https://github.com/public/wicket/issues/422)). Two causes: a call the box gave up on before it was sent (its client timed out while the restarted node fetched the model credential) kept its output reservation for good, and now gives it back; and a re-attached supervisor sent its node budget slices in its own counts, which start at the node's first report, so the node held less than it had spent and refused every call. Slices now go out in the node's counts.

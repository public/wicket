---
area: Remote nodes and capacity
type: Fixed
---
- The reconciler stops a paused (hibernating) box whose supervisor is gone by unpausing it first,
  instead of failing its kill on every pass, and a ledger it can't read never counts as "this run's
  box can't still be running": the run is kept
  ([#676](https://github.com/public/wicket/issues/676)).

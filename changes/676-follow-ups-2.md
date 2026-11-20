---
area: Remote nodes and capacity
type: Fixed
---
- The reconciler stops a paused (hibernating) box whose supervisor is gone by unpausing it first,
  instead of failing its kill on every pass, and pauses it again if the kill then fails. A ledger
  that can't be read never counts as "this run's box can't still be running": the run is kept and
  said so, and a failed takeover is still counted towards stopping its box
  ([#676](https://github.com/public/wicket/issues/676)).

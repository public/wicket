---
area: Remote nodes and capacity
type: Fixed
---
- A run whose supervisor is gone, on a node that can't be asked, is no longer ended while its box
  may still be running there because its stored manifest no longer loads (a later version refuses
  something in it, as #674 does `**/…` globs) and its authority record is missing. Its fence's end
  is read from the stored manifest's timeout without the manifest's other checks, then from the
  ledger's record of the box's authority; with neither, the run is kept, fenced, until its node
  confirms the box stopped. A takeover (`wicket attach`) that fails on such a run no longer ends it
  either. Wake says how such a fence ends, and root can release one without the node:
  `wicket node release-fence <run> --reason …`, audited as `run.fence_released`. Run records are
  now written durably ([#676](https://github.com/public/wicket/issues/676)).

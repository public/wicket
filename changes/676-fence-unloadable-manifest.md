---
area: Remote nodes and capacity
type: Fixed
---
- A run whose supervisor is gone, on a node that can't be asked and is no longer active, is no
  longer ended while its box may still be running there just because its stored manifest no longer
  loads (a later version refuses something in it, as #674 does `**/…` globs) and its authority
  record is missing. The run's timeout is read from the stored manifest without its other checks,
  and if even that can't be read the run is kept, fenced, until its node confirms the box stopped;
  the reconciler says why ([#676](https://github.com/public/wicket/issues/676)).

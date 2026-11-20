---
area: Remote nodes and capacity
type: Fixed
---
- A run whose takeover (`wicket attach`) keeps failing while its box still runs on its node is no
  longer retried on every reconcile pass: the reconciler waits between tries (a minute, doubling,
  at most an hour), audits `run.attach_failed` only when the reason changes (and
  `run.attach_recovered` once a takeover has its box), and after five failures stops the box through
  its node, ending the run once the node reports the box exited. A box the reconciler kills counts
  as stopped only once its Docker no longer lists it: a kill that Docker or ssh refused is reported,
  and its run's fence holds. A run which this host has no record of (as on a standby restored from
  the state store) is kept while the ledger has its box authorized, on a node that can't be asked
  and when a capacity lease ends while its node's boxes can't be listed; such a lease no longer ends
  runs whose boxes may still be running there ([#676](https://github.com/public/wicket/issues/676)).

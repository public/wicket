---
area: Nodes
type: Fixed
---
- A node no longer refuses, as a rollback, a snapshot that another run's frames overtook on the way:
  two runs catching one node up at once each send it a snapshot, and the one that arrives second,
  signed before the statement the node holds, is dropped as superseded, like an older statement
  ([#589](https://github.com/public/wicket/issues/589)).
- A placed node is no longer held, and billed past its lease, for a run whose work was collected
  before a control host crash, when the supervisor that took the run over failed to fetch it again
  ([#590](https://github.com/public/wicket/issues/590)).

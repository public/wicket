---
area: Nodes
type: Fixed
---
- A node no longer refuses, as a rollback, an older snapshot that reaches it after another run's
  snapshot but before that run's statement. A snapshot below the node's epoch is now dropped as
  superseded when it was signed no later than the snapshot and deltas the node's state came from.
  It is never applied, so a replayed old snapshot is dropped the same way. One signed after them,
  such as a restored control plane's, is still a rollback, and one off the node's chain is still a
  fork ([#589](https://github.com/public/wicket/issues/589)).

---
area: Nodes
type: Fixed
---
- A node no longer refuses an overtaken snapshot as a rollback. When two runs catch one node up at
  once, each sends it a snapshot. If the second to arrive was signed before the statement the node
  holds, it is now dropped as superseded, like an older statement. Its head must still match the
  node's own at its epoch, or it is refused as a fork
  ([#589](https://github.com/public/wicket/issues/589)).
- A placed node is no longer held, and billed past its lease, for a run whose files were fetched
  before a control host crash, when the supervisor that took the run over failed to fetch them again.
  A taken result or an allowed push still leaves the node holding the run's files
  ([#590](https://github.com/public/wicket/issues/590)).

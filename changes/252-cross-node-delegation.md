---
area: Messages
type: Added
---
- The acceptance test's multi-host flow (`--nodes local`) checks delegation across nodes
  ([#252](https://github.com/public/wicket/issues/252)). The `cap` agent spawns an agent child onto
  the node it leased, and the child's report on its task comes back as a message. `continue_child`
  then gives it another brief there, and its report on that comes back on the same delegation.

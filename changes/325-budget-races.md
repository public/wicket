---
area: Model budgets
type: Fixed
---
- A spawn's model budget carve-out is checked again as it is made: a model call admitted between
  the spawn's check and its carve-out could take the parent and child past the parent's budget
  together. A node's next budget slice is computed from one reading of the counters: a `Spent`
  report merged while it was computed could lease a node more than was left. Budget figures can't
  overflow any more (a slice of more than half of `u64::MAX` did, in the renewal rule), and an
  agent can't decide its own request through a cycle of parent links
  ([#325](https://github.com/public/wicket/issues/325)).

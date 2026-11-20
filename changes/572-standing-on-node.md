---
area: Identity, spawn and links
type: Fixed
---
- `await_grant` on a standing ask ([#572](https://github.com/public/wicket/issues/572)) answers
  "granted" once the run's node has the rule, as it does for a grant: at most 15 s after the rule
  is published, or after the hand-off wait if the run's process never puts it in the box's token.
  Before, it answered as soon as a human approved, and a request made straight away could be held
  as pending because the node didn't have the rule yet. The ledger records where each rule is on
  its way into a run's token (`standing_on_node`, schema 37).

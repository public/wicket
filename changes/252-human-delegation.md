---
area: Messages
type: Added
---
- A human delegates from the CLI ([#252](https://github.com/public/wicket/issues/252)). An agent
  an operator starts (`wicket run`, not a child or a wake) is that operator's delegation, as a
  child is its parent's: its report on its task comes to the operator's inbox as a `report`
  message. `wicket message continue <agent> <brief>` then gives it another brief, a signed message
  its session wakes with, its context intact. Its report on that comes back too, on the same
  delegation. `wicket message delegations` lists them. Only the operator who started an agent may
  continue it, and only once its report is in. A refusal is audited (`delegation.refused`), and
  so is each step (`delegation.started`, `continued`, `reported`).

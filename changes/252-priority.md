---
area: Messages
type: Added
---
- The harness acts on a message's priority
  ([#252](https://github.com/public/wicket/issues/252)). A `now` message from an agent's parent, or
  from the operator it acts for, interrupts its running turn, as an operator's cancel does: ACP's
  `session/cancel`, or a driven harness's interrupt. Each message does so once, and the interrupt is
  audited as `run.turn_interrupt`. From any other sender, `now` waits for the turn to end: a peer
  that may write to an agent can't keep stopping its work. Between turns, wicket's notice to the
  agent says how many of its waiting messages asked to be read now.

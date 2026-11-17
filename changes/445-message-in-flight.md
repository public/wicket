---
area: Messages
type: Fixed
---
- A message or operator prompt taken for an agent just before a control-host restart is no longer
  lost. Before, it was marked delivered when its supervisor took it, before the box had it.
  - A peer's message stays in flight until the box's node says the box has had it. The node sends
    a new `MessageRead`, which bumps the control/node protocol to 15.
  - An operator prompt is recorded by where it is in the box's stdin.

  A supervisor that takes the run over gives again what never arrived, and the node drops a message
  its box has already had. With a node at protocol 14, a message is counted read when it is handed
  over, as before. The ledger's schema moves to 16, an expand step that adds `messages.taken_at`
  and `operator_messages.stdin_start` and `stdin_end`
  ([#445](https://github.com/public/wicket/issues/445)).

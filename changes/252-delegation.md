---
area: Messages
type: Added
---
- Delegation, the agent-to-agent protocol's next slice
  ([#252](https://github.com/public/wicket/issues/252)):
  - **A handle.** `spawn` (and `spawn_agent`) ends its answer for an agent with a handle: the
    child's principal and a delegation id (`d-…`). The child's task is its first brief.
  - **Reports are messages.** When the child's turn on its brief ends, wicket sends the turn's result
    to the parent's principal as a `report` message, signed with the child's identity, with a
    receipt like any message. The child's session stays open; its final `run_finished` names the
    delegation too.
  - **Continue by name.** A new `continue_child` tool gives a child that has reported another brief
    (by its name, principal or delegation id), in the same run, its context intact, instead of
    spawning a new one; the next report comes back the same way. `delegations` lists the caller's,
    with each one's state (`working`, `reported`, `ended`) and its report's receipt.
  - **What holds.** A brief or a report grants nothing, and a continued child keeps the zone it was
    spawned with, within its parent's. Only the agent that delegated may continue a child: anyone
    else is refused and audited (`delegation.refused`). Every step is audited
    (`delegation.started`, `.reported`, `.continued`, `.ended`).
- Ledger schema 6 (expand) adds the `delegations` table.

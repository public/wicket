---
area: Long-lived agents
type: Added
---
- Triggers on wicket's own events ([#578](https://github.com/public/wicket/issues/578)): a
  `wicket` source listens to runs ending or lost, boxes exiting or under memory pressure, agents
  waking or hibernating, refused messages, and decisions. They are read from the audit chain by
  sequence number, with a filter over the record's fields. wicket sets the run's `zone`, `agent`,
  `principal` and `agent_id` itself, so a trigger can be held to one zone.
  - Each record fires each listening trigger once, only for records written while the trigger was
    live and no more than 15 minutes old. Each record's firings are one transaction, and one
    trigger's error doesn't undo the others'.
  - The turns triggers queue record the chain of triggers that led to them. A trigger never fires
    on what its own firing led to, and no more than four triggers fire in a row.
  - Text from these records reaches the agent as JSON-quoted data.
  [On wicket's own events](../docs/how-to/wake-an-agent-on-a-schedule.md#on-wickets-own-events).

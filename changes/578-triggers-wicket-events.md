---
area: Long-lived agents
type: Added
---
- Triggers on wicket's own events ([#578](https://github.com/public/wicket/issues/578)): a
  `wicket` source listens to runs ending or lost, boxes exiting or under memory pressure, agents
  waking or hibernating, refused messages, and decisions. It reads them from the audit chain by
  sequence number, with a filter over the record's fields. Each record fires each listening trigger
  once, only for records written while the trigger was live. A trigger never fires on the wake it
  caused. Text from these records reaches the agent quoted, as data.
  [On wicket's own events](../docs/how-to/wake-an-agent-on-a-schedule.md#on-wickets-own-events).

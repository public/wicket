---
area: Long-lived agents
type: Added
---
- Triggers, the first part ([#578](https://github.com/public/wicket/issues/578)): `wicket trigger
  create --file T.yaml` keeps an operator's trigger, and each reconcile pass fires the schedules
  (cron, in a time zone) and timers that came due, once per minute they match. A firing wakes a
  long-lived agent or queues a message as its next turn (waking it if it hibernates), within the
  trigger's hourly limit. `list`, `show`, `pause`, `resume`, `rm` and `fire --dry-run` manage and
  preview triggers. Every firing, skip and failure is audited (`trigger.*`). A `start` action is
  only queued so far, and webhooks, GitHub and wicket's own events come in later steps.
  [Wake an agent on a schedule](../docs/how-to/wake-an-agent-on-a-schedule.md).

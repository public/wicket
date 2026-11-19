---
area: Long-lived agents
type: Added
---
- Triggers, the first part ([#578](https://github.com/public/wicket/issues/578)): `wicket trigger
  create --file T.yaml` keeps an operator's trigger, for 30 days unless `--lasts` says otherwise.
  Each reconcile pass fires the schedules (cron, in a time zone) and timers that came due: once per
  pass, saying how many minutes it missed, and never for the time a trigger was paused. A firing
  wakes a long-lived agent, or queues a message as its next turn (waking it if it hibernates),
  within the trigger's hourly limit. The agent is found and pinned when the trigger is made. Before
  each firing the owner's authority is checked again: `operators.yaml`, and wicketd's run class
  for their unix user. A trigger whose owner lost it, or whose firings keep failing, is paused.
  `list`, `show`, `pause`, `resume`, `renew`, `rm` and `fire --dry-run` manage and preview
  triggers. Every firing, skip, failure and pause is audited (`trigger.*`), and settled firings
  are kept for 14 days. A `start` action is only queued so far. Webhooks, GitHub and wicket's own
  events come in later steps, and are refused until then.
  [Wake an agent on a schedule](../docs/how-to/wake-an-agent-on-a-schedule.md).

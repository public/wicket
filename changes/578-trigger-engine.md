---
area: Long-lived agents
type: Added
---
- Triggers start runs ([#578](https://github.com/public/wicket/issues/578) step 5): a `start`
  action's queued firings are started by each reconcile pass, the oldest first, one at a time per
  trigger, as the trigger's owner (checked again when the run starts). The run starts from the
  manifest bytes the trigger's sha256 pins, copied into its run directory; a manifest edited since
  is refused, nothing starts, and a `trigger.refused` audit record names both digests. A started
  run carries the trigger's chain, so its own records don't fire the trigger again.
  [Wake an agent on a schedule](../docs/how-to/wake-an-agent-on-a-schedule.md#start-a-run).

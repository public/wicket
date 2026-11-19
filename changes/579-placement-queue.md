---
area: Long-lived agents
type: Changed
---
- A wake that no node can take now waits in a queue instead of failing
  ([#579](https://github.com/public/wicket/issues/579), step 2). It says why
  (`queued: no node may take agent … now (…)`), then tries again every 2 s for up to
  `wicket wake --wait` (default 30 minutes; `--wait 0` fails at once, as before). Waiting wakes are
  placed first come, first served: one goes ahead only when no wake waiting longer fits a node now.
  A waiting wake keeps its claim on the agent. Ledger schema 24 adds `placement_waits`.

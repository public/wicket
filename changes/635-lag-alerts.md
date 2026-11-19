---
area: Approvals and the console
type: Added
---
- The console alerts, and pushes to registered devices, when the ledger's stream to the state store
  has had no sync for more than 5 minutes, an audit sink's oldest unacknowledged record has waited
  more than 5 minutes or it is more than 10,000 records behind, or `state-store.yaml` or
  `audit-sinks.yaml` can't be read for more than 5 minutes. Each alert clears once it catches up.
  A `jsonl` sink to standard output, fed only by hand, never alerts. A device without details now
  hears "N health alerts", not "N node health alerts"
  ([#635](https://github.com/public/wicket/issues/635)).

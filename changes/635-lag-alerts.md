---
area: Approvals and the console
type: Added
---
- The console alerts, and pushes to registered devices, when the ledger's stream to the state store
  hasn't been current for more than 5 minutes, or an audit sink's oldest unacknowledged record has
  waited more than 5 minutes or it is more than 10,000 records behind. The alert clears once it
  catches up. A device without details now hears "N health alerts", not "N node health alerts"
  ([#635](https://github.com/public/wicket/issues/635)).

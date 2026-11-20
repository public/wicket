---
area: Approvals and the console
type: Added
---
- The console's *Health* section, and `wicket top`, show the state store's sync and the audit
  export's progress. The ledger stream gets one row: streaming, lagging or stopped, the last sync and
  the last error. Each audit sink gets one: records and time behind the chain head, the last
  checkpoint's age and the last error
  ([#635](https://github.com/public/wicket/issues/635)).

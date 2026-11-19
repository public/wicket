---
area: Operations and audit
type: Changed
---
- The ledger keeps a change counter per topic (grants, turn cancels and mode changes, revocations,
  node CAs), moved by triggers on every write to its tables (grants also by standing reach and a
  run's renewed authority end)
  ([#582](https://github.com/public/wicket/issues/582), step 2). A reader asks SQLite whether
  anything was committed since it last looked (`PRAGMA data_version`), and reads the counters only
  then. Runs' supervisors use it next, to skip their polls when nothing they depend on changed.
  Ledger schema 27 (`ledger_changes`; an expand step).

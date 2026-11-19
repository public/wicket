---
area: Operations and audit
type: Changed
---
- The ledger's cost per box no longer grows with its history
  ([#582](https://github.com/public/wicket/issues/582), step 1). What every run's supervisor and every
  node's feed status look up is indexed (grants by request, node, run and scope; runs by status,
  lease and tenant; the cancel and mode-change asks by run; audit by kind). Each node's last shipped
  audit record is kept in `node_audit_heads` by a trigger, instead of being searched for back through
  the audit table. A supervisor with no cancel or mode change to take no longer takes the write
  lock. On a ledger with 10,000 runs, `grants_for_run` (every run, four times a second) drops from
  28.6 ms to 18 µs, `node_feed_at` from 434 µs to 7 µs, and a node's audit head from 7.2 ms to 4 µs.
- Each `wicket reconcile` pass now does the ledger's upkeep. It moves the settled requests and dead
  grants of runs ended over 7 days ago to `requests_archive` and `grants_archive` (2,000 at a time;
  still read for those runs), and drops spent cancel asks. It also runs `PRAGMA optimize` and a passive
  WAL checkpoint. Ledger schema 22 (an expand step, after 21).

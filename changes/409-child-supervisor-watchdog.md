---
area: Identity, spawn and links
type: Fixed
---
- A spawned child's supervisor that hasn't ended 30 s after its parent asked it to stop is no
  longer left running unseen. The parent's log names it, its run gets a `run.child_stuck` audit
  record and is marked stuck in the ledger, and `wicket top` shows it as `stuck`. `wicket reconcile`
  reports it on every pass, and takes the run over once the parent's process ends
  ([#409](https://github.com/public/wicket/issues/409)).

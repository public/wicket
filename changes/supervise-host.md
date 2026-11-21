---
area: Operations and audit
type: Added
---
- An internal `wicket supervise` process holds a shard of nodes under a lease, renews it while its
  runtime makes progress, and answers a heartbeat that doesn't touch the ledger; a clean stop
  frees its shard at once. wicketd doesn't start it yet, and it supervises no runs yet
  ([#582](https://github.com/public/wicket/issues/582)).

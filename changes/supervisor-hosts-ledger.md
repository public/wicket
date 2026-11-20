---
area: Operations and audit
type: Added
---
- The ledger records supervisor hosts, the shards of nodes each holds under a lease at an epoch, and
  which shard supervises each run (schema 42), the groundwork for supervisors as tasks in a few
  processes. A run owned by a host (`host:<shard>:<epoch>`) reads as unsupervised to a build without
  hosts, which adopts it with a process; a node never stops a box for such an owner
  ([#582](https://github.com/public/wicket/issues/582)).

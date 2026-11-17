---
area: Long-lived agents
type: Removed
---
- Version-1 hibernation bundles (tar and zstd per tree) are no longer read or written
  ([#258](https://github.com/public/wicket/issues/258)). The build before this one converts them
  to bundle trees when its reconciler starts. `wicket serve` and `wicket reconcile` now refuse to
  start while any agent's head is still version 1, and name those agents: run the previous build's
  `wicket reconcile` once, then this one.

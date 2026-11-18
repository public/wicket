---
area: Updates
type: Removed
---
- Ledger snapshots that builds before the content-addressed store (#258) pushed to the state store
  are no longer listed, fetched or pruned by `wicket state snapshots`, `wicket state snapshot` and
  `wicket self prune`: every update since pushes them to the store with a digest, and those are
  unchanged.

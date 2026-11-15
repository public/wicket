---
area: Updates
type: Changed
---
- The ledger snapshot `wicket self update` pushes to the state store now goes into wicket's
  content-addressed store: a blob named by its sha256, sealed under `state.key`, with a ref
  `ledger-snapshots/<time>-<build id>.db`. `wicket state snapshot` checks the digest as it fetches,
  and the `self.snapshot` audit record names it (`store_digest`). Snapshots pushed by earlier builds
  are still listed, fetched and pruned. This is the first part of one store for bundles, snapshots,
  volume snapshots and versions; the design is in docs/explanation/store.md
  ([#258](https://github.com/public/wicket/issues/258)).

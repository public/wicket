---
area: Nodes
type: Fixed
---
- A node now puts a snapshot it drops as superseded on its audit record
  (`feed.snapshot_superseded`), and its feed counts these snapshots apart from superseded
  statements. So a replayed old snapshot stays visible now that it is no longer refused as a
  rollback ([#589](https://github.com/public/wicket/issues/589)).
- `wicket node forget` refuses, without `--force`, a run whose only collected work is a taken
  result: its workspace was still to be fetched. A run whose files were fetched or bundled, or
  whose push was allowed, is forgotten as before ([#590](https://github.com/public/wicket/issues/590)).

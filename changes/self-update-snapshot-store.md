---
area: Updates
type: Added
---
- With a state store, `wicket self update` pushes the ledger snapshot it takes before each switch
  there too, sealed under `state.key`, and doesn't switch until it is; pruning applies to the
  store's copies. `wicket state snapshots` lists them and `wicket state snapshot` fetches one, so a
  rollback past a contract step survives losing the control host
  ([#167](https://github.com/public/wicket/issues/167)).

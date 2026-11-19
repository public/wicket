---
area: Remote nodes and capacity
type: Fixed
---
- The money limit now counts what a placed node bills while it's held past its lease
  ([#494](https://github.com/public/wicket/issues/494), [#495](https://github.com/public/wicket/issues/495)).
  A run started shortly before its node's lease ended keeps the node until the run is done, and the
  node bills hours its worst-case reservation didn't cover. The next `wicket node create` was
  checked against what was reserved, so owned nodes could be committed past `max_total_usd`.
  Each reconciler pass now raises a held node's reservation to every hour it has started and the
  next, so that create is refused. The nightly simulation found it.

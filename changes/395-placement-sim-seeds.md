---
area: Placement
type: Fixed
---
- A placed node no longer starts a box past its lease
  ([#395](https://github.com/public/wicket/issues/395),
  [#396](https://github.com/public/wicket/issues/396),
  [#398](https://github.com/public/wicket/issues/398)). The lease was checked only when
  `wicket run` began, and the box starts seconds later on the node, so the two raced. The run's
  `BoxStart` now carries its node's lease end (`start_by`), and the node refuses a start that
  reaches it then or later. The check at the run's start stays as the early, clear answer. The
  simulation's placement stand-ins now follow the node in two ways: a box start is refused there
  past its lease, and a box the node has forgotten is gone from it. That stand-in gap made
  [#397](https://github.com/public/wicket/issues/397) and
  [#399](https://github.com/public/wicket/issues/399) report a node billing past its lease, where
  the real node forgets the box and is released. The five seeds are regression tests.
- A node takes a late freshness statement older than the history it holds as superseded, not as a
  rollback (found by a fresh-seed sweep of the placement scenario, seed 50002077). Another run's
  statement, signed before the newest one the node holds and delivered later over its own
  connection, named an epoch from before the snapshot the node had been caught up from. It can't
  take effect, and the node no longer refuses it. A newer statement for such an epoch is still a
  rollback.
- The placement simulation's provider latency is per run. It was a process-wide static, so runs in
  one `cargo test` process set it for each other, which made `deterministic` and the seed tests
  flaky when run in parallel.

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

---
area: Boxes and the egress path
type: Fixed
---
- `on_output_full: stop` now stops a box once what it *wrote* passes `limits.output`, not what its
  node had read of it ([#824](https://github.com/public/wicket/issues/824)). Before, a burst faster
  than the node read went partly unread, since Docker rotates away what a lagging reader hasn't
  read, and the box could write far past its cap without being stopped. The node counts the box's
  output on Docker's attach stream, opened before the box starts (Docker doesn't let a box write
  past it), and `box.output` records the count as `written_at_least`. Through Docker's CLI, which
  can't attach before the start, the count is what the node read, as before.

---
area: Messages
type: Added
---
- The acceptance test's multi-host flow (`ci/acceptance.sh --nodes local`) checks the
  agent-to-agent protocol across nodes ([#252](https://github.com/public/wicket/issues/252)).
  A box on each node finds the other through the gateway and messages it, with a receipt that
  reaches read, and gets the other's reply. A message written unasked is refused, with a receipt
  and an audit record. A human's `wicket message send` reaches one box as its operator's, and the
  box's answer lands in `wicket message inbox`, with receipts on both sides.

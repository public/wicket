---
area: Remote nodes and capacity
type: Added
---
- `wicket why-here <run>` says why a run's box went on the node it did, or why it went nowhere
  ([#579](https://github.com/public/wicket/issues/579), step 2). It shows what the box asked for,
  the nodes it may go on in order, every reason each other node was out, or the waiting wake it went
  behind. `--json` gives the record. Every placement decision is recorded (`placement_decisions`,
  ledger schema 24), a run's latest, kept a week, naming at most 10 nodes of each kind.

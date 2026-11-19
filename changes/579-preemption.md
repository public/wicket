---
area: Remote nodes and capacity
type: Added
---
- Preemption ([#579](https://github.com/public/wicket/issues/579), step 4). A waiting wake which
  no node may take now may ask long-lived agents to hibernate to make room: only active agents of
  its own tenant whose manifest marks them `placement.preemptible` and whose priority is below its
  own, on one node, each one needed. A program is never preempted, and nothing is revoked: a
  preempted agent keeps its work and wakes again. Each is audited as `placement.preempted`, and the
  wake reserves the room while they hibernate. It defers only to a wake ahead of it that fits a node
  now or could make room itself; it asks every node for its room first; an agent asked counts as
  gone for 2 minutes; and it doesn't preempt with under 30 s of its wait left. Placement still
  decides placement only: the woken box's authority is issued as before, and the node's admission
  decides its start. Ledger schema 30 also adds `run_terms`, each box's limits, priority and
  preemptibility recorded at its start (a box started by an older build has none and is never
  preempted).

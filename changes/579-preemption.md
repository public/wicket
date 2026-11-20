---
area: Remote nodes and capacity
type: Added
---
- Preemption ([#579](https://github.com/public/wicket/issues/579), step 4). A waiting wake which
  no node may take now may ask long-lived agents to hibernate to make room: only active agents of
  its own tenant whose manifest marks them `placement.preemptible`, whose priority is below its own,
  and which have no live child (hibernating ends an agent's run, which stops its children), on one
  node, each one needed. Nothing is revoked: a preempted agent keeps its work and wakes again.
  Programs are never preempted, by design (a program has no stop that keeps its work). Each agent
  asked is audited as `placement.preempted`, and the wake holds the room while they hibernate. An
  operator's own `wicket hibernate` request stands; preemption's is tagged, and one that hasn't
  been honoured within 5 minutes, or that the wake no longer needs (it was placed, gave up or failed), is
  withdrawn, audited as `placement.preempt_abandoned`. The agent's supervisor checks before it
  hibernates for preemption, at its quiet point and again out of a linger, and declines (audited as
  `placement.preempt_declined`) if the request was withdrawn, is stale, its wake is gone, or the
  agent has started a child since. An agent that has hibernated counts as gone until a node report
  from after its end, so no second agent is stopped for the same room. The wake defers only to a
  wake ahead of it that fits a node now or could make room itself; it probes nodes only when it has
  something to stop, at most every 30 s; and it doesn't preempt with under 30 s of its wait left.
  Placement still decides placement only: the woken box's authority is issued as before, and the
  node's admission decides its start. Ledger schema 33 adds `run_terms`, each box's limits,
  priority and preemptibility recorded at its start (a box started by an older build has none and
  is never preempted).

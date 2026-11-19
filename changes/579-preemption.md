---
area: Remote nodes and capacity
type: Added
---
- Preemption ([#579](https://github.com/public/wicket/issues/579), step 4). A waiting wake with
  nothing ahead of it in the queue, which no node may take now, may stop boxes to make room: only
  its own tenant's boxes whose manifest marks them `placement.preemptible` and whose priority is
  below its own, as few as it can on one node. Each is stopped through the normal path, its run
  revoked (by `wicket:preempt`), and audited as `placement.preempted`. A box already being stopped
  counts as gone, and a wake that preempted stops no more for 2 minutes, while the nodes' reports
  catch up. Placement still decides placement only: the woken box's authority is issued as before,
  and the node's admission decides its start. Ledger schema 30 adds `run_terms`, each box's limits,
  priority and preemptibility recorded at its start (an expand step; a box started by an older
  build has none and is never preempted).

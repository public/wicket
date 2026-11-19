---
area: Remote nodes and capacity
type: Added
---
- A manifest's `placement:` takes `priority` (-1000 to 1000), `preemptible`, `affinity` (a service
  its zone uses, or a volume it declares, on its node) and `anti_affinity` (a zone's or a
  principal's boxes off its node), each preferred unless `required: true`
  ([#579](https://github.com/public/wicket/issues/579), step 4). A spawned box's priority is at
  most its parent's, and a preemptible parent's children are preemptible, approved or not. The
  scheduler (`wicket-placement::schedule`) filters by required affinity and anti-affinity and ranks
  by preferences met before bin-packing; orders a queue by priority, first come, first served
  within one (`queue_cmp`, `ahead`); and chooses which boxes to stop when no node may take a box
  (`preempt`): only preemptible ones of lower priority, each one needed, the lowest highest
  priority first. All are pure functions with property tests. The wake queue and the ledger's view
  of each node come in the next change.

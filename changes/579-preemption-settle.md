---
area: Remote nodes and capacity
type: Fixed
---
- Preemption ([#579](https://github.com/public/wicket/issues/579), step 4): a wake whose victim
  another wake has asked to stop since gives up on its plan, audited as "another wake asked it to
  stop since", instead of counting that victim as one that declined; the later wake's request
  stands. A ledger error while a wake checks on its victims fails the check rather than reading as
  a decline. A supervisor that declines a hibernate for preemption audits
  `placement.preempt_declined` once, not again when it re-checks out of a linger.

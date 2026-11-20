---
area: Remote nodes and capacity
type: Changed
---
- `wicket run` without `--node` is placed by the scheduler
  ([#579](https://github.com/public/wicket/issues/579)), as a woken agent is: among every enrolled,
  active node not held by a lease, this host's own among them, by the manifest's requests, labels,
  taints, CA coverage, affinity and priority. With no enrolled node but this host's own, every run
  goes there, as before. A spawn, a re-attach, a lease's run, a wrapped session and an in-place
  `--workspace-dir` keep their node. `wicket run` fails at once, saying why each node is out, when
  none may take the box now; `wicket run --wait <duration>` waits in the queue instead (and may
  preempt, by its priority). `wicket why-here` shows the decision.

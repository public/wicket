---
area: Remote nodes and capacity
type: Added
---
- `wicket service add|list|remove` installs per-node services, and each `wicket reconcile` pass
  keeps one instance of each on every node whose live boxes use it
  ([#579](https://github.com/public/wicket/issues/579), step 3). A service is installed from a
  snapshot wicket owns, its source's digest pinned, so editing the files it came from changes
  nothing until it is added again. An instance is per tenant unless the service is shared, never
  started on a capacity lease's node past its lease, and stopped once no box has used it for 10
  minutes. One that ends is retried ever more slowly. Instances are ordinary runs of the service's
  program. Ledger schema 25 (`services`, `service_wants`, `service_instances`; an expand step,
  after 24).

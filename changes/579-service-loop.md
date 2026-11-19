---
area: Remote nodes and capacity
type: Added
---
- `wicket service add|list|remove` installs per-node services, and each `wicket reconcile` pass
  keeps one instance of each on every node whose live boxes use it
  ([#579](https://github.com/public/wicket/issues/579), step 3). The instance is per tenant unless
  the service is shared, only on active nodes its `node_selector` matches, and started again at most
  once a minute when it exits. Instances are ordinary runs of the service's program. Ledger schema
  25 (`services`, `service_wants`, `service_instances`; an expand step, after 24).

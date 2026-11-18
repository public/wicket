---
area: Operations and audit
type: Added
---
- Kani now checks three more decisions in `wicket-core`
  ([#325](https://github.com/public/wicket/issues/325)):
  - **The org policy's spawn ceiling (`quota::SpawnLimits::admits`):** `wicket-authz`'s
    `OrgLayer::allows_spawn` now calls it. With no limits every spawn is admitted. A spawn that
    asks for no more than an admitted one is admitted too. Limits no looser than another set never
    admit a spawn that set refuses.
  - **wicket's own approval namespace (`op::agent_op_refusal`, #117):** an agent or a node is
    refused every reserved method in any case, and every name under `wicket.internal` in any case
    and with trailing dots. Past that, only the HTTP methods are let through. The check no longer
    allocates.
  - **Duration terms (`time::add_to`, #437):** adding a term never panics, and a sum it makes is
    exact to the nanosecond. It refuses a sum only past the largest duration, or when a term's
    nanoseconds and the total's together don't fit 64 bits.

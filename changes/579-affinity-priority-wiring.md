---
area: Remote nodes and capacity
type: Added
---
- Affinity and priorities place woken agents
  ([#579](https://github.com/public/wicket/issues/579), step 4). A node is seen with the boxes of
  the box's own tenant running there or being started on it (their zones and principals), the live
  instances of the services it may use there, and, for a kept volume, whether a box of the box's
  zone ran there within the volume's retention, so `placement.affinity` and `anti_affinity` decide
  where it goes. Another tenant's boxes are never seen. Waiting wakes are served first come, first
  served across tenants; within a tenant, `placement.priority` decides which of its own wakes fills
  each of its places in line, so a priority never moves another tenant's wakes, and a wake behind
  another tenant's isn't told which run. `wicket why-here` shows the priority and affinity a box
  asked for. A node named for a run (`--node`) is refused for a required term it fails, as for a
  label. Ledger schema 30 adds `placement_owners`: whose box each reservation is for.

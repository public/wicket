---
area: Remote nodes and capacity
type: Added
---
- Affinity and priorities place woken agents
  ([#579](https://github.com/public/wicket/issues/579), step 4). A node is seen with the boxes of
  the box's own tenant running there (their zones and principals), the live instances of the
  services it may use there, and, for a kept volume, whether it ran a box of the box's zone, so
  `placement.affinity` and `anti_affinity` decide where it goes. Another tenant's boxes are never
  seen. Waiting wakes are served by `placement.priority`, highest first, and first come, first
  served within one. `wicket why-here` shows the priority and affinity a box asked for. A node
  named for a run (`--node`) is refused for a required term it fails, as for a label.

---
area: Images
type: Added
---
- A remote node that hasn't a box's pinned image gets it from the control host over the node
  channel, as an OCI image layout, and verifies it before importing it: every blob against its
  digest, the pin as an image index or manifest whose config and layers are all there, and nothing
  else kept. A tampered image is refused before the box starts, and the node's audit records
  `image.received` or `image.refused`. Protocol 7
  ([#191](https://github.com/public/wicket/issues/191)).

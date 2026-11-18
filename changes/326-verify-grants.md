---
area: Remote nodes and capacity
type: Fixed
---
- A money reservation asked again for a node that already holds one (a retried `wicket node
  create`) now records the configured limits as the tenant's money limit grant too, as every other
  reservation does; before, the grant kept the limits it was last recorded with until the next new
  reservation ([#326](https://github.com/public/wicket/issues/326)).

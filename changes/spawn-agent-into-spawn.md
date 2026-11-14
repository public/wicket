---
area: Identity, spawn and links
type: Changed
---
- `spawn_agent` is read as `spawn` with `kind: "agent"`, by one parser on the control host and on
  nodes, so a box cut off from the control host answers a `spawn_agent` with no task as the control
  host does ("`task` is required") ([#254](https://github.com/public/wicket/issues/254)).

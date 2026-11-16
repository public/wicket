---
area: Nodes
type: Security
---
- A node writes a harness's config files into a box's state (Claude Code's `settings.json`, and now
  its skills) without following symlinks: every directory on the way is made a real one and each
  file is created new. A woken agent's state comes from its own bundle, which could hold a link that
  sent the node's write outside the box. The control host already wrote its own files this way.

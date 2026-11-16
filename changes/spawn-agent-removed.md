---
area: Identity, spawn and links
type: Removed
---
- **The `spawn_agent` MCP tool is gone; use `spawn`.** `spawn` with a `name` and a `task` and no
  `zone` starts a child agent in the caller's own zone, as `spawn_agent` did. Its `reach_hosts`
  shorthand (the caller's zone narrowed to some of its hosts) is gone too: describe the narrower
  zone in `spawn`'s `zone` instead. An agent that calls `spawn_agent` now gets an unknown-tool
  error (#253, #255).

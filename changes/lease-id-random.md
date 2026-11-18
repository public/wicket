---
area: Remote nodes and capacity
type: Fixed
---
- A capacity lease's id no longer falls back to `l-000000000000` when the operating system's
  random source fails; wicket stops with an error instead, as it does for every other random id.

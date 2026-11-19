---
area: Development
type: Added
---
- Prefix grants (#568) are proved in the Lean spec: a grant for a path prefix covers its directory
  and paths continuing it with `/`, never a sibling such as `/a/app-secrets` for `/a/app`; it is
  no wider than the reach rule `Q/**`; and a covered canonical path keeps the directory's segments
  however an upstream decodes and resolves it ([#322](https://github.com/public/wicket/issues/322)).

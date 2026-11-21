---
area: Messages
type: Added
---
- Programs in discovery ([#252](https://github.com/public/wicket/issues/252),
  [#255](https://github.com/public/wicket/issues/255)). A program's identity document now says
  what it is (`kind: program`, signed by wicket). The gateway's `principals` lists a program as
  `kind: program`, and a message from one says so in its verified `from.kind`. Agents' documents
  are unchanged, and documents issued before the claim read as agents.

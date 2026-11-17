---
area: Principals
type: Added
---
- What an agent may grant its descendants is policy: `operators.yaml`'s `agents` section (`kinds`,
  `prefix`, `zone_wide`, `git_push`, `unbounded`). The defaults are what agents could always do:
  HTTP requests, for the asking run and the asked path, with a number of uses, and no git push. So
  nothing changes until a policy says otherwise. No rule lets an agent decide beyond its own reach
  or authority, and capacity grants stay with operators
  ([#256](https://github.com/public/wicket/issues/256)).

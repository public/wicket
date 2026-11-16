---
area: Manifests
type: Added
---
- `zone.llm.models` lists the models a box may call: exact names, or prefixes ending in `*`. The
  model proxy refuses a call naming any other model, or none, with a 403, and audits it. A zone a
  box starts may only narrow the list, `agent.model` must be in it, and spawn cards and the console
  show it. Without the field, any model the credential reaches is allowed, as before
  ([#366](https://github.com/public/wicket/issues/366)).

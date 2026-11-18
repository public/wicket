---
area: Operations and audit
type: Added
---
- Kani now checks when a refused request may be asked for
  ([#325](https://github.com/public/wicket/issues/325)). `wicket-authz` now takes the rule from
  two `wicket-core` functions (`escalation::check_escalatable` and `needs_grant`). A token check
  that reads the org policy is never escalatable. A refusal needs a grant only when it failed at
  least one check and every check it failed is known to be escalatable. Anything else, including
  a check of unknown class, forbids.

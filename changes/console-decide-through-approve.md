---
area: Approvals and the console
type: Changed
---
- The console decides requests through the same function as `wicket approve` and `wicket deny`: it
  can grant a prefix the operator names (`prefix`) and grant zone-wide (`zone_wide`), signed with the
  decision; denying a capacity ask releases its lease's reservation at once, and approving one says
  that the next reconcile pass provisions it. Its decision records carry the same fields as the
  CLI's ([#254](https://github.com/public/wicket/issues/254)).
- `wicket approve --prefix` refuses a prefix that doesn't cover the asked path (or, for a prefix
  ask, lie within it), rather than granting the exact path instead.

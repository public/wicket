---
area: Approvals and the console
type: Changed
---
- A refused decision on a standing reach ask, a public name or a trigger is recorded like every
  other refused decision (#256): one `decision.refused` record, which now also names the granter
  kind and identity. A refused trigger approval (by something other than an operator, or by an
  operator who may decide nothing) is now on the audit record; it wasn't before. The human-only
  check, the refusal record and the merge of the console's signed fields are one copy, in
  `grant`, instead of one per kind.

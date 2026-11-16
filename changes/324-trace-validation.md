---
area: Operations and audit
type: Added
---
- `wicket doctor --invariants` also checks that no placed node was released while a run's box ran on
  it or while a run's files on it were uncollected (unless a human released it, files and all), and
  that no message was pushed to a box twice, none wicket refused was pushed at all, and every refusal
  says why. A message whose push its node recorded lost is said, not counted
  ([#324](https://github.com/public/wicket/issues/324)).
- Trace validation (#324): the ledger check `wicket doctor --invariants` runs now lives in
  `wicket-store`, and the deterministic simulation runs its clock-free half over every placement and
  messages seed's ledger, so the simulation's oracle and the check on real records are held to each
  other. CI's node end-to-end run now ends with `wicket doctor --invariants` too, as acceptance
  already did.

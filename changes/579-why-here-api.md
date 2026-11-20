---
area: Approvals and the console
type: Added
---
- `GET /api/runs/<run>/placement` ([#579](https://github.com/public/wicket/issues/579)): why a run
  went where it did, for the console to show. It returns the placement decision recorded when the
  run's node was chosen, by named fields, with the plain-words explanation `wicket why-here`
  prints; a run with no decision recorded says why. Read-only, behind an operator's session. A run
  of another tenant is not found, here and in `GET /api/runs/<run>/authority`, which looked a run up
  by id alone.

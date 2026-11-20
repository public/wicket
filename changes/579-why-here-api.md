---
area: Approvals and the console
type: Added
---
- `GET /api/runs/<run>/placement` ([#579](https://github.com/public/wicket/issues/579)): why a run
  went where it did, for the console to show. It returns the placement decision recorded when the
  run's node was chosen, as `wicket why-here --json` prints it, with the same plain-words
  explanation; a run with no decision recorded says why. Read-only, behind an operator's session.

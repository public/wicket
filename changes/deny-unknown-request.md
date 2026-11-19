---
area: Approvals and the console
type: Fixed
---
- `wicket deny` (and a console decision) on a request id that doesn't exist now says "no such
  request", as `wicket approve` does. Before, it answered "refused (the refusal is on the audit
  record)" and audited a refusal for the mistyped id.

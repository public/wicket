---
area: Operations and audit
type: Fixed
---
- `wicket doctor --invariants` checks an egress request a standing rule allowed (#572) against that
  rule: approved before the request, covering it, bound to the run's principal or zone, and not
  lapsed or revoked. It reported every such request as allowed by a grant "never issued". Found by
  the attack matrix ([#326](https://github.com/public/wicket/issues/326)).

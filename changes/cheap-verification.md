---
area: Operations and audit
type: Added
---
- `wicket doctor --invariants` checks an installation's ledger for #321's properties on its real
  logs: every allowed egress request (its own and its nodes') had a reach rule or a live grant for
  exactly that request, no run's model calls went past its quota grants, and no run outlived its
  node's lease. It is read only, says what it couldn't check, and exits non-zero on a violation
  ([#326](https://github.com/public/wicket/issues/326)).
- CI: `cargo deny` on every pull request (advisories, licences, bans, sources), weekly mutation
  testing of the decision code with its results in `verification/mutants`, and an acceptance box that
  tries every way out of its reach, on the control host's node and on a placed one (#326).

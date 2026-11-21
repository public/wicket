---
area: Approvals and the console
type: Added
---
- Every operator action now has a row on [console and CLI parity](../docs/reference/parity.md)
  ([#713](https://github.com/public/wicket/issues/713)), giving its console path, its CLI command,
  or why it is host-only. The CLI gains what only the console had: `wicket capacity
  list|grant|renew|revoke` for standing capacity grants, `wicket authority <run>` for a run's
  token as its node holds it, and `wicket audit explain <seq>` for an activity record's
  decision. Each prints the console's own view (`--json` for scripts), through the same checks
  and audit records. `wicket grant revoke` on a capacity grant now revokes it as the console
  does, audited as a decision.

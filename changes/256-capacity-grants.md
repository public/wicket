---
area: Approvals and the console
type: Added
---
- An operator can give a principal a standing capacity grant from the console's new Capacity card:
  the plans and regions it covers, the most its nodes may cost per hour together and per day, how
  many nodes at once, and a lifetime of at most 24h. Issuing and renewing one are passkey-signed
  actions (`capacity_grant`, `capacity_renew`). Revoking one needs only the session. The card lists
  each live grant with what its nodes use and leave and when it ends
  ([#256](https://github.com/public/wicket/issues/256)).
- A capacity grant is one grant record, `QUOTA wicket.internal /quota/capacity`, bound to its
  principal, with its daily money as its amount. `wicket grant list` shows it, `wicket grant renew`
  and `revoke` work on it, and an operator whose `operators.yaml` authority lacks `capacity` may not
  issue or renew one. It is issued on a `decision` audit record (`decision: issue`).
- The ledger's schema goes to version 9, an expand step: `grants.principal`, `grants.terms` and the
  `capacity_uses` table.

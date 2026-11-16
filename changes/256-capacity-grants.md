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
---
area: Placement
type: Changed
---
- `wicket node create` no longer asks for the spend on the terminal. Its spend is a request from the
  operator who runs it, `CAPACITY wicket.internal /capacity/node/<name>`, with the plan, region, rate
  and worst case. It is decided by the same function as every approval. If one of that operator's
  live capacity grants covers it, it is approved at once and audited against the grant: the grant,
  the ask, and what the grant's nodes took before. Otherwise it is pending, in `wicket pending` and
  on the console (which sends a notification), for up to `--wait` (default `15m`), and denied if
  nobody decides by then. The money envelope (`--max-hourly`, `--max-total`) is still checked
  first.

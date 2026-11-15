---
area: Approvals and the console
type: Security
---
- A node honoured a grant for up to 999 ms past the end the ledger gave it: the token's check is
  inclusive and in whole seconds, and the grant was published with the ledger's `expires_at`. A
  grant now ends on the node exactly when it does in the ledger (live while now is before
  `expires_at`, in ms), cut off or not. It's published with `not_after = expires_at - 1`, so the
  token keeps its shape and older nodes agree as well
  ([#342](https://github.com/public/wicket/issues/342)).
- An agent's `decide` approval is capped at 100 uses and a grant's lifetime at 24 hours where every
  grant is made, not only in the gateway's argument parsing. A signed decision over either cap is
  refused, and the refusal is on the audit record as `decision.refused`. An operator's approval over
  the lifetime cap, or with zero uses, is now audited the same way
  ([#342](https://github.com/public/wicket/issues/342)).

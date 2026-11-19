---
area: Approvals and the console
type: Changed
---
- `await_grant`'s answer to an approved request now says what the grant allows: how many uses, and
  for how long. It also says that each attempt spends a use whatever the host answers, and that a
  403 without "Blocked by wicket box" in it is the host's own answer, not wicket's. A grant that
  has since expired, been used up or been revoked is answered as spent: a retry would only ask
  again, as a new request for a human. Before, it said "retry now" in every case, and an agent
  that spent a one-use grant on an attempt the host refused asked for the same thing again.

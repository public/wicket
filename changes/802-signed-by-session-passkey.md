---
area: Approvals and the console
type: Security
---
- A signed console action must be signed by the passkey its session signed in with. Before, any
  enrolled passkey's signature on a session's challenge was accepted, and the action ran as that
  passkey while the page and the signed JSON named the session's. The challenge now offers only the
  session's passkey, and another's signature is refused (403) and audited as `operator.action_refused`,
  for every action ([#802](https://github.com/public/wicket/issues/802)).

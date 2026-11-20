---
area: Approvals and the console
type: Changed
---
- The session page names what wicket holds for a decision a request, as the glossary does
  ([#647](https://github.com/public/wicket/issues/647)): "Request waiting for you" with a note that
  wicket enforces it, a card labelled "wicket request" with its status in words (waiting for you,
  approved, denied, withdrawn), and the agent's own ask labelled "The agent asks (not enforced by
  wicket)". An approved request's card now reads approved: the endpoint compared the ledger's
  status with `approved`, but the ledger records `granted`, so an approval showed as failed.
- The session page's sign sheet shows what the console's shows before the passkey
  ([#652](https://github.com/public/wicket/issues/652)): what else an approval that widens would
  allow, what approving an update request installs and where, and the effect's hash, all read from
  the action the passkey signs.

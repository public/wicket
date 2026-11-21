---
area: Approvals and the console
type: Added
---
- From the console, an operator can now revoke a grant, cut a link, pause a trigger and end one of
  their own console sessions ([#713](https://github.com/public/wicket/issues/713)): `POST
  /api/grants/revoke`, `/api/links/cut`, `/api/triggers/pause` and `/api/sessions/end`. Each needs
  only the session, since it only takes something away, and goes through the same function as its
  `wicket` command. Each is kept to the console's tenant and audited with the passkey's operator.

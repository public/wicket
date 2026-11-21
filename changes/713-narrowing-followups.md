---
area: Approvals and the console
type: Fixed
---
- Follow-ups to the console's narrowing actions ([#713](https://github.com/public/wicket/issues/713)):
  - A repeated revoke, cut or pause answers 409 and records nothing again; `wicket unlink` of a
    closed link is refused too.
  - Ending the session the request came with clears its cookie.
  - A session prefix two of your sessions share is ambiguous.
  - An error that is the installation's own answers 500, not 409.
  - A trigger's audit records are its own tenant's.

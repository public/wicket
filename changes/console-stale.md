---
area: Approvals and the console
type: Fixed
---
- When the console can't reach wicket for a moment (a restart's 502, a network drop), it says so
  ("Can't reach wicket (HTTP 502) since 12:41:05Z; what is shown is as of then. Retrying.") and
  keeps polling, instead of showing the sign-in screen and stopping until you signed in again. Only
  the server saying your session is gone signs the page out.

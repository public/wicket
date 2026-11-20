---
area: Operations and audit
type: Fixed
---
- `wicket audit --verify` now re-verifies the console's signed standing reach decisions (approve,
  deny, renew), capacity grants (issue, renew) and fence releases. They used to fail it. Each kind's
  record is checked against the fields its signed action names
  ([#799](https://github.com/public/wicket/issues/799)).

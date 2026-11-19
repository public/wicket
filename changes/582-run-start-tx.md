---
area: Operations and audit
type: Changed
---
- A run's start writes its rows in one ledger transaction
  ([#582](https://github.com/public/wicket/issues/582), step 2): the run itself, its supervisor, the
  lease it is placed on, and a new long-lived agent's row. That's one write lock and one sync instead
  of three to four, and a start that fails leaves none of them.

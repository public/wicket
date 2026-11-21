---
area: Operations and audit
type: Fixed
---
- `wicket self update` no longer fails with `sqlite: database is locked` while wicketd writes the
  ledger ([#830](https://github.com/public/wicket/issues/830)). Accepting a signed build read,
  then wrote, in a deferred transaction, which SQLite refuses at once (without waiting) when another
  connection writes in between. Every ledger transaction that writes now begins `IMMEDIATE`, so it
  waits its turn under the busy timeout. If the wait runs out, the error says the ledger is busy and
  to try again.

---
area: Operations and audit
type: Changed
---
- Kani's check that a node's token and the ledger end a grant at the same millisecond (#342) is
  now two bounded harnesses instead of one over every `i64`, which took 4–6 minutes of a CI
  shard. They cover:
  - every grant end through year 2106, with every clock reading from the epoch to 2109;
  - and clock readings up to 2^32 ms before the epoch, under every grant.

  Ends past 2106 are left to the unit tests ([#325](https://github.com/public/wicket/issues/325)).

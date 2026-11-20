---
area: Console
type: Fixed
---
- A read of the ledger stream's state that came right after another is no longer sometimes refused as
  "Litestream hasn't answered an earlier question" when Litestream had already answered
  ([#695](https://github.com/public/wicket/issues/695)).

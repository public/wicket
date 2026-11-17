---
area: Messages
type: Fixed
---
- A message given to a box just as the link to its node dropped is now given again when the link
  comes back. Before, it stayed in flight, neither waiting nor read, until a later supervisor took
  the run over. The node drops the repeat if its box had it after all
  ([#453](https://github.com/public/wicket/issues/453)).

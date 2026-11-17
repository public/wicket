---
area: Nodes
type: Fixed
---
- `wicket node serve`, `wicketd`, the console, the reconciler (`wicket reconcile --every`), the
  ledger's audit writer and `wicket secret serve` no longer panic when their stdout or stderr is
  closed, for example when the journal restarts or a pipe's reader exits. They lose only the lines
  they would have printed ([#422](https://github.com/public/wicket/issues/422)).

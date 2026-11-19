---
area: Operations and audit
type: Changed
---
- `wicket --help` lists each command with a one-line summary, without issue numbers. Before,
  several summaries were whole paragraphs (`session`, `reconcile`, `node`, `self`). The full text
  is still in `wicket <command> --help`. `wicket audit` on an empty ledger now says "no audit
  records yet" instead of printing nothing.

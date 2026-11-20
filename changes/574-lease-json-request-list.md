---
area: Operations and audit
type: Added
---
- `wicket lease list --json`, the last list without it
  ([#653](https://github.com/public/wicket/issues/653)): an array of every lease, with its status,
  holder run, node, money in micro-USD and times in Unix seconds, as docs/reference/cli.md lists.
- `wicket request list`, another name for `wicket pending`, named as `grant list` names grants
  ([#654](https://github.com/public/wicket/issues/654)). `pending` still works.

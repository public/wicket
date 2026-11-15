---
area: Operations and audit
type: Changed
---
- One word per thing: the glossary ([concepts](../docs/explanation/concepts.md#the-nouns)) defines box,
  operator, request, control host and control plane, run, activation and generation, the four
  qualified sessions, and host name, and the CLI's help, the docs and wicket's messages use them.
  `wicket pending` lists pending requests, `wicket node` is for remote nodes, `wicket secret` binds
  host names, a run prints `[wicket] Remote Control session: <url>` and `→ an operator decides`,
  a node cut off says the control host is unreachable, and the box-start timing `budget.lease` is
  `budget.slice` ([#332](https://github.com/public/wicket/issues/332)).
- `ci/check-terms.sh` fails on words the glossary replaced ("sandbox node", an unqualified
  "escalation request", "mandate" and "crew" outside research and Deferred, "sandbox" for a box) in
  the docs and the CLI's help, with an allow-list in `ci/check-terms.allow`
  ([#332](https://github.com/public/wicket/issues/332)).

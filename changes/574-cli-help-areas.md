---
area: Operations and audit
type: Changed
---
- `wicket --help` lists its commands by area (runs and agents, approvals and grants, nodes and
  placement, the installation), with what an operator does daily first, as part of the CLI polish
  pass ([#574](https://github.com/public/wicket/issues/574)). `why-here`, `standing` and `service`
  get one-line summaries without issue numbers.
- One name for one thing, the old name kept: `wicket secret remove` (was `secret rm`, still
  accepted), and `wicket standing approve|renew --ttl` (was `--lasts`, still accepted), as
  `approve` and `grant renew` say it. `wicket hibernate --wait` and `wicket session --timeout` take
  a duration (`90s`, `5m`) like every other such flag; a bare number is still seconds.

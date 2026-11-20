---
area: Operations and audit
type: Added
---
- `--json` on every command that lists things: `pending`, `top`, `links`, `grant list`,
  `standing list`, `node list`, `service list` and `audit` (with `agents`, which had it), as part of
  the CLI polish pass ([#574](https://github.com/public/wicket/issues/574)). Stdout then holds one
  JSON document: an array for a list (`[]` when empty), one object for `top --json` (which implies
  `--once`). docs/reference/cli.md lists each output's fields. A field is never renamed or removed,
  and a test per command checks the printed fields against that list.

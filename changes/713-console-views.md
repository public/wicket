---
area: Approvals and the console
type: Added
---
- The console serves the lists that only `wicket …` on the host had
  ([#713](https://github.com/public/wicket/issues/713)): `/api/grants`, `/api/links`,
  `/api/triggers`, `/api/nodes`, `/api/services`, `/api/identities` and `/api/sessions`. Each
  answers an operator's session with what its command's `--json` prints. `wicket trigger list`,
  `wicket identity list` and `wicket operator sessions` gain `--json`.

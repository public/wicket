---
area: Operations and audit
type: Fixed
---
- `wicket audit`'s check that a pid file names a running wicket no longer counts a number that has
  since gone to a thread of some wicket process: only a process (its own thread group) counts
  ([#663](https://github.com/public/wicket/issues/663)).

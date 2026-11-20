---
area: Operations and audit
type: Fixed
---
- `wicket audit`'s check that a pid file names a running wicket now counts only a process (its own
  thread group), not a number that has since gone to a thread of some wicket process. Its test no
  longer flakes: it now waits until the child it starts is running `sleep`, where it could catch it
  still forked from the test binary ([#663](https://github.com/public/wicket/issues/663)).

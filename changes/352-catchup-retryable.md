---
area: Nodes
type: Fixed
---
- A node that is catching up with its policy feed, holds no valid policy, or briefly can't reach the
  control host now answers model calls and egress with 503 and `Retry-After: 5` instead of 403, so
  harnesses retry. Claude Code read the 403 from the Messages API as an authentication failure and
  ended its turn. A model call is held for up to 3 s first, in case the node catches up. Real
  refusals (never allowed, denied, needs approval) are still 403. Egress log lines and audit records
  are unchanged ([#352](https://github.com/public/wicket/issues/352)).

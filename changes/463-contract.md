---
area: Updates
type: Removed
---
- The ledger drops `operator_messages` (schema 19, a contract step of #463's one inbox): prompts and
  notices have been rows of `messages` since schema 17. The schema floor rises to 17, so builds from
  before one inbox can no longer open the ledger, and `wicket self rollback` refuses to switch to
  them (restore the snapshot taken before the update instead). Rolling back to a build of schema 17
  or 18 is still safe. `wicket self follow` doesn't cross a floor rise: take this build with
  `wicket self update` ([#463](https://github.com/public/wicket/pull/463)).

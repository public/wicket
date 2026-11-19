---
area: Development
type: Added
---
- Standing reach (#572) is in the Lean spec (`Wicket/Standing.lean`): an ask narrowed to its
  evidence pairs each method only with paths a human granted it on, never sets `allow_dangerous`,
  and allows only granted requests to the asked host; a rule allows only paths its globs match; and
  a rule binds only to its principal or zone under the zone definition it was approved under, so
  every zone it binds to decides requests as that one did. Narrowing moved into wicket-core
  (`standing::narrow`, unchanged), and the oracle checks it and `ReachRule::allows` against the
  spec on 10,000 generated cases ([#322](https://github.com/public/wicket/issues/322)).

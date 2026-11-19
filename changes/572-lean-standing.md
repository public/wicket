---
area: Development
type: Added
---
- Standing reach (#572) is in the Lean spec (`Wicket/Standing.lean`): an ask narrowed to its
  evidence pairs each method only with paths a human granted it on, never sets `allow_dangerous`,
  has at most 16 pairs (or one path), and, for evidence paths without glob metacharacters, allows
  only granted requests to the asked host; a rule allows only paths its globs match; and a rule
  binds only to its principal or zone under the zone definition it was approved under, so every
  zone it binds to decides requests as that one did. Narrowing moved into wicket-core
  (`standing::narrow`, unchanged), and the oracle checks it and `ReachRule::allows` against the
  spec on 10,000 generated cases. The `rule_allows` cases whose globs have classes (the literal
  globs of paths with metacharacters) are outside the spec's language and answered `unsupported`;
  a unit test covers them instead ([#322](https://github.com/public/wicket/issues/322)).

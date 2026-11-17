---
area: Development
type: Changed
---
- A pull request fuzzes each selected target in a job of its own, so its fuzzing takes as long as
  its slowest target rather than the sum of them, and replays the corpora once, in a job of their
  own. `Fuzz (short)` passes when the replay and every target did
  ([#323](https://github.com/public/wicket/issues/323)).

---
area: Development
type: Changed
---
- A pull request fuzzes its selected targets in groups of up to three, one job per group, with the
  same 60 s per target and the same corpora replay. The run's jobs then fit the 15 runners it gets
  at once, and the longer jobs no longer wait behind fuzzing. The job is named `Fuzz targets`
  (GitHub adds the group's targets), so a run cancelled before its matrix exists leaves no check
  named after an unexpanded expression.

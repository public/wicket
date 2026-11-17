---
area: Manifests
type: Fixed
---
- A duration whose fractions carry past the largest duration (`18446744073709551615s 500ms 500ms`)
  is refused as too large instead of crashing whatever parses it, a manifest's limits included.
  Found while adding the `time` fuzz target, which fuzzes how wicket parses and prints durations and
  times
  ([#437](https://github.com/public/wicket/issues/437)).

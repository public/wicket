---
area: Dependencies
type: Changed
---
- wicket no longer depends on `humantime`, which was declared unmaintained (RUSTSEC-2026-0542).
  Durations in manifests, operator files and flags (`30m`, `1h 30m`, `24h`, `7d`) and printed
  times (`2026-11-12T19:05:05Z`) are parsed and printed by wicket itself. Every spelling it
  accepted, and everything it printed, is unchanged
  ([#437](https://github.com/public/wicket/issues/437)).

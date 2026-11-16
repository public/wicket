---
area: Development
type: Changed
---
- A clean debug build of wicket-cli is about 7% faster (355 s to 329 s at `-j1` in a 5-CPU box).
  The Cedar crates are now optimized at level 1 rather than 2 in development and test builds:
  together they build in 58 s instead of 82 s, and #51's Cedar differential test takes 64 s
  instead of 55 s. Fewer duplicate crates: rcgen 0.14 and x509-parser 0.18, ulid without its own
  rand, and rusqlite 0.43. The bundled SQLite is now 3.54.1 (was 3.46.0)
  ([#219](https://github.com/public/wicket/issues/219)).

---
area: Development
type: Changed
---
- The Cedar crates are optimized in development and test builds, so `cargo test` runs #51's Cedar
  differential test in half the time (230 s to 119 s on the development host)
  ([#219](https://github.com/public/wicket/issues/219)).

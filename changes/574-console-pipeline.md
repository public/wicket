---
area: Approvals and the console
type: Changed
---
- The console's script is minified when wicket is built, by Oxc's minifier from Rust crates in
  `build.rs`, so `cargo build` still needs no Node: about 25 KB gzipped instead of 38 KB
  ([#574](https://github.com/public/wicket/issues/574)). `WICKET_CONSOLE_UNMINIFIED=1` embeds it as
  written.
- The console also sends a Trusted Types policy, reported but not yet enforced
  (`Content-Security-Policy-Report-Only`), on the way to enforcing it
  ([#739](https://github.com/public/wicket/issues/739)).
- A request card's risk label wraps on a phone instead of pushing the card's time past the edge.

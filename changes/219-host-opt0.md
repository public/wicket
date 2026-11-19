---
area: Development
type: Changed
---
- A clean build is faster (#219). Proc-macros and build tools are back at opt-level 0: optimizing
  every dependency for the tests (`[profile.dev.package."*"] opt-level = 1`) had optimized code
  that only generates code too, since cargo's `build-override` ranks below it. They're listed in
  `Cargo.toml`'s `[profile.dev.package]`, and a determinator test keeps the list complete: every
  proc-macro, and only crates built for the host alone.

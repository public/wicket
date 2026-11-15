---
area: Manifests
type: Changed
---
- The warning an agent gets near its box's memory limit says only what holds for any box (use less
  memory now, save work in progress), no longer advice for building Rust. A zone can add its own with
  `limits.memory_advice`, a one-line note of up to 300 characters appended to the warning, which a
  spawned zone inherits and may replace. examples/self-hosting sets the cargo and make advice there
  ([#348](https://github.com/public/wicket/issues/348)).

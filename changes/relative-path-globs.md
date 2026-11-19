---
area: Manifests
type: Changed
---
- A manifest's reach and forbid path globs must start with `/`, as a standing rule's already do: a
  relative glob such as `tena/repos/**` is refused at load. Subset admission let a parent's `/**`
  admit it, though it matches paths `/**` doesn't. Those paths aren't canonical, so no request could
  use the gap, but it broke the subset invariant the fuzzer and the Lean spec check. A glob such as
  `**/merge` is refused too: write `/**/merge`, which matches the same paths.

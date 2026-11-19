---
area: Manifests
type: Fixed
---
- A manifest's reach and forbid path globs must start with `/`. One without it (`repos/**`) matched
  no request, so as a forbid rule it forbade nothing, and the subset check could admit a child zone
  with one under a parent's `/**` although the parent's glob didn't match what it did (found by the
  manifest fuzzer). Such a manifest is now refused when it loads, naming the glob. No example or
  documented manifest had one.

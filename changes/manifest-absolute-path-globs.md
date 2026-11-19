---
area: Manifests
type: Fixed
---
- A manifest's reach and forbid path globs must start with `/`, and a manifest with one that
  doesn't is refused when it loads, naming the glob. Some such globs matched no request
  (`repos/**`), so as a forbid rule one forbade nothing, and the subset check could admit a child
  zone with one under a parent's `/**` although the parent's glob didn't match what it did (found
  by the manifest fuzzer). Others did match: a reach or forbid rule written `**/…` (such as
  `**/git-receive-pack`) or as a brace or class starting with `/` (`{/a/**,/b}`) worked before and
  is now refused: write it `/**/…` (or list the alternatives each starting with `/`). A hibernated
  agent whose stored manifest has one can't be woken (wake refuses, naming the glob) until it is
  started again from a fixed manifest. No example or documented manifest had one.

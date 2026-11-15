---
area: Programs
type: Changed
---
- A program's digest (`wicket program digest`, `program.digest`) is now its source's tree in
  wicket's content-addressed store: every file's content, name and executable bit, so every checkout
  of the same source has the same digest. Symlinks and special files are still refused. A pin made
  by an earlier build is still accepted, with a warning, while the source is unchanged, and
  `wicket zone pin MANIFEST` rewrites it to the new digest. The store can now hold whole directories
  as trees and check them out again, verified, which hibernation bundles move onto next
  ([#258](https://github.com/public/wicket/issues/258)).

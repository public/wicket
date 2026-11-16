---
area: Identity, spawn and links
type: Changed
---
- A spawned child's supervisor runs in its parent's process
  ([#257](https://github.com/public/wicket/issues/257) slice 4c), on a thread of its own, instead
  of as a `wicket run --parent-run` process of its own. What it prints still goes to
  `children/<run>.log` in the parent's run directory. `wicket run` no longer takes the internal
  `--parent-run`, `--lease` and `--adopt` arguments. A parent's process ending ends its children's
  supervisors (their boxes go on), and the reconciler re-attaches each run, as for any supervisor
  that died.

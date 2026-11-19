---
area: Development
type: Changed
---
- The nightly mutation testing covers a held placed node's money (#326): wicket-placement's
  `held_reservation` and the reconciler's placed pass are two more sets in `ci/mutants.sh`. Two
  new tests kill what survived in the pass: a pass renews a placed node's money for a day (a dry
  run doesn't), and a node gone before its release is reported as already gone, with no bill.

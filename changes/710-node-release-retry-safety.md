---
area: Remote nodes and capacity
type: Fixed
---
- A placed node's release records that it asked the provider to destroy the machine before asking
  (`placement.node_release_destroying`), so a release that finds the machine gone after an earlier one
  that never finished still forgets the files that went with it. Its enrolment is revoked last, only
  once the rest is done, so its name can't be enrolled for another machine until then, and a retry
  touches nothing on a name enrolled again since. A run the release ends is revoked in the same
  transaction, so a run that ends on its own meanwhile isn't revoked; a service instance stopped
  already isn't audited again. A ledger error while finishing releases no longer stops the
  reconciler's lease-end releases of billing nodes
  ([#710](https://github.com/public/wicket/issues/710)).

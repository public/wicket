---
area: Remote nodes and capacity
type: Fixed
---
- Releasing a placed node ends the runs still on it as lost, whether or not they have an identity (their
  agents are handed back as a lost run's are), and stops its service instances only once the provider has
  destroyed it, so a release the provider refuses leaves the node and its services as they were.
  `wicket node release` asks before releasing on a terminal, as shown, unless `--yes`
  ([#710](https://github.com/public/wicket/issues/710)).
- A release whose ledger side fails after the machine is destroyed (ending its runs, stopping its
  services, revoking its enrolment) still does every other step, records which failed
  (`placement.node_release_incomplete`), and is finished by `wicket node release <id>` again or by the
  reconciler, which also finishes a release whose process stopped after the node was marked released.
  A retry decides from the ledger, and touches only the runs, services, files and enrolment from before
  the release ended, never those of a machine given the node's name since. `wicket node release` on a
  released node finishes it or says there is nothing left, and never asks the provider to destroy it
  again. A run that ended on its own during the release keeps how it ended, and a run the release ends
  fires `run.lost` triggers. `wicket node release` asks before destroying a machine the ledger doesn't
  list too ([#710](https://github.com/public/wicket/issues/710)).

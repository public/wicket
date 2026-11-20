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
  (`placement.node_release_incomplete`), and is finished by `wicket node release <id>` again. A run that
  ended on its own during the release keeps how it ended. `wicket node release` asks before destroying a
  machine the ledger doesn't list too ([#710](https://github.com/public/wicket/issues/710)).

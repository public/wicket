---
area: Remote nodes and capacity
type: Fixed
---
- Releasing a placed node ends the runs still on it as lost, whether or not they have an identity (their
  agents are handed back as a lost run's are), and stops its service instances only once the provider has
  destroyed it, so a release the provider refuses leaves the node and its services as they were.
  `wicket node release` asks before releasing on a terminal, as shown, unless `--yes`
  ([#710](https://github.com/public/wicket/issues/710)).

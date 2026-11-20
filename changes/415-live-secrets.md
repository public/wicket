---
area: Secrets
type: Changed
---
- A running box picks up a secret set, rotated or removed after it started, with no restart. An
  `inject` rule's secret is read at each request, so its next request carries the new value, or goes
  without it. On a remote node that takes about 2 s. Before, an optional rule whose secret wasn't set
  at start was dropped for the run's whole life. A required rule whose secret is removed fails its
  host's requests until it is set again. The first request after each change is audited
  (`inject.skipped`, `inject.unavailable`, `inject.available`), once per change. A host with an
  optional rule is now always inspected, and plain HTTP to it is refused, whether or not its secret is
  set ([#415](https://github.com/public/wicket/issues/415)).

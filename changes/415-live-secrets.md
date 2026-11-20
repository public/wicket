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
  set. wicket never injects a credential over plain HTTP, whatever the earlier check found. Protocol
  23: an older node is sent the zone without an optional rule whose secret isn't set, as before
  ([#415](https://github.com/public/wicket/issues/415)).
- A node follows its control host's secret changes more reliably. Each new connection revokes every
  secret released to the run, so a revoke lost on a dying link, or one a restarted control host
  didn't know about, still arrives. A revoke ends the uses a child box shares from its parent, and an
  answer to a fetch that a revoke overtook is not taken. While the control host can't be reached, a
  secret's fetch fails at once for 2 s, instead of making each request wait, and is audited once per
  outage ([#415](https://github.com/public/wicket/issues/415)).

---
area: Identity, spawn and links
type: Added
---
- Public names ([#575](https://github.com/public/wicket/issues/575), step 4b, second part):
  - `wicket reconcile` plans the boxes zone's records from the ledger's live public names: an A
    and an AAAA record at the node's public addresses, and the owner record. It changes only
    records this installation owns, and leaves a name held in the zone by someone else's records
    as a conflict. A name whose label is reserved since it was approved, or whose node has no
    public address, gets no records, and the pass says why.
  - With the `noop` provider, the plan is recorded (`name.plan`, `applied: false`) and nothing is
    published or listed as owned. The same plan isn't recorded again on every pass.
  - `wicket names approve` and `revoke` run the names step at once.
  - A host port a name gave up is free again twice the TTL after its records are gone.
  - Revoking an internal name closes the links other boxes opened by it.

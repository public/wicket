---
area: Identity, spawn and links
type: Added
---
- Public names ([#575](https://github.com/public/wicket/issues/575), step 4b, second part): the
  names reconciler. Each `wicket reconcile` pass ends the names whose lifetime is over
  (`name.lapsed`), and plans the boxes zone's records for the live public names that running runs
  hold: an owner record, A and AAAA for the node's public addresses (SRV once host ports come with
  step 4c). A name on a node without the `names.public.nodes` labels or a public address waits, and
  the pass says why. The plan goes through `names.public.provider`. With `noop`, the only provider so
  far, nothing is published: each new plan is audited `name.plan` with `applied: false`, and no
  record is claimed as created. A provider that writes records each change (`name.record`), and a
  name the zone holds records at that wicket doesn't own is a conflict, left alone
  (`name.conflict`). `wicket reconcile --dry-run` shows the plan.
  A host port a name let go of is freed, twice the TTL later, once none of its records is left.

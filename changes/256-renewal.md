---
area: Approvals and the console
type: Added
---
- `wicket grant renew <id> --ttl` gives a live grant a new end, `--ttl` from now (at most 24h,
  and only later than its end now), keeping its uses. It is a decision through the same function as
  `wicket approve`, and goes on the audit record the same way. A grant a node holds is republished
  in the box's rebuilt token, so the node honours it until the new end
  ([#56](https://github.com/public/wicket/issues/56), [#256](https://github.com/public/wicket/issues/256)).
- A running box's authority is renewed the same way, by its run id. Its run mints the box's block 0
  again with the later end, and its node keeps the box past the old end, never past the run's
  `timeout`. A box nobody renews stops when its authority ends, as before. A re-attached run keeps
  a renewal. After a renewal, the box's spawns are decided by its control host, not on its node.
- An agent renews with the `decide` tool's new `renew` decision (`grant_id`, `request_id` or
  `run`), within its own authority. It may renew a grant it could make now (a descendant's, for
  exactly the asked path, to that run, with a number of uses), or a descendant box's authority. The
  new end is never past its own authority's. The renewal is signed and audited with the chain, as
  its approvals are.
- `wicket grant renew` is a privileged command through `wicketd`, as `wicket approve` is. The
  ledger's schema goes to version 2, an expand step: `runs.authority_until` and `authority_cap`.

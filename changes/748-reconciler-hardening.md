---
area: Identity, spawn and links
type: Changed
---
- The names reconciler is ready for providers that write records
  ([#748](https://github.com/public/wicket/issues/748)):
  - A pass also withdraws the records of a zone that isn't the configured one (after a zone
    change), with the provider that made them. Records another provider made, or left after
    `names.public` was removed, are reported each pass as stranded, and never forgotten.
  - A record the provider that made it no longer lists is forgotten 10 minutes or more after it was
    written, so it holds no name's host port.
  - Each change is audited `name.record` (`state: intended`) in the same write that records its
    records, before the provider applies the plan, once per plan. `name.applied` says how the apply
    ended.
  - A plan the provider's capabilities refuse is refused whole. A provider whose apply isn't atomic
    can say how far it got, and only those changes count as made.
  - Names on two nodes that share a public address wait.
  - A name that ends closes the links other boxes opened by it (#668).

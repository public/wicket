---
area: Operations and audit
type: Added
---
- Kani proof harnesses check wicket-core's decision functions themselves, on bounded inputs, each
  stating the property the way #322's Lean spec does and naming its theorem: host matching and
  covering (`hostCovers_sound`), forbid before reach (`forbid_wins`, `allow_iff`,
  `evaluate_reach_set`, `allow_lower_risk`), canonical paths (`check_plain` is exactly Lean's
  `plainOk`; `canonicalPath_plain`; `upstream_eq`), an agent's descendant chain and grant lifetime
  (`descendantChain_desc`, `not_own`, `agentTerms`), protocol skew and the schema floor, and the
  model budget's arithmetic (carved children never exceed the parent, a slice never leases more
  than is left, nothing overflows). A loom test runs the run's budget counter under every
  interleaving of its node's `Spent` reports, slice leases, model calls and carve-outs.
  `ci/kani.sh` runs them one at a time (each needs under 2 GiB), and CI runs it when a change
  touches the harnessed code (the `kani` suite in `ci/affected.map`)
  ([#325](https://github.com/public/wicket/issues/325)).

---
area: Operations and audit
type: Added
---
- A deterministic simulation of the control host, a node and two boxes (`crates/wicket-sim`, on
  turmoil) runs wicket's own feed, decide path and model budget accounting on a simulated network
  and clock. Partitions, node and control host crashes and restarts, delays and clock skew all come
  from a seed. It checks that no egress request is allowed without a live grant (after revocation,
  and past a grant's lifetime while cut off), and that model spend stays within the run's budget
  across slices. Pull requests that touch the simulated crates run a fixed set of seeds, and the
  nightly run tries 300 more and files an issue for each failing seed with its replay command
  (`WICKET_SIM_SEED=<seed> cargo test -p wicket-sim --test scenario replay`)
  ([#324](https://github.com/public/wicket/issues/324)).

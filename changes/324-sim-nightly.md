---
area: Development
type: Changed
---
- The nightly simulation covers more seeds in about the same time (#324). `ci/sim.sh` runs the
  scenarios' parts four at once (`--threads`), and gives the `update` scenario, which costs next
  to nothing a seed, its own count (`--update-seeds`, default 100000). A scenario's count can be
  set on its own with `WICKET_SIM_SEEDS_<SCENARIO>`.

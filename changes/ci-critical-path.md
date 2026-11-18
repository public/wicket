---
area: Development
type: Changed
---
- A pull request's CI finishes sooner, with the same coverage. The simulation's fixed seeds run as
  eight tests, one per part of a scenario, that nextest runs at once (`seeds_<scenario>_<part>`;
  `ci/sim.sh` runs them all). The TLA+ models and the Kani harnesses each run in three jobs at
  once (`ci/tla.sh --shard I/N`, `ci/kani.sh --shard I/N`), split by each model's or harness's time
  in CI, longest first (`--plan N` shows the split). Acceptance runs beside the gVisor smoke test
  instead of after it. The selection's own tests run beside the selection instead of before every
  job.

---
area: Operations and audit
type: Fixed
---
- An operator can again run `wicket audit --verify --against <export>` through wicketd: the export,
  and `--issuer-jwk`'s key, now go to it as content, as a run's manifest does, so the wicket user
  never reads a path its caller names ([#713](https://github.com/public/wicket/issues/713) review).
  #823 had made these root-only. `--against store:<sink>` is unchanged.

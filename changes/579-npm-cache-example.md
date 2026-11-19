---
area: Examples
type: Added
---
- `examples/services/npm-cache`: a per-node Verdaccio pull-through cache for npm
  ([#579](https://github.com/public/wicket/issues/579), step 3). Installed with
  `wicket service add`, it runs on each node whose boxes use it (`zone.uses: [npm-cache]`), per
  tenant, and fetches public packages under its own read-only reach. Its README says why a box using
  it needs the same reach. `ci/service-e2e.sh` checks it end to end: two boxes install `left-pad`
  through it, the second from its storage, neither reaching the registry itself, and a box without
  the cache's reach isn't linked without a human.

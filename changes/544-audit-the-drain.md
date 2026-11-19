---
area: Updates
type: Added
---
- wicketd's drain now shows in the audit trail. `wicket self update` records `daemon.sighup` when
  it signals wicketd, and each start of wicketd records `daemon.started`, with its build and how
  many commands it followed from the previous image. A drain that never returns, as in #487, now
  shows as a `daemon.sighup` with no `daemon.started` after it.

  `ci/tla-trail.py` turns such records into trails. In CI, `UpdateTrace.tla` tells a hung drain from
  a returning one: the hung drain matches only #487's fail variant, a returning one the merged
  spec. The 10:04 update of 2026-11-18 stays without a trail: its records aren't in the export, and
  that day's builds didn't audit the drain ([#544](https://github.com/public/wicket/pull/544)).

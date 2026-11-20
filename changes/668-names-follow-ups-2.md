---
area: Identity, spawn and links
type: Fixed
---
- More internal-name fixes ([#668](https://github.com/public/wicket/issues/668)):
  - A zone named `wicket.internal`, or ending in it, can't hold names: `<name>.build.wicket.internal`
    would otherwise be read as a name in zone `build`.
  - `connect(box: …)` to a box the caller already reaches by name takes a name of its own, at that
    box's address, instead of reusing the by-name link's name. So a later `connect(name: …)` works.
  - `request_name` on a port the box exposed itself keeps that exposure, and a port two names
    share stays offered until both have moved away (ledger schema 31: `name_exposures`).
  - Clearing names left by ended runs is safe with several wicket processes. It no longer clears a
    name another run took meanwhile, or audits it twice. A name it ends records `run gone`.

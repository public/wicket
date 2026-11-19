---
area: Identity, spawn and links
type: Added
---
- A box whose zone `uses` a per-node service is linked to the service's instance on its node,
  `<name>.wicket.internal:<port>`, and gets the service's `env` (such as `npm_config_registry`)
  ([#579](https://github.com/public/wicket/issues/579), step 3). The instance is found in the
  ledger, as the one wicket started there for the box's tenant, never by a name a box exposed. Using
  a service is having its reach: the link opens on its own only if the box's zone reaches everything
  the service's does, and otherwise needs a human's approval of exactly that link. A service's
  instance offers its port to them when it starts.

# npm-cache: a per-node npm pull-through cache

A [Verdaccio](https://verdaccio.org) cache that runs on every node whose boxes use it
([#579](https://github.com/public/wicket/issues/579)), so their `npm install`s fetch each package
from the internet once per node and tenant, not once per box.

## Install it

```bash
wicket service add examples/services/npm-cache/manifest.yaml
```

Its manifest is read from here at each start, so keep the directory. `wicket reconcile` (its
service runs it every 30 s) starts an instance on a node once a box there uses it.

## Use it

In a box's zone:

```yaml
zone:
  uses: [npm-cache]
  reach:
    - { host: registry.npmjs.org, methods: [GET, HEAD], paths: ["/**"] }
```

- The box gets `npm_config_registry=http://npm-cache.wicket.internal:4873/`, so `npm` and `npx`
  use the cache with no change to the box's own commands.
- Once the instance on its node runs, the box is linked to it. The box's output says
  `npm-cache on node …: linked …`.
- `npm config get registry` in the box shows it. The cache's log, in
  `services/npm-cache/<run>.log` under wicket's data directory, shows each package it fetched, and
  each one it served from its storage.

## Why the box needs the cache's reach

Using a service is having its reach. Through the cache, a box can make it fetch whatever the box
names on `registry.npmjs.org`, and the names a box asks for are themselves a way to send data out.
So a box may use the cache only if its own zone reaches what the cache's does (above: GET and HEAD
of `registry.npmjs.org`). Without that, its link to the cache needs a human's approval of exactly
that link. The cache saves time and bandwidth; it gives no box more than it already had.

## Tenancy

The cache is per tenant: each tenant using it on a node gets its own instance and storage, so what
one tenant installed, or asked for, never shows in another's. `tenancy: shared` would make it one
per node. Only the operator who installs it can choose that, and only by also declaring
`public_only: true` in this manifest, which no agent can set.

## What it can't do

- It can't publish: `publish: $nobody`, and nobody can sign in.
- It can't widen a box's reach.
- Its own reach is GET and HEAD of the public registry, with everything else hidden.

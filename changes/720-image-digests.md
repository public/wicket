---
area: Images
type: Security
---
- The agent image's base images (`rust:1.99.1-slim-bookworm` for the forwarder, `node:22-bookworm-slim`)
  are pinned by digest, so a tag pushed again upstream can't change what `wicket image` builds
  ([#720](https://github.com/public/wicket/issues/720)).

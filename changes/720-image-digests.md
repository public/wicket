---
area: Images
type: Security
---
- The agent image's base images (Rust for the forwarder, Node for the box)
  are pinned by digest, so a tag pushed again upstream can't change what `wicket image` builds
  ([#720](https://github.com/public/wicket/issues/720)).

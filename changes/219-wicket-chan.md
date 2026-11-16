---
area: Development
type: Changed
---
- The control/node channel's protocol is a library crate of its own, `wicket-chan` (the channel,
  node health, a node's secrets, OCI images and registries): it builds and tests without the rest
  of wicket-cli, and the fuzz targets link it instead of compiling the CLI's source files into
  themselves ([#219](https://github.com/public/wicket/issues/219)).

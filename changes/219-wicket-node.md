---
area: Development
type: Changed
---
- `wicket node serve` and its MCP gateway are a library crate of their own, `wicket-node`, with
  what the node shares with the control host: the node's status and its view's types, a spawn's
  plan, the box files read and written without trusting the box, re-executing on a new build, the
  control host's calls on a node's channel, and its half of a node CA's renewal. The node builds
  and tests without the rest of wicket-cli, which re-exports each moved item under its old path
  ([#219](https://github.com/public/wicket/issues/219)).

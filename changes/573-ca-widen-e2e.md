---
area: Development
type: Added
---
- The acceptance job's node flows check that a node's CA is widened at runtime
  ([#573](https://github.com/public/wicket/issues/573)). The check sets the node's CA policy to
  `auto` and runs a box there whose reach names an inspected host the node wasn't enrolled for.
  The box's request works without a `wicket node renew-ca`, and `wicket node ca` and the audit
  (`node.ca_widened`) show the change.

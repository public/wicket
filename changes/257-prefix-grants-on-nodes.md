---
area: Remote nodes and capacity
type: Fixed
---
- A path-prefix grant now covers its whole prefix on a node, as it does on the control host
  ([#257](https://github.com/public/wicket/issues/257)). An approval for "every path under
  `/repos/acme/app/`" covered only the one path that was asked about once it reached the box's node,
  so the box's next request under it was asked about again. The grant now goes in the box's token as
  the prefix it is, and the node covers the directory and every path under it: whole segments of the
  canonical path only, so no `..`, escaped dot or doubled `/` reaches outside it. Protocol 16. A node
  still at 15 is sent the grant for its asked path only, as before; update it with
  `wicket node install <node>`.

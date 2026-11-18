---
area: Remote nodes and capacity
type: Changed
---
- The control host keeps one ssh connection per enrolled node open for 10 minutes after its last use
  and runs every call to the node over it, so a box start on a node no longer pays a fresh ssh
  connection: 0.39 s to 0.05 s measured on one node. Revoking or releasing a node closes it, and a
  channel that gets no answer over a stale connection dials again over a fresh one
  ([#287](https://github.com/public/wicket/issues/287)).

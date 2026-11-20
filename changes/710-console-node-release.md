---
area: Remote nodes and capacity
type: Added
---
- A server `wicket node create` made that a run holds past its lease can be released from the console
  with a passkey (`node_release`), not only with `wicket node release` on the host. The passkey signs the
  server, its lease, the runs and service instances still on it and the runs whose files go with it; a server that changed since it
  was shown is refused. Only an operator whose `operators.yaml` authority covers `capacity` at R4 may. The
  decision is audited first as `placement.node_release_decided`, which `wicket node release` now writes
  too (as root's), then `placement.node_released` with the decision, or `placement.node_release_failed`
  ([#710](https://github.com/public/wicket/issues/710)).
- `wicket node release` releases a placed node with the node's own provider key (the one it was made
  with), not the command line's, takes `--reason`, and stops the node's service instances and revokes
  the runs still on it, as the console's release does. A machine already gone keeps its runs' uncollected
  files on record ([#710](https://github.com/public/wicket/issues/710)).

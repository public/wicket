---
area: Updates
type: Added
---
- An update request approved in the console now also applies for a box on another node. The
  control host fetches the run's `/workspace/out` from the node, as a new read-only `outbox` tree
  (refused if the box made it a link). It finds the artifact there by its sha256 and installs it
  as for a box on the control host. A node older than this build sends the whole workspace instead
  ([#465](https://github.com/public/wicket/issues/465)).

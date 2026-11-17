---
area: Updates
type: Added
---
- Approving an agent's `request_update` in the console installs its build, with no terminal on the
  control host: wicket takes the file with the requested sha256 from the run's `/workspace/out`,
  checks its hash, and runs the blue/green `self update` with its health gate and rollback, then
  the nodes. The confirmation shows the artifact, its size, the commit the agent says it is
  (`request_update`'s new `commit`) and the nodes it reaches, and the agent is told how the update
  ended in a notice. `wicket self apply-update <request>` does the same from a terminal
  ([#465](https://github.com/public/wicket/issues/465)).

---
area: Remote nodes and capacity
type: Fixed
---
- A revoke for a secret that changed (rotated, rebound or removed), lost on a dying link or with a
  node's old process during a self-update, is sent again as the change it was. It now also ends the
  uses the run shared with child boxes its node started while cut off, which kept the old value
  before. The run's holdings mark such a secret, so a supervisor that takes the run over sends it the
  same way ([#415](https://github.com/public/wicket/issues/415)).
- A node's self-update hands its secret cache to the exec only. The new process is named the memfd in
  its own environment, never this process's, and the memfd stays close-on-exec until the exec's last
  step, so no child the node starts meanwhile inherits it. The new process takes the variable out of
  its environment before any other thread starts
  ([#818](https://github.com/public/wicket/issues/818)).

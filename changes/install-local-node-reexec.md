---
area: Updates
type: Fixed
---
- After `deploy/install.sh`, runs on the control host's own node keep their boxes. wicketd's
  restart left the local node's `serve` running the old build, and a run handed over to the new
  build was then stopped. At its start, wicketd now re-executes that serve as its own build
  (SIGHUP, as `wicket self update` does) before it hands runs over. `wicket-reconcile.service`
  now has `KillMode=process`, so restarting it no longer stops the supervisors and the local serve
  that its passes started ([#529](https://github.com/public/wicket/issues/529)).

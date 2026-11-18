---
area: Development
type: Added
---
- `wicket-sim` has a new `update` scenario. While a long-lived run goes on on this host's own node
  and another on a remote node, the control host moves to a new build, by an install's restart of
  wicketd or by `wicket self update`'s re-exec. The scenario covers:
  - old-build supervisors handed over (#477);
  - the local node's serve moved first (#529);
  - the drain (#489);
  - the reconciler service re-attaching runs, and its unit's restart.

  It checks that no box is stopped, no prompt is lost, and the CLI is answered within 10 s. With
  #475's, #487's or #529's fix turned off, a seed finds each bug again
  ([#324](https://github.com/public/wicket/issues/324)).

---
area: Development
type: Changed
---
- The control host's core is a library crate of its own, `wicket-control`: a run's supervisor and
  its box on a node, spawns, hibernation and its stores, transcripts, the authority roots and the
  feed, and what a run needs of nodes (enrolment, placement, leases), grants, operators and policy.
  It builds and tests without the console, the daemon and the commands, which stay in wicket-cli
  with self update; a change to them no longer runs wicket-control's tests. wicket-cli imports
  each moved module under its old name ([#219](https://github.com/public/wicket/issues/219)).

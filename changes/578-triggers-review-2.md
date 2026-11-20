---
area: Long-lived agents
type: Fixed
---
- Triggers on wicket's own events ([#578](https://github.com/public/wicket/issues/578)):
  - **Wakes are scoped.** An agent's wake, recorded before its new run is, now carries the agent's
    zone, name and principal, so a zone filter hears it.
  - **The chain cap counts single chains.** It counts the longest single chain, not every trigger
    that ever messaged the run, so four schedules messaging one agent no longer stop its other
    triggers.
  - **An owner that can't be checked holds the pass.** When a user, group or policy lookup fails,
    the pass stops before the record that trigger would hear, rather than skipping what follows,
    and the skip is audited at most once an hour.
  - **Renewing a lapsed trigger** brings it back from now, as resuming does.

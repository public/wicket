---
area: Long-lived agents
type: Fixed
---
- An agent's `finish` or `hibernate` is no longer lost if the control host restarts before the
  end of its turn. Its harness used to keep running until its timeout. The request is now
  recorded in the ledger when the agent asks, and the supervisor that takes the run over after the
  restart closes the session or hibernates the agent at the end of the turn. The ledger's schema
  moves to 15, an expand step that adds `runs.want`
  ([#444](https://github.com/public/wicket/issues/444)).

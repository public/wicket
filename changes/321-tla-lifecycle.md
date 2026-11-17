---
area: Development
type: Added
---
- Two more TLA+ models, checked by TLC in CI ([#321](https://github.com/public/wicket/issues/321)):
  - `RunLifecycle`, a long-lived agent's activations across control-host restarts: wake,
    re-attach, finish and messages. It finds three gaps in today's code, each a failing variant:
    - an agent's finish is lost across a restart;
    - a message taken just before a restart is lost;
    - a wake during a long outage starts a second box of the agent.
  - `Placement`, placed nodes, their leases and the runs on them. It checks the start-by check
    (#395), admission (#300, #430) and the release hold (#294, #324).

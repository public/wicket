---
area: Long-lived agents
type: Changed
---
- The harness decides its lifetime ([#249](https://github.com/public/wicket/issues/249)): a run
  ends when the agent's process exits, at `limits.timeout`, or when its authority ends. wicket no
  longer closes a session after its first turn, pauses an idle box or hibernates on a timer; the
  agent ends its session with the new gateway tool `finish`, and hibernates with the new `hibernate`
  tool (or the operator's `wicket hibernate`). A message to a hibernated agent still wakes it.
  `agent.idle_timeout` and `agent.hibernate_after` are removed, and so is the agent state `idle`. At
  its timeout a box is stopped, also between turns (it was hibernated instead). The agent is no
  longer told to write `result.json`, which stays an optional output.

---
area: Long-lived agents
type: Fixed
---
- Triggers ([#578](https://github.com/public/wicket/issues/578)):
  - An owner check that can't be made, because the user database or a policy file doesn't answer, skips that firing and leaves the trigger active. Only a definite no pauses it.
  - A wake that `wicket wake` would refuse counts as a failed firing, not a start: the agent's box may still be running, a revoked run in its chain, or no state to wake from.
  - Renewing a trigger no longer moves the minute its schedule fires after.
  - A done timer replaced by a new trigger of its name is recorded as deleted. Done timers aren't counted toward an owner's 100 triggers, and can't be renewed.
  - A firing just after a skipped daylight-saving hour says how many times it stands for.

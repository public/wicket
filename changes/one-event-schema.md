---
area: Approvals and the console
type: Added
---
- The console's session page shows Claude Code runs too: wicket keeps their stream-json as it is
  (and `acp-client.jsonl` for what it wrote to them) and translates both to ACP when the page reads
  them, so a Claude Code run's messages, thoughts, tool calls, plans, prompts, permission outcomes
  and turn ends show as an ACP agent's do. `wicket session` still reads them as stream-json.
- Notifications also tell a device when an agent's turn ends and when a run ends, under their own
  topic and notification, with no more than what happened and the run (the agent's name with
  details on). None about a run whose session you have open in the console
  ([#364](https://github.com/public/wicket/issues/364)).

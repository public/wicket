---
area: Development
type: Fixed
---
- `wicket dev mock-llm` no longer runs its command twice for one prompt when Claude Code adds a
  note of its own after the prompt. Claude Code does this when its MCP connection to wicket's
  gateway dropped between turns, for example during a control-host restart. The mock now decides
  from the last user message, so the restart acceptance check counts one turn per prompt.

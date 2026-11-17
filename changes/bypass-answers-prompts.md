---
area: Agents and harnesses
type: Fixed
---
- A driven Claude Code in `bypassPermissions` (a driven box's default) no longer waits on a human when it still raises a permission prompt (for example for a shell command that writes a file with a heredoc). wicket answers it at once, as the mode says, if wicket's rule allows it (control files, mode changes and questions stay refused), and audits it as `run.agent_prompt` with answer `allow`. Since #363 such prompts became `TOOL` requests, which stalled unattended boxes for hours. In any other mode they are still `TOOL` requests, and `/mode` switching out of `bypassPermissions` asks again.

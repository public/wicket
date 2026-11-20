---
area: Agents and harnesses
type: Changed
---
- A driven harness's tool prompts are answered by the box's node, not the control host (#257 step 8,
  channel protocol 22). The node reads the prompts from the box's output and answers on its stdin,
  so a prompt is answered while the control host is unreachable too. A control file, a mode change or
  a question is refused at once, as before. Any other call is allowed at once in `bypassPermissions`,
  a driven box's default (this supersedes #423; such prompts used to wait on a human, and stalled
  unattended boxes for hours). In any other mode it is allowed by a `TOOL` grant in the box's token,
  each use counted on the node, or it becomes a request for a human, as before. Cut off from the
  control host, a call that needs a request is refused after 2 minutes, so the harness never waits on
  a node that can't ask. Only an operator's `/mode` changes the mode prompts are answered by; nothing
  the box writes does. `run.agent_prompt` audit records now come from the node. A node below
  protocol 22 takes no box whose harness asks before tool calls.

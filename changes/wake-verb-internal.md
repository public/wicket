---
area: Long-lived agents
type: Removed
---
- **`wicket wake` is no longer an operator command.** Wake a hibernated agent with
  `wicket session <agent>` (a prompt, if given, is its first turn), from the console's session
  page, or with a message from another agent, as #249 decided: what wakes an agent is something for
  it to read. `wicket wake` stays as the hidden, internal entry point that each of those starts in the
  background (and that wicket's own tests drive); it is out of `--help`, the CLI reference and the
  docs, and wicket's messages now say `wicket session` where they said `wicket wake` (#253).

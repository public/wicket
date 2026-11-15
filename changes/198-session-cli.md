---
area: Sessions
type: Added
---
- `wicket session <run or agent>` opens a running agent's session in the terminal, as its operator
  ([#198](https://github.com/public/wicket/issues/198)).
  - **ACP agents:** the whole session as the console's session page shows it, through the same
    bridge: messages and thoughts as they stream, tool calls with wicket's policy answers and diffs,
    plans, other principals' prompts, and wicket's escalations, which you decide with `wicket
    approve` or `wicket deny`.
  - **Claude Code agents (stream-json):** their messages, tool calls, results and turn ends, from
    the transcript.
  - **Prompts:** each line you type is the agent's next turn. `/stop` cancels an ACP agent's running
    turn. Ctrl-C or the end of input leaves, and the agent goes on.
  - **One prompt:** `wicket session <run> "…"` sends one prompt and returns when its turn ends
    (`--timeout` stops following it; `--no-wait` returns at once). Scripts that used `wicket say`
    use `wicket session --no-wait`.
  - **Hibernated agents:** opening the session wakes the agent. A prompt is its first turn, and
    without one the command follows the woken run.
  - **Audit:** prompts are `session.prompt`, and attaching and leaving are `session.attached` and
    `session.closed`, all with `via: terminal`, as the console's are with `via: acp`.
  - **Daemon:** it runs through wicketd in the `run` class, as `say` did.

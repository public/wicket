---
area: Sessions
type: Added
---
- wicket drives Claude Code's stream-json control protocol
  ([#363](https://github.com/public/wicket/issues/363)). A driven Claude Code runs with
  `--permission-prompt-tool stdio`. In a mode that asks before acting, wicket answers each
  `can_use_tool` prompt with the rule its ACP client uses: writes to control files, mode changes and
  questions are refused at once. Anything else becomes a `TOOL wicket.internal /tools/<tool>/<digest>`
  request, decided with `wicket approve`/`wicket deny` or in the console (operator authority kind
  `tool`), and the session waits for it. Cancelling a Claude Code run's turn now sends an
  `interrupt` (the console's Stop, and `/stop` in `wicket session`). `/mode MODE` in
  `wicket session` changes the session's permission mode while it runs (`set_permission_mode`).
  `agent.remote.permission_mode: default` with `drive: true` is no longer refused.

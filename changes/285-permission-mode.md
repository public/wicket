---
area: Manifests
type: Added
---
- `agent.remote.permission_mode` sets a remote session's permission mode (`acceptEdits`, `auto`,
  `bypassPermissions`, `default`, `dontAsk` or `plan`, as `claude remote-control --permission-mode`
  takes them), so a Remote Control box can work unattended instead of stalling on prompts in the
  Claude app. It defaults to `default`, as before; an unknown mode is refused, and a harness adapter
  without permission modes refuses any but `default`. wicket's proxies decide what the box can reach
  whatever the mode ([#285](https://github.com/public/wicket/issues/285)).

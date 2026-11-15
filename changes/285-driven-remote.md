---
area: Manifests
type: Added
---
- `agent.remote.drive: true` runs a driven Remote Control box: wicket drives Claude Code as in any
  box (the manifest's task is its first turn; follow-ups, messages and wakes are its next ones; it
  hibernates and wakes), and turns Remote Control on over its stdin (`claude -p` has no flag for it),
  so the session is also in the owner's Claude apps, where they watch it and can send it messages.
  wicket prints and records the session's address, or why Remote Control didn't start. Its
  permission mode defaults to `bypassPermissions`, and `default` is refused, since a driven Claude
  Code asks wicket, not the app. A plain `agent.remote` session still starts when its owner sends
  the first message: the docs now say so. See `examples/remote-driven-box.yaml`
  ([#285](https://github.com/public/wicket/issues/285)).

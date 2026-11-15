---
area: Manifests
type: Changed
---
- `program.on_pending` is gone: a program is an agent without a model, and its zone's
  `escalation.request` defaults to `false`, so a request outside its reach is refused with nothing
  queued. `zone.escalation: { request: true }` makes it a pending request, as `on_pending: wait` did.
  A program `spawn` starts may not ask either, unless its zone says `escalation.request: true`
  ([#255](https://github.com/public/wicket/issues/255)).
- `zone.llm`'s `provider`, `secret` and `upstream` defaults are the harness's: its adapter fills them
  in when the manifest is loaded (for Claude Code, and `acp` with `profile: claude-agent-acp`:
  `anthropic`, `claude-oauth`, `https://api.anthropic.com`), and core and the proxies take them as
  data. The model host the egress proxy always inspects is the route's upstream, and the provider
  profile's own host while the zone has a route. The known ACP profiles are the adapter's too
  ([#255](https://github.com/public/wicket/issues/255)).
- The vault has no default host bindings: `claude-oauth` is no longer bound to `api.anthropic.com`
  by its name. `wicket secret set` and `wicket secret link` bind a harness's default model secret to
  its model host when they store it with no binding, so a secret stored before this change with no
  `--hosts` needs `wicket secret hosts claude-oauth --hosts api.anthropic.com` (`wicket doctor` says
  so). `wicket doctor --image` defaults to the default harness's image without naming it in its help
  ([#255](https://github.com/public/wicket/issues/255)).

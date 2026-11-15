---
area: Manifests
type: Fixed
---
- A woken driven Remote Control box (`agent.remote.drive`) resumes its session in the Claude apps:
  `examples/remote-driven-box.yaml` reaches `POST /v1/sessions/*/unarchive` (and its
  `/v1/code/sessions/*/unarchive` form), which Claude Code calls to reattach before fetching the
  session's bridge credentials again, so the wake no longer leaves it pending for a human and the
  app keeps the same conversation. When a woken box can't reattach and starts a new session, wicket
  says so and prints the new address as loudly as at the start; `run.remote_session` records whether
  it was `resumed`, and the `previous` address when it wasn't
  ([#330](https://github.com/public/wicket/issues/330)).

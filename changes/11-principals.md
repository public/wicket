---
area: Principals
type: Changed
---
- `send_message` names its recipient by principal, not by run: `"parent"`, or an agent's identity
  (`spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>`, which `whoami` and `spawn` now show for the agent
  and its children). A run id is no longer an address. The message goes to the principal's live run.
  If it has none, a hibernated agent is woken to read it, and otherwise wicket holds the message
  for up to 7 days until the principal runs again. A message its run ended without reading goes to
  the principal's next run too, so a named agent is reached across its restarts. Every message is
  audited with the principal it is for, the run it reached, and whether it was held
  ([#250](https://github.com/public/wicket/issues/250)).
- `accept_from` may name single principals as well as zones. `whoami` shows it as
  `accepts_messages_from` (it was `accepts_messages_from_zones`).
- Operators are principals (#11). Each has an identity (`spiffe://<domain>/t/<tenant>/op/unix/<user>`
  on the CLI, `…/op/passkey/<name>` on the console) and an authority, set in
  `<data dir>/operators.yaml`. Without the file every operator may decide anything, as before. An
  approval, denial or renewal outside the operator's authority (its request kinds, hosts or
  highest risk) is refused through the same decide function agents use. The request stays pending,
  and the refusal is audited as `decision.refused`. Decisions record the operator's identity
  (`granter_identity`), as an agent's do
  ([#11](https://github.com/public/wicket/issues/11)).
- A run started from the CLI or the console records its operator's principal id (`principal.sub` in
  its identity), not only the unix user or passkey name.

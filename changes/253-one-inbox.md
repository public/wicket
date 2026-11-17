---
area: Principals
type: Changed
---
- An agent has one inbox (#253). Operators' prompts (from `wicket session`, the console's
  session page and a wake) and wicket's own notices (a box near its memory limit) are now messages
  in the ledger, beside other agents' messages, from the operator's principal id. The ledger moves to
  schema 17 (expand): waiting prompts are copied over on the first open, and the old
  `operator_messages` table stays, unread, until a later release drops it. Three decisions, each to
  keep today's behaviour and trust while recording humans as principals:
  - **One store, two deliveries.** A prompt is still the agent's next turn, with the principal's
    authority. A peer's message is still read with `await_message`, as data. #252 can change how
    either is delivered later.
  - **Unsigned, attested by wicket.** A prompt carries the operator's authenticated principal id
    (from the CLI's peer credentials or the console's passkey) and is audited when it is written.
    Notices are from wicket.
  - **No `accept_from` for operators.** `operators.yaml` decides who may prompt; `accept_from`
    stays a rule for peers.
  The `session.prompt` audit record's `operator_message` is now the prompt's message id (a string).
  ([#253](https://github.com/public/wicket/issues/253)).

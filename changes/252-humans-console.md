---
area: Messages
type: Added
---
- Humans in the agent-to-agent protocol, in the console's API
  ([#252](https://github.com/public/wicket/issues/252)). The passkey's operator
  (`…/op/passkey/<name>`) sends with a new signed action, `send_message`, bound to the recipient,
  the text, its priority and the message it answers, under `wicket message send`'s rules. The
  signature is on the message's audit record. `GET /api/messages` returns its inbox (verified),
  receipts and the agents it may write to, and `POST /api/messages/read` marks its own messages read.
  The console's pages don't show them yet.

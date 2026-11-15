---
area: Messages
type: Added
---
- The agent-to-agent protocol, its first slice, all through the MCP gateway
  ([#252](https://github.com/public/wicket/issues/252)):
  - **Discovery and presence.** A new `principals` tool lists the principals an agent may talk to,
    by the parent/child chain and `accept_from` (theirs, to send; its own, to hear). Each comes with
    its stable principal id, its kind (agent, human) and its state: `running`, `busy` (in a turn),
    `idle` (between turns), `waiting` (in `await_message` or `await_grant`), `hibernated` or
    `offline`. Supervisors report busy and idle, and the gateway reports waiting (`runs.activity`).
  - **Receipts.** Every message carries its sender's principal as its reply address (`reply_to`,
    signed). `send_message` answers with the message's first receipt, and a new `receipts` tool
    follows it: `delivered`, `read`, `held` (why, who can release it, and when it expires),
    `refused` (why) or `expired`. It can also wait until the message is read.
  - **Refusals.** A message the recipient's `accept_from` doesn't allow is refused with a receipt
    that says so, and audited as `message.refused`. So is one dropped at delivery (by the org policy,
    or because it doesn't verify). A box cut off from its control host refuses the same way, on its
    node's audit log.
  - **Replies.** `send_message` takes `in_reply_to`: a reply to a message the recipient sent you
    needs no `accept_from`.
  - **Priority.** `send_message` takes `priority` (`now`, `next`, `later`). The inbox hands out the
    most urgent first, and pushed messages carry it.
  - **Push delivery.** For a harness whose adapter turns it on, the box's node sends each incoming
    message on the MCP session's stream as the harness's notification, `{ content, meta }`, with the
    verified sender in `meta` and the content marked as a peer's data. Claude Code's channels are
    the matching feature, but the image's version (2.1.319) can't take them in a box (`-p` mode
    registers none, and they need a feature flag a box can't fetch). So the Claude adapter leaves
    push off, and `await_message` stays the path.
- Ledger schema 5 (expand) adds `messages.from_principal`, `messages.priority`,
  `messages.in_reply_to`, `runs.activity` and the `message_refusals` table.

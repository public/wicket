---
area: Messages
type: Added
---
- Humans in the agent-to-agent protocol, over the CLI
  ([#252](https://github.com/public/wicket/issues/252)). An operator sends and receives the same
  signed envelopes an agent does, under the same rules, with receipts and audit:
  - **`wicket message send <agent> <text>`** writes to an agent that acts for you (you started it,
    or its chain), whose `accept_from` names you, or that wrote to you (`--in-reply-to`). Anyone
    else is refused, with a receipt that says why, as a peer outside `accept_from` is. `--priority`
    is `now`, `next` or `later`. A hibernated agent is woken to read it.
  - **`wicket message inbox`** lists the messages agents sent you, verified, and marks them read
    (their senders' receipts say so) unless `--peek`. **`wicket message receipts`** follows what you
    sent, and **`wicket message principals`** lists the agents you may write to, with their state.
  - **Agents write to operators.** `send_message` to an operator's principal id now works for the
    operator the agent acts for, and as a reply to one that wrote to it; any other is refused with
    a receipt. The gateway's `principals` lists the agent's own operator, with `may_send_to`.
  - **Signed as an operator.** wicket signs each operator message with a short-lived operator
    identity document (`wicket-operator+jwt`) bound to a fresh key. Its type and envelope header
    are its own, so no check of an agent's identity or envelope (a signed decision, a report)
    accepts one. `wicket audit --verify` checks both kinds.
  - A message grants nothing either way: an agent reads an operator's message as data, and
    `wicket session` remains how an operator prompts an agent.
  - `in_reply_to` must name a message the sender may answer, whichever rule lets the message go,
    and an id over 64 bytes is refused. The inbox cleans everything it shows for the terminal.
    A message is marked read only after it is shown, with its audit record in the same
    transaction, once.
  - Who may message whom is decided by the one rule (`message::relation`): the operator an agent
    acts for stands where a parent does. The org policy's `msg_from` decides operators' messages
    too, by their principal id.
  - A manifest's `accept_from` may not have an empty entry.
  - An operator's message is recorded as `messages.kind = operator-message`, so a previous build
    rolled back to leaves it alone rather than refusing it, and doesn't count it in its
    `audit --verify`.
  - `wicket message` refuses a caller that isn't a human on the CLI.

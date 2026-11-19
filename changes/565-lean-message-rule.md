---
area: Development
type: Added
---
- The message rule (#565) is in the Lean spec (`Wicket/Message.lean`): a message goes to a peer
  only when the receiver's `accept_from` names the sender's zone or principal, and a node that
  doesn't know the sender's principal refuses whatever the control host would. The oracle checks
  `message::relation` against it on generated cases, and a Kani harness checks the Rust over every
  bounded input ([#322](https://github.com/public/wicket/issues/322),
  [#325](https://github.com/public/wicket/issues/325)).

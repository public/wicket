---
area: Messages
type: Changed
---
- Who may message whom is one rule, decided the same way by the control host and by a box's node
  while it's cut off from it ([#257](https://github.com/public/wicket/issues/257)): to a parent or
  a child, to a box whose `accept_from` names the sender or its zone, or as a reply. A box on a
  node cut off from its control host can now answer a message it was given (`in_reply_to`), as it
  can when connected, even if the other box's `accept_from` doesn't list it; before, the node
  refused it. A refusal reads the same wherever it was decided.

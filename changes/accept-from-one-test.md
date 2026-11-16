---
area: Messages
type: Changed
---
- `accept_from` is checked the same way everywhere a sender is let in (the control host's
  `send_message`, the gateway's `principals`, a node's own delivery while cut off): an entry is a
  zone's name or one principal's id (#250), and the field's reference says so. Nothing it accepts
  changes (#253).

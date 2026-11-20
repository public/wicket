---
area: Approvals and the console
type: Changed
---
- The console's Inbox (the status line, the request cards and the problems) is drawn with lit-html,
  the first view of the console's move to it ([#574](https://github.com/public/wicket/issues/574)).
  It looks and acts as before: a card that hasn't changed is the same element across polls, a tap
  just after the cards move is ignored, and the signing sheet and what a passkey signs are unchanged.
  lit-html is committed with the console (no build step, no Node), and the console's modules are
  served from one content-hashed directory with Subresource Integrity.

---
area: Approvals and the console
type: Changed
---
- The console's Agents view and an agent's page are drawn with lit-html, as the Inbox is
  ([#574](https://github.com/public/wicket/issues/574)): the list of runs, Start an agent, an agent's
  head, what it can reach and its activity. They look and act as before, except that a line of an
  agent's activity now stays put when a new record arrives (the list was redrawn), so a "why?"
  opened on it stays open.

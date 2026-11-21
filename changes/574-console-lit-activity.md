---
area: Approvals and the console
type: Changed
---
- The console's Activity view is drawn with lit-html, as the Inbox and Agents are
  ([#574](https://github.com/public/wicket/issues/574)): the log, its filters, recent decisions, and a
  decision's "why?". An opened "why?" now stays open across polls and when new records arrive, in
  the log and on an agent's page alike, and a second tap closes it without asking the server again.
- A "why?" explanation no longer breaks its labels mid-word ("req / ues / t"): each label sits whole
  beside its value, with room inside the box's border.

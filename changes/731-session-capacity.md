---
area: Approvals and the console
type: Fixed
---
- The session page shows a request as the console's cards do
  ([#731](https://github.com/public/wicket/issues/731)): wicket's terms come from the request's
  fields (a capacity ask's lease, an update's build). What the agent wrote (a lease's region and
  reason, an update's commit and reason) is quoted and labelled as its words, never shown as
  wicket's. The request's reason no longer goes out as a tool call's raw input.
- The agent's words sit in an element of their own, clipped to 500 characters, with hidden
  characters removed and their quote marks replaced, so they can't close wicket's quote and write
  terms after it (the console's inbox replaces them too). A capacity ask's reason is limited to
  1000 characters. A capacity or update request is shown once its lease or claims are there (or
  after 5 seconds without them).

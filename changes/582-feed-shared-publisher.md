---
area: Operations and audit
type: Changed
---
- A delta on a node's feed costs each other publisher on the control host about a millisecond,
  whatever the feed's history ([#582](https://github.com/public/wicket/issues/582), step 3). Each
  one applies only the deltas other processes appended, where it opened the feed again. The runs on
  a node in one process (a parent and its children's supervisors, link relays) share one publisher
  for it. At 100 boxes on a node with 10,000 deltas of history, a delta now costs 94 ms of CPU across
  the node's supervisors (33 s before step 3). A renewed feed certificate (`wicket keys certify`, or
  another process) is picked up at the next commit or statement.

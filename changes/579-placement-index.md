---
area: Remote nodes and capacity
type: Changed
---
- A woken agent is placed from the nodes' own reports in the ledger, not by connecting to every node
  ([#579](https://github.com/public/wicket/issues/579), step 2). A node's health report (every 30 s)
  now carries its capacity, as its `Welcome` does. Only a node with no report under 90 s old, or one
  from before this change, is still asked. Each node's health is stored at most every 20 s, by
  whichever of its runs' connections has it first, instead of once per run
  ([#582](https://github.com/public/wicket/issues/582)).

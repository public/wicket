---
area: Operations and audit
type: Changed
---
- Opening a node's feed on the control host no longer replays its whole delta log
  ([#582](https://github.com/public/wicket/issues/582), step 3). A checkpoint beside the log
  (`checkpoint.json`, written every 64 deltas) holds the state at an epoch. An open reads only the
  deltas kept for catching nodes up and applies those after the checkpoint. A checkpoint that doesn't
  match the log is ignored. A publisher keeps only those deltas in memory, not the whole log. The node
  gets one freshness statement per refresh, not one from each run on it. At 100 boxes on a node with
  10,000 deltas of history, a delta cost 33 s of CPU across the node's supervisors, which each opened
  the feed again; it now costs 10 s. The delta log keeps its format, so older builds still read it.
  The protocol and the node are unchanged.

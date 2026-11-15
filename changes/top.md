---
area: Remote nodes and capacity
type: Added
---
- `wicket node top`, on a node as its `wicket` user: a live, read-only view for the node's console.
  It shows the node's identity and CA expiry, whether a control host is connected or the node is cut
  off (and since when), the feed's freshness, and load, memory and disk. One row per box gives its
  state, uptime, CPU and memory from Docker's stats, model requests and tokens, what is left of its
  budget slice, egress allowed and refused, and queued asks. Under them are the last 10 egress
  decisions. `wicket node serve` answers its status on `ctl/status.sock`, beside the control socket:
  names, deadlines and counts, no secrets. `wicket top` gives the same kind of view on the control
  host, across every node, run, pending request and active lease, through wicketd for operators. It
  redraws every 2 s (q quits); `--once` prints one frame, and a stdout that isn't a terminal gets
  plain text cut to 80 columns.

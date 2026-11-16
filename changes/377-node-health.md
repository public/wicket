---
area: Remote nodes and capacity
type: Added
---
- Node health ([#377](https://github.com/public/wicket/issues/377)): every node reports its data
  directory's disk and inodes, memory, feed freshness, out-of-memory kills and failures to persist its
  own state to the control host every 30 s (protocol 11). `wicket top` shows a DISK column and the
  alerts, `wicket node top` and the console show the report, and the console pushes to operators when
  a node's disk passes 85%, its feed is stale for more than 5 min, a box is killed for memory, or it
  can't persist its state (and when the control host's own disk passes 85%).
- Admission control: a node refuses to start a box whose memory limit doesn't fit in what is actually
  free (less what running boxes may still take, less a margin), or when its disk is below the floor,
  and says why. Waking an agent places it only where there is room.
- A node keeps a disk reserve for its own state, released when it can't write, and a feed that
  couldn't be persisted recovers by itself once space frees, without a restart.
- Collection tracking: the ledger records when a run's work was collected (files fetched, outbox taken,
  a push allowed, a hibernation bundle). A remote node keeps an uncollected workspace until
  `wicket node forget <run> --force`, which is audited.
- A zone's volumes are each run's own cache unless marked `keep: true`: a cache starts empty and is
  deleted when the run's work is collected (or its `retention` after the run ends, default 7 days). A
  kept volume is shared by the zone's runs as before, and with a `retention` it is deleted once unused
  that long. Mark the volumes your runs share `keep: true`. Volumes from a control host before this are
  kept as before. A per-box volume size cap isn't possible on bind mounts (see the limits).

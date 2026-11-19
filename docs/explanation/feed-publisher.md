# One feed publisher per node

Design note for [#582](https://github.com/public/wicket/issues/582) step 3. It covers how the runs on a
node share the node's policy feed on the control host, what it cost before, and what changes.

## Before

Every run's supervisor is its own process, and each opened its own `Publisher` on
`<data dir>/nodes/<name>/feed/deltas.jsonl` (`noderun::SharedFeed`). Every commit and every statement
took `feed.lock` (an `flock`), and if the log had grown since the process last looked, it **opened the
feed again**: it read the whole log, parsed every delta, replayed it and compiled every token still
held. The log was compacted only when no box held authority from it (a new generation, which needs the
feed root at hand), so on a busy node it was never compacted. Each process also kept the whole log in
memory for catch-up, and signed its own statement every refresh.

So one append on a node with `b` boxes made `b` processes each replay a log of `L` deltas and compile
`b` tokens: about `b · (L + b)` work per append, and appends grow with `b`. That is the roughly cubic
term in #582.

## After

The node's decisions, the wire protocol (no bump) and the ledger (no schema change) are unchanged.
The delta log keeps its format and is still append-only, so an older build can still read it.

1. **Each publisher applies deltas instead of replaying** (`Publisher::refresh`). A publisher knows the
   log's length and inode as it last read or wrote it. Under the lock, it reads only the bytes appended
   since, checks that each delta extends the chain (feed, epoch, previous head, version), and applies
   them; only the tokens those deltas put are compiled. A log that was replaced or truncated (a new
   generation, a restore), or a delta under a newer certificate, makes it open the feed again, as
   before. A torn last line under the lock is a crashed append and is dropped, as on open.
2. **Checkpoints: compaction while boxes live** (`checkpoint.json`, every 64 deltas, written
   atomically under the lock). A checkpoint is the state at an epoch (a `Snapshot`, unsigned like the
   log: it is the control host's own file), where that epoch's line ends in the log, and where the
   deltas kept for catch-up begin. Opening the feed reads only from there: the kept deltas are checked
   to chain up to the checkpoint's head, the state is loaded from the checkpoint, and only the deltas
   after it are applied. A checkpoint that doesn't match the log (another head, offsets past the end
   or mid-line, another node's, another version) is ignored and the whole log is replayed, which also
   writes a new checkpoint. `read_state` (the console, effects) uses the same path, read-only.
3. **A bounded tail**: a publisher keeps the last `retain` deltas and their heads (it kept the whole
   log). A node at most `retain` epochs behind is still caught up with deltas; one further behind gets
   a snapshot, as before.
4. **One statement per node per refresh.** `Publisher::tick` is due a refresh after the newest
   statement signed for the feed by any publisher (the shared `feed/issued` time), not after its own.
   Every run's connection reaches the same replica on the node, so one statement per refresh is enough;
   `b` processes no longer sign `b`. A connection's catch-up still signs its own statement.
5. **One publisher per node per process** (the second PR): `SharedFeed::open` hands every run in a
   process the same publisher for a node (children's supervisors and link relays share their parent's
   process). With #582 step 5 (supervisors as tasks in a few processes) that becomes one, or a few,
   per node. Several processes stay correct: they serialise on the lock and follow each other's appends
   by (1).

### Batching

Changes are already batched per caller (a grant sync, a start with its dead tokens' drops, a
revocation's ids, each one delta). Batching across runs would make one run's delta reach the node over
another run's connection; if that connection is down, the node waits for a gap and a catch-up. That is
a change to the revocation path I don't want without a single owner of the node's connection (step 5).
The numbers below show the append itself (one fsync under the lock) isn't the cost.

### Rollback

The log's format is unchanged and still complete, so an older build opens it as before and ignores
`checkpoint.json`. A build with this change that finds a checkpoint an older build has made stale (the
log grew under it) checks it against the log and, since the log only grew, still uses it and applies
the rest. Truncating the log behind the checkpoint (to bound its disk use, not its replay) is a
contract step for a later release, after this one has stopped anything from needing the whole log.

## Numbers

`cargo run --release -p wicket-feed --example feed_scale -- <boxes> <history> <measured>`: one node's
feed with `boxes` publishers (as `boxes` supervisors), a history of churn (each run puts its token,
re-publishes it with three grants, then drops it), then each append followed by every other publisher
catching up as `SharedFeed::lock` does. Release build, this container, medians.

| boxes | history (deltas) | one append, every publisher catching up: before → after | one publisher's catch-up | opening the feed |
|---|---|---|---|---|
| 10 | 2,000 | 463 ms → 8.3 ms | 50 ms → 0.9 ms | 52 → 43 ms |
| 30 | 2,000 | 2.0 s → 26 ms | 66 ms → 0.9 ms | 68 → 47 ms |
| 100 | 2,000 | 11.5 s → 102 ms | 113 ms → 1.0 ms | 113 → 178 ms |
| 100 | 10,000 | 33.4 s → 94 ms | 327 ms → 0.9 ms | 336 → 99 ms |
| 300 | 10,000 | not run before (minutes) → 290 ms | 0.9 ms | 253 ms |

- *After* is with `refresh` (the second PR). With only the checkpoints (each process still opening
  the feed again after every append, now from the checkpoint), 100 boxes and 10,000 deltas of history
  cost 10.1 s per append (`feed_scale … reopen`).
- An append now costs the node's publishers about 1 ms each, whatever the history: what is left is
  compiling the one token the delta put (Biscuit verification). It still grows with the boxes on the
  node, `b` times, not `b · (L + b)`. In one process (step 5) that is once.
- Opening the feed costs the deltas kept for catch-up (`retain`, default 1,000) and compiling the
  tokens held, not the history. With 2,000 deltas the two are about even; at 10,000 it is a third.
- Statements: `b` processes signed `b` statements per refresh (5 s); now one.

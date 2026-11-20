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
   before. A torn last line under the lock is a crashed append and is dropped, as on open. A
   publisher that hasn't read what was appended since refuses to commit (its delta would fork the
   chain on a stale head), so a caller that skips `refresh` fails closed.
2. **Checkpoints: compaction while boxes live** (`checkpoint.json`). One is written, atomically
   and under the lock, at every epoch that is a multiple of 64, by whichever publisher commits that
   epoch: one per 64 deltas for the feed, however many publishers share it. A checkpoint is the
   state at an epoch (a `Snapshot`, unsigned like the log: it is the control host's own file) with
   its hash, where that epoch's line ends in the log, and where the deltas kept for catch-up begin
   (at least the checkpoint's own). Opening the feed reads only from there: the state must match its
   hash, the kept deltas must chain up to the checkpoint's head, and only the deltas after it are
   applied. A checkpoint that doesn't match (a damaged state, another head, offsets past the end or
   mid-line, no delta kept, another node's or version) is ignored and the whole log is replayed,
   which writes a new one. A checkpoint that can't be written is logged and tried at the next
   multiple: only the next open is slower. `read_state` (the console, effects) reads the same way.
3. **A bounded tail**: a publisher keeps the last `retain` deltas and their heads (it kept the whole
   log). A node at most `retain` epochs behind is still caught up with deltas; one further behind gets
   a snapshot, as before.
4. **One statement per node per refresh.** `Publisher::tick` is due a refresh after the newest
   statement signed for the feed by any publisher (the shared `feed/issued` time), not after its own.
   Every run's connection reaches the same replica on the node, so one statement per refresh is enough;
   `b` processes no longer sign `b`, and a process just started doesn't sign one at once. A
   connection's catch-up still signs its own statement.
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
the rest. The log still grows on disk on a node that is never idle (an idle one starts a new
generation past `WICKET_FEED_COMPACT_BYTES`, as before). Truncating it behind the checkpoint (to bound
its disk use, not its replay) is a contract step for a later release, after this one has stopped
anything from needing the whole log: a follow-up issue.

## Numbers

`cargo run --release -p wicket-feed --example feed_scale -- <boxes> <history> <measured> [reopen]`:
one node's feed with `boxes` publishers (as `boxes` supervisors), a history of churn (each run puts
its token, re-publishes it with three grants, then drops it), then `measured` appends, each committed
by the next publisher in turn after catching up, and followed by every other publisher catching up as
`SharedFeed::lock` does. Release build, this container; median / p99 / max.

*Main* is main's `publisher.rs` with the harness's `reopen` path (open the feed again whenever the
log's length moved, as `SharedFeed::lock` did), built in a worktree of main with the `refresh` path
and the `Refreshed` and `checkpoints_written` uses taken out of the example, the only parts main
lacks. *#632* is `refresh` (what #634's `SharedFeed` does).

One append, every other publisher catching up:

| boxes | history | main | #632 |
|---|---|---|---|
| 10 | 2,000 | 465 ms / 1.1 s / 1.2 s | 9.3 / 16.8 / 18.7 ms |
| 30 | 2,000 | 3.3 s / 4.9 s / 5.3 s | 26.7 / 40.6 / 44.9 ms |
| 100 | 2,000 | 11.8 s / 12.5 s / 12.5 s | 87 / 119 / 119 ms |
| 100 | 10,000 | 32.6 s / 33.2 s / 33.2 s | 92 / 151 / 164 ms |
| 300 | 10,000 | not run (minutes) | 283 / 406 / 408 ms |

One publisher's catch-up after an append: main 50 ms (10 boxes, 2,000 deltas) to 324 ms (100 boxes,
10,000 deltas) median, up to 626 ms; #632 about 0.9 ms median, 1.3–1.9 ms p99, at most 20 ms.

The commit itself (the fsync, and the checkpoint at every 64th epoch): #632 2.5–3.0 ms median, at
most 22 ms (10 boxes, the commit that wrote the checkpoint). Checkpoints written: one per 64 appends
in every run, however many publishers commit in turn (10, 30, 100 and 300).

Opening the feed: main 55 / 66 / 116 / 345 ms (10, 30, 100 boxes at 2,000 deltas; 100 at 10,000);
#632 28 / 47 / 97 / 99 ms, and 237 ms for 300 boxes.

- With only the checkpoints (#632's open, but each process still opening the feed again after every
  append, `… reopen`): 100 boxes, 2,000 deltas, 11.0 s; 10,000 deltas, 9.9 s. The open is bounded
  by the kept tail (`retain`, default 1,000 deltas) and the tokens held, not the history.
- An append now costs each other publisher on the node about 1 ms, whatever the history: what is left
  is compiling the one token the delta put (Biscuit verification). It still grows with the boxes on
  the node, `b` times, not `b · (L + b)`. In one process (step 5) that is once.
- Statements: `b` processes signed `b` statements per refresh (5 s); now one.

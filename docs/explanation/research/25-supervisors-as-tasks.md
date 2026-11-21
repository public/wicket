# 25 — Supervisors as tasks in a few processes

Research date: 2026-11-20. Scope: [#582](https://github.com/public/wicket/issues/582) step 5. It
covers moving a run's supervisor from its own OS process into a task inside one of a few
long-lived supervisor processes, with one channel per node, periodic writes batched in shared
transactions, and a sharded, event-driven reconciler. It is a design only, with no code changes.

Context:
- #582 (the analysis and its order of changes): steps 1–4 are merged (step 4, #689: file and task
  limits, a small runtime per supervisor);
- [the feed publisher note](../feed-publisher.md) (step 3, which left cross-run batching to this
  step);
- [one decision path](../one-decision-path.md) (#257: only the node decides);
- research [24](24-control-plane-ha.md) (#151–#153: runs live on their node, bounded node autonomy,
  the fence);
- [updates](../updates.md) (supervisors are killed and adopted on an update);
- `crates/wicket-control/src/{run,noderun,spawn,hibernate}.rs`, `crates/wicket-cli/src/reconcile.rs`.

Confidence tags, as in note 24: **[H]** verified against the code at `main` (2026-11-20, after
#682 and #692); **[M]** measured elsewhere or partly checked; **[L]** inference or estimate, not
measured.

Reviewed twice, 2026-11-20. This version takes in both reviews' liveness, authority and blast-radius
fixes (§3). It lists what is still to decide in §8 and the open items in §9.

---

## 0. Summary

- **What a supervisor is now.**
  - Every run has a `wicket run`, `attach`, `wrap` or `wake` process on the control host [H].
  - It holds an ssh session to its node, multiplexed over one ssh master per node.
  - It opens its own ledger connection and runs its own audit writer thread and audit-sink exporter
    thread.
  - It opens its own publisher on its node's feed: one per node per process since step 3.
  - It runs about ten timers between 250 ms and 600 s.
  - The node decides everything (#257). What is left on the control host is bookkeeping, plus
    relaying the run's output and answering its gateway calls.
- **What costs, per box, at 10,000 boxes.** Each cost is paid once per run even when nothing
  happens:
  - a process and its threads;
  - an ssh session, and a `wicket node attach` process on the node;
  - a ledger connection polling `PRAGMA data_version` four times a second;
  - a feed lock and refresh every second;
  - an agent's claim written every 5 s, in its own transaction;
  - a token compiled by every publisher on the node for each delta.
  - Each is cheap. Together they grow with boxes, not with work. Step 4 (#689) raised the
    limits these hit; this step removes most of them.
- **Proposal: `wicket supervise`.**
  - A few long-lived **supervisor hosts** each run many runs as tasks. Runs are sharded **by node**,
    so each node has exactly one host and one channel.
  - Each host holds its shard under a **lease with an epoch**. The epoch is a grant the control host
    signs, and once node links exist the node checks it and refuses a lower one. Every ledger write
    carries it. Before node links, a SIGKILL before any hand-off is the fence. Either way, a stalled
    host that comes back can't take runs back (§3.1).
  - Inside a host, a run task is today's supervisor loop, harness adapter and all. What a host shares
    is what doesn't depend on the run:
    - the ledger and its change watch;
    - a **periodic writer** that batches heartbeats and presence into one transaction a tick
      (nothing that carries authority);
    - one **node link** per node, which multiplexes every run's frames;
    - the node's feed publisher;
    - a per-shard **reconciler** driven by events, with a slow level-triggered pass as a backstop.
- **What doesn't change.** Each of these still holds as it does today; §3 says why:
  - the node decides;
  - block 0's end is the box's authority (#153);
  - `ctl/authority.json` fences a wake;
  - one supervisor per run;
  - a supervisor's death leaves its box running.
- **What gets worse: the blast radius.** A host that crashes takes its whole shard's supervisors at
  once, and every box on its nodes depends on it for a fresh feed.
  - The design bounds the shard (§3.3), brings node links and feeds up first on a restart (§3.2), and
    adopts a crashed shard in safe mode, bisecting to find a run that crashes it (§3.4).
- **Estimated gains** at 10,000 boxes on 100 nodes [L]: see §6 for the arithmetic. They need measuring
  before and after, with a scale harness (§7).
  - processes on the control host: from 10,000 to about 8;
  - processes on each node: from about 100 `wicket node attach` to 1;
  - ssh sessions: from 10,000 to 100;
  - heartbeat and presence write transactions: from hundreds a second to about 8;
  - feed lock ticks: from 10,000 a second to 100;
  - token compiles per feed delta: from 100 to 1.

---

## 1. Today: what one supervisor does

This section is from the code at `main` [H].

| Work | How often | State | Ledger writes |
|---|---|---|---|
| Start: run row, owner, lease, identity, token mint, feed `PutZone`, `ctl/authority.json`, trees, image, `Start` (`run::run_to_end`, `noderun::start`); placement with `--node` (#579) happens inside it | once | `ctl/run.json`, `ctl/authority.json`, feed files | `runs`, `agents`, `identities`, `placements`, audit |
| The node channel: an `ssh … wicket node attach` session (`Via::Ssh`), with a handshake scoped to the run; one `node attach` process on the node per session | for the run's life; reconnect backoff 0.5–5 s | `Progress` (memory), `ctl/link.json`, `nodes/<n>/sessions/*` (#692) | `node_feed_at` on `FeedStatus` |
| Feed statement tick: takes `feed.lock`, refreshes other processes' deltas, signs if due | every 1 s | publisher (memory) | none |
| Grant sync, behind `ChangeWatch` (step 2) | every 250 ms; a full sync every 10 s | grants published/live | `grants` (handed, published), `node_ca_wants` |
| Revocations, node status, node certificate and CA | every 1 s, on change | node cert | `node_certs`, audit |
| Budget slices, secret revocations | every 2 s | `llm::Budget`, `ctl/holdings.json` | none |
| Run loop tick: presence, prompts, turn cancels, mode changes, the operator's hibernate | every 1 s while stdin is open | | `runs.activity`, `messages`, `turn_cancels`, `mode_changes`, audit |
| Progress | every 3 s | `ctl/progress.json` | none |
| Agent heartbeat: usage, `claim_until = now + 30` | every 5 s, agents only | | `agents` |
| Identity rotation (half the 600 s TTL), chain revocation check | every 2 s / 300 s | | `identities`, `identity_history`, audit |
| Quota renewal | every 600 s | | `grants` |
| Node health (one row per node, step 2) | at most every 20 s per node | | `node_health` |
| Frames: output (deduplicated, acknowledged), events, asks, secret fetches, spawns, gateway calls, node audit, `MessageRead` | as they come | transcript, `agent.stderr.log` | `requests`, `messages`, `audit`, `node_audit_heads` |
| Output relay: stdout parsed line by line (harness events, ACP, remote-session URL) into `transcript.jsonl` | per line | transcript | none |
| Audit writer thread (batches 512 / 2 ms); audit-sink exporter thread (1 s, its lease 30 s) | continuous | | `audit`, `audit_export` |

**Authority renewal (#56) is a decision, not a timer.** An operator or an agent decides it, which
writes `runs.authority_until`. The run's next grant sync re-mints block 0 and publishes it.

**Who starts supervisors** [H]:
- `wicketd` starts the CLI's runs as its children;
- the console (`launch_detached`) starts runs from the UI;
- the reconciler (`spawn_attach`, a detached `wicket attach`) adopts runs;
- triggers and messages start wakes (`trigger_wake`, a detached `wicket wake`);
- services start their runs.

A child's supervisor already runs as a thread in its parent's process, on a current-thread runtime
under `catch_unwind` (`spawn.rs:113-150`, slice 4c of [one decision path](../one-decision-path.md)).
That is this design in miniature, and the place to start (§5).

**One supervisor per run** is held two ways [H]:
- `ctl/supervisor.lock`, a non-blocking `flock` per run;
- `runs.owner`, which is `<machine-id>:<pid>:<start ticks>`.

The reconciler judges `runs.owner` alive from `/proc/<pid>/stat`, and only on the same machine
(`wicket-home/src/owner.rs`). There is no heartbeat for a run, only for an agent
(`agents.claim_until`).

**When a supervisor dies** [H]:
- the box goes on running;
- the next reconcile pass (every minute) sees the owner dead;
- it lists the node's runs through a `nodecall::Link`;
- it either adopts the run with a detached `wicket attach`, or ends it as `lost`.

An update SIGKILLs every supervisor on purpose and relies on this ([updates](../updates.md)).
#688 (in review) stops a run's box after its takeovers have failed 5 times. §3.4 says how that
must count failures once a host holds many runs.

---

## 2. The design

### 2.1 What moves where

```
today                                   step 5
─────                                   ──────
wicketd ─┬─ wicket run (run A) ─ssh─┐   wicketd ─── wicket run (client: start, stream, exit code)
         ├─ wicket run (run B) ─ssh─┤                    │ asks
console ─┼─ wicket run (run C) ─ssh─┼─ node 1           ▼
reconcile┴─ wicket attach (D) ─ssh─┘   wicket supervise #k, epoch e  (shard: nodes 1..n)
                                          ├─ run tasks A, B, C, D … (today's loop, per run)
                                          ├─ node link 1 ──── one channel, epoch e ──── node 1
                                          ├─ node link 2 ──── one channel, epoch e ──── node 2
                                          ├─ feed publisher per node (as today)
                                          ├─ ledger: one writer, a bounded reader pool, change watch
                                          ├─ periodic writer (one transaction a tick)
                                          ├─ lease thread (its own small transaction)
                                          └─ shard reconciler (events; slow pass)
```

- **`wicket supervise`** is a new long-lived process. There are a few of them, all on the control
  host's one machine in this version.
  - wicketd starts them (§5.2), as the `wicket` user, under step 4's unit limits (#689).
  - Each owns a **shard**: a set of nodes, and with them every run placed on them.
  - It holds the shard under a lease with an **epoch** (§3.1).
- **A run task** is today's per-run code, `run_to_end` and `noderun`'s `manage` and `session`, on the
  host's runtime instead of its own. What stays per run:
  - the harness adapter, the transcript, the ACP client;
  - `Progress`, the budget, `ctl/*`;
  - the run's identity, its token issuer, and its gateway calls.
  - It doesn't open its own ledger, write its own heartbeats, dial its own node or sign statements;
    it asks the host's shared services.
  - Each task runs under `catch_unwind`, as a child supervisor does today. §3.5 says what that does
    and doesn't contain.
- **Placement happens before the hand-off.** Today placement runs inside `run_to_end` (#579). In step
  5, wicketd places the run (reserving its room) and then gives it to the host that owns the chosen
  node's shard. A host never places.
- **`wicket run` becomes a client** when the daemon is installed.
  - It asks wicketd to start the run, and wicketd hands it to the host whose shard holds the run's
    node.
  - The client then streams the run's output from the host and returns its exit code, as wicketd
    relays a child's exit code today.
  - Its SIGTERM or Ctrl-C asks the host to stop the run, keeping today's meaning: the box is stopped
    and the status is `interrupted`.
  - The client path through a host restart (stdin, reconnecting, the exit code) is an open item
    (§9).
  - Without the daemon (development mode, `--node` on a laptop), `wicket run` keeps running its run
    in its own process, as today. That is a host of one run, the same code.
- **The console, triggers and services** ask a host to start or wake a run, through wicketd, instead
  of spawning a detached process.

### 2.2 One channel per node

- A host has one **node link** per node in its shard: one connection (one ssh session, one
  `node attach` process on the node) over which every run on that node talks.
- **The node-link protocol (proposed; the first free version when it's built, 21 or later, since 20
  is #578's webhook intake): `Run { run, frame }`.**
  - It wraps today's per-run frames, so `Msg::Data`, `Started`, `Exited`, `Call`, `Ask`, `Audit` and
    the rest are unchanged inside it.
  - The handshake is scoped to a host and carries its **shard grant** (`scope: "host:<k>"`; §3.1):
    the epoch, signed by the control host. The welcome already lists the node's runs.
  - The link routes each run's frames to its task, and a task's frames out over the link. The node
    side, `wicket node attach`/`serve`, already serves many runs and gains the demultiplexer. Some of
    the node's code assumes a run's scope; §9 lists it.
  - **A node below that version** gets today's channel per run from the same host, so a mixed fleet
    works within the skew. Feed deltas are batched across runs only on node links.
- **Node-wide messages go once per node.** Today `FeedStatus`, `Health`, statements, catch-ups, the
  node certificate and the node CA are handled per run, deduplicated after the fact; the 20 s health
  write is one example.
- **Flow control.** One run's output must not stall another's, and a large frame must not hold up a
  `Kill`.
  - Each run's `Data` keeps its own offsets and acknowledgements as today.
  - Control frames (revocations, `Kill`, statements) go first.
  - How the link schedules frames both ways, and how large frames such as a 16 MiB feed snapshot are
    split, is open (§9, item 8).
- **Revocation latency doesn't get worse.**
  - A revocation is a feed delta. With one owner of the node's connection, the host can batch deltas
    across runs on a node link: the feed publisher note left this for step 5, because without
    a single owner one run's delta could reach the node over another run's dead connection.
  - If the link is down, the node treats it as it treats a lost session now: the feed's TTL and
    bounded autonomy decide (§3.2).
- **`MaxSessions` stops mattering.** It is one session per node per host, so step 4's 512 (#689)
  becomes a ceiling nothing reaches.

### 2.3 Periodic writes in shared transactions

- **The periodic writer** is one task per host, and every run task's routine writes go through it:
  - agent heartbeats (`renew_agent_claim`, usage);
  - presence (`set_run_activity`);
  - each task's progress heartbeat (§3.4: a task that stops making progress is caught by it).
- **What the periodic writer does not take:**
  - The host's own lease. It is renewed in its own small transaction on a dedicated thread (§3.1), so
    a stalled batch can't lapse it.
  - Quota renewals. They move a grant's `expires_at`, which is authority, so they stay immediate
    (below).
  - `ctl/progress.json`. It stays a per-run file written every 3 s; nothing in the ledger depends on
    it.
- **Batch rules:**
  - **One transaction a tick (1 s)**, `BEGIN IMMEDIATE`, with **a savepoint per item**. An item that
    fails (an agent superseded, a run ended) fails alone and its caller is told; the rest commit.
  - **Bounded.** At most 2,000 items or 50 ms of work a transaction; what is left goes in the next
    tick, oldest first.
  - **Conditional on the shard.** Every item is written only while the run's `runs.host` is this
    host and the shard's epoch is this host's (§3.1). An item refused for that is dropped, and its
    task told to stop.
  - **A failed batch** (the transaction can't be taken or committed: the ledger busy past its
    timeout, the disk full) is retried at the next tick with the same items, and counted. No item
    is reported done until its transaction commits. A caller that needs the write within a deadline
    (an agent claim, 30 s) sees its item still pending and treats it as a write that hasn't landed,
    as it would a failed write today.
  - **Nothing authority-bearing is batched.** These stay immediate, in their own transactions, as
    today:
    - `runs.authority_until`, a write-ahead before block 0 is re-minted (#56);
    - `ctl/authority.json`, written durably before a start or a renewal reaches the node (#153);
    - a granted request's audit commit, which already waits for its batch;
    - a run's start, already one transaction (step 2);
    - a quota renewal (`renew_quota_grants`: a grant's `expires_at`);
    - asks, messages, a grant handed to a node;
    - the end of a run.
- **Timing.** An agent's claim still lasts 30 s from its write and is still asked for every 5 s, so
  the batch adds at most a tick (1 s) to its age. That is far inside the 30 s, and the fence doesn't
  depend on it (§3.2).

**One change watch per host.**
- One task reads `PRAGMA data_version` and the change counters for every topic a supervisor waits
  on:
  - grants (with standing reach and renewed authority ends);
  - revocations (with node status and node certificates);
  - node CAs;
  - turn cancels and mode changes (asks).
- It wakes only the tasks whose topic moved: for grants, the runs whose rows changed, by a `grants`
  row's `run` and `scope` (step 1 indexed both).
- Secret revocations (`secrets_changed`) and message delivery aren't behind a counter yet. They are
  polled per task as today until they are (§9).
- The 10 s full sync per run stays as the backstop, staggered across tasks, so a host doesn't do
  them all in the same second.

### 2.4 A sharded, event-driven reconciler

Today one `wicket reconcile` runs every minute under a host-wide lock [H]. Each pass:
- lists every node's runs whose owner is dead;
- lists Docker boxes on every node over ssh;
- decides adopt, end or wait.

Proposed:
- **Each host reconciles its own shard**, with events:
  - a node link's welcome (its runs list), and its loss;
  - a run task's end, panic or watchdog stop (§3.4);
  - the ledger's change counters for runs.
  - The same rules apply as now (`reconcile::runs`): adopt if the node lists the box, end as `lost`
    if it doesn't, wait while the node is unreachable and the run is fenced. Adoption is a new task in
    the same process, not a spawned `wicket attach`, and it is backed off per run (§3.4).
- **Shard hand-off is on the fast path, and wicketd alone does it.** wicketd starts every host
  (§5.2), so it is the one starter for a dead shard too. When a host's process exits (wicketd reaps
  its child), or its heartbeat has been silent and its lease has lapsed alone (§3.1), wicketd:
  1. takes the shard in the ledger (a new epoch);
  2. kills the old host, if it is still there;
  3. starts a fresh, isolated host for the shard.
  It does this at once, without waiting for a slow pass (§3.2 gives the timeline). A live host never
  takes another's shard: shards aren't merged, so the 2,000-run bound holds.
- **The global `wicket reconcile` keeps what isn't per shard**:
  - triggers, leases and machines (#579), placed nodes, signers, services;
  - the ledger's upkeep;
  - a check that every shard has a live host, which it reports (`supervisor.unowned`) but doesn't
    act on: wicketd is the one starter, so two never race for a shard;
  - a slower level-triggered pass (every 10 min) that checks every shard's runs as a backstop.
- **Box listing moves off ssh.** The node link's welcome and the node's health report already say
  which boxes a node runs. Docker listing over ssh stays only in the backstop pass, for boxes with no
  record.

### 2.5 What stays at the edge, and harness-agnostic

- **Decisions.**
  - The host decides nothing the supervisor didn't decide before. The node still decides egress, the
    model gate, secrets, spawns and the box's limits, from its feed and its own records (#257).
  - The host only publishes what the ledger says (tokens, grants, revocations), relays what the node
    sends, and answers the control-host tools (`ControlTool` through `Msg::Call`), as today.
  - Batching changes when a routine write lands, not what is decided, and nothing that carries
    authority is batched (§2.3).
- **Harnesses.**
  - Harness code stays inside the run task, behind `wicket_agent::harness::Adapter`.
  - The host's shared parts (node link, periodic writer, change watch, feed, reconciler) see only run
    ids, frames and ledger rows. None of them reads a transcript or knows Claude Code from an ACP
    agent.
  - The run task keeps the two harness-specific pieces that live outside the trait today: the
    stream-json "between turns" check on re-attach and `attribution::Tracker`. §8 suggests moving them
    behind the trait in step 1.

---

## 3. The failure model

### 3.1 Host leases, epochs and fencing

**Tables** (schema 42, an expand step, built: `wicket-store/src/hosts.rs`):
- `supervisor_hosts`, one row per shard: `host` (the shard's name), `owner` (`machine:pid:start`, the
  process holding it), `epoch`, `lease_until`, `stopping` (the clean-stop marker, §3.4), `adopting`
  (the safe-mode batch, §3.4), `updated_at`. The epoch is the shard's, so it sits here rather than on
  each of its nodes;
- `shard_nodes`: `node` → `host`;
- `runs.host`.

**The lease.**
- A host holds its shard under a lease of 30 s. It renews the lease every 5 s in its own small
  transaction, on a dedicated thread.
- **It renews only while its runtime makes progress.** The runtime moves a counter every tick (a
  task that does nothing else). The lease thread renews only if the counter moved since its last
  renewal. A frozen process lapses its lease, and so does a wedged runtime whose lease thread is
  still alive. A long batch doesn't, since the ticking task is never behind the batch.
- **The watchdog is wicketd's, not systemd's.** Hosts are started by wicketd (§5.2), not as units
  of their own. So there is no `WatchdogSec`.
  - **The heartbeat is off the ledger path.** A thread of its own in the host answers wicketd's
    heartbeat on the host's control socket, sent every 5 s. It says whether the runtime's tick has
    moved, and touches no ledger, so a ledger stall can't silence it.
  - **wicketd kills only after it has taken the epoch.** A host whose heartbeat has been silent for
    20 s, or says its runtime is stuck, is fenced only once wicketd has taken its shard in the ledger
    (below). Taking it needs a ledger write, and only works while that host's lease has lapsed. So a
    ledger stall, which stops every write at once, gets no host killed.

**Epochs, as authority.**
- Taking a shard (a fresh host, or the same host after a restart) increments its `epoch`. That
  happens in the same transaction that sets `shard_nodes.host` and the shard's runs' `runs.host`.
- **The epoch is a grant, not a claim.** When the shard is taken, the control host mints a **shard
  grant** for the host: `{shard, host, epoch, nodes, not_after}`, signed with the authority issuing
  key, as a box's block 0 is. The host can't make one; it only carries the one it was given.
  - The control plane issues authority, and the edge decides.
- **The node checks it.** Once node links exist (the node-link protocol, §2.2), the handshake
  carries the shard grant. The node verifies its signature against its pinned authority root, that
  it names this node, and that it hasn't expired.
  - The node keeps the highest epoch it has accepted for its shard **durably**, in its own state
    beside the feed, synced before it answers. A node restart doesn't forget it.
  - It refuses `Start`, `Resume` and every run frame under a lower epoch. That is note 24's term, per
    shard.
  - This matters because today a node binds a run's output to whoever last sent `Resume`. A stalled
    host that comes back can no longer take its runs back from the host that adopted them.
- **Before node links** (migration steps 1 and 2), nodes know nothing of epochs. The fence is then:
  - the SIGKILL below, before any hand-off;
  - ledger writes conditional on the epoch.
  - Each run still has its own channel, and a killed host's channels die with it.
- **Every ledger write carries the epoch.** Writes are conditional on `runs.host = me` and the
  shard's `epoch = e`: the periodic writer's items, grant hand-offs, quota renewals, a run's end, and
  adoption. A host whose epoch has been taken writes nothing.

**Leaving.**
- A host exits only when it sees its epoch taken by another host, not merely because a renewal
  failed.
- When it exits, it stops its tasks without stopping their boxes, as a SIGKILL does today.

**A shared stall isn't a host's.**
- One ledger stall (a long checkpoint, a full disk) makes every host's renewal fail at once, and
  every lease lapse together. wicketd then kills no one:
  - **it fences only a host whose lease lapsed alone**, while other hosts renewed within the same
    window, or whose process is gone;
  - **when every lease lapsed together**, the cause is the ledger, not a host. It waits for renewals
    to resume, and audits the stall (`supervisor.stall`).
- And it never kills a host whose epoch it hasn't first given away. The order is:
  1. take the shard (new epoch) in the ledger, which only works if the old lease is still lapsed;
  2. kill the old host;
  3. start the fresh one.

**Fencing before a hand-off.**
- A lapsed lease doesn't prove the old host is gone. It may be stalled, still holding every run's
  `ctl/supervisor.lock` (a `flock` is released only when the process dies) and able to send frames.
- So before the fresh host adopts the shard, the old host is **SIGKILLed** by its `owner` pid,
  checked against its start time, and the shard is adopted only once that process is gone. All
  hosts run on the control host's one machine in this version, so the pid can be checked and killed
  (§9 lists hosts on several machines).
- With node links, the epoch also covers the window between the kill and the node noticing: the new
  host's shard grant raises it, and nothing from the old one is accepted after.

**Per-run ownership.**
- `runs.owner` becomes per run: `host:<k>:<epoch>`, not the process label every run in a shard would
  share.
- A run whose task has ended (panic, watchdog) is marked so in the ledger, so a live process doesn't
  make a dead run look supervised (§3.4).

### 3.2 The fence, the authority rules and the timeline

None of these depends on the process model, and each is kept as it is [H]:

- **Block 0's end is the box's authority** (#153). The node stops the box then, with or without a
  supervisor.
- **Renewals.** A human's or an agent's renewal (#56) is a decision written to the ledger, and the
  run's task re-mints block 0 from it. While a run's host is down, a renewal decided meanwhile can't
  reach the node. A shard down for longer than its runs' authority loses those boxes. That is as
  today, for one supervisor.
- **`ctl/authority.json`** is still written by the run's task, durably, before the start and on each
  renewal. `fenced_in` and `claim_wake` (`FENCING_RUNS`) still refuse a wake elsewhere while the box
  may run. Batching the agent claim doesn't touch this fence: the fence is the authority's end, not
  the claim.
- **The agent claim** (`claim_until`, 30 s) still lapses if the host stops writing. A lapsed claim
  doesn't let a second supervisor in, because the fence above still holds while the box's authority
  lasts. After that the box has stopped anyway.

**A host restart against the feed's and identities' lifetimes.** Every box on a node now depends on
one host for a fresh feed [H for the TTLs, `wicket-feed/src/lib.rs`]:

| Down for | What the shard's boxes see |
|---|---|
| under 30 s (the feed's TTL) | nothing: the feed is still fresh |
| 30–150 s | egress decided from a stale feed: plain reads only (#57's 120 s grace) |
| over 150 s | all egress refused |
| over 600 s | identities (TTL 600 s, re-issued every 300 s) begin to expire |

So:
- **On a restart, node links and feeds come up first, concurrently**, before any run task is adopted.
  A statement per node is the first thing sent, so the shard's feeds are fresh again within one
  handshake.
- **How long a hand-off takes depends on how the host failed:**
  - **A crash** (the process is gone) is seen at once: wicketd reaps its child, and the reconciler
    sees the owner's pid dead. A fresh host takes the shard at once and brings its node links and
    feeds up first, so the boxes' feeds stay within their 30 s.
  - **A stall** (the process alive, its runtime or ledger stuck) takes the full lease, 30 s, before
    it counts as lapsed. Then comes the SIGKILL, then the fresh host's links, so about 30–40 s. Its
    shard's boxes see a stale feed for the difference: plain reads only, for seconds.
  - A host that is down longer than that costs its shard fresh egress for the difference, and is
    visible as such (§9, observability).
- **Nodes run alone.** While a node link is down, the node runs on its feed and its leases (bounded
  autonomy, #153), exactly as when one run's session is down today.

### 3.3 One process crashing takes many supervisors

| Failure | Today | Step 5 |
|---|---|---|
| A bug panics one run's code | that run's process exits, and the reconciler adopts it within about a minute | that task ends (§3.5), is marked ended in the ledger, and the shard reconciler adopts it again, backed off |
| A task hangs (a loop, a blocked call) | that run's process looks alive and is | the task's progress heartbeat stops; the host's watchdog cancels the task if it can, and otherwise restarts the host or quarantines the run, never starting a second supervisor (§3.4) |
| Abort, OOM or SIGKILL of the process | one run | the shard: every box keeps running; the host restarts, brings node links and feeds up first, and adopts its runs in safe mode (§3.4) |
| The host stalls (its runtime wedged, a lock held for long) | one run | its lease stops being renewed, or it stops answering wicketd's heartbeat; once its lease has lapsed alone, the shard is taken at a higher epoch, the host is SIGKILLed, and a fresh host adopts the shard (§3.1) |
| A ledger stall for every host | every supervisor's writes wait | every host's renewal fails alike: no host is killed, and none exits; supervision resumes when the ledger does (§3.1) |
| A node link breaks | one run reconnects | every run on the node waits for one reconnect (backoff 0.5–5 s), then all resume from their offsets |
| An update | every supervisor is SIGKILLed; the reconciler spawns thousands of `wicket attach` | a rolling restart, host by host, with a canary and a gate (§5.2) |

- **The blast radius is bounded by the shard size.** At most 2,000 runs a host, to be set from
  measurements (§7), and at least two hosts.
- **Every host gets a memory cgroup.** wicketd's unit gets `Delegate=yes`, so wicketd may make
  sub-cgroups of its own. It puts each host it starts in one, with `memory.max` set, so one host's
  leak doesn't take the others down with the control host.
  - Until `deploy/install.sh` has delivered that unit (self update doesn't install units), hosts
    share wicketd's own cgroup and its limits. Then a host's leak can take down the others, though
    not the control host's other services.

### 3.4 Attributing crashes, and adopting safely

A crash of a whole host doesn't say which run caused it. Counting it against every run it held
would quarantine the wrong runs, or, with #688, stop a whole shard's boxes. So:

- **Planned stops don't count.** An update's SIGHUP or SIGKILL, a lease lost to another host, or a
  shutdown writes a clean-stop marker first (`supervisor_hosts.stopping`). A death without one is a
  crash.
- **Adopt a crashed shard in safe mode.**
  - Adopt it in an **isolated host** (a fresh process holding only that shard), never merged into a
    healthy host.
  - Adopt in small batches (16 runs). Record each in-flight batch durably
    (`supervisor_hosts.adopting`) before it starts.
  - When the host crashes again during a batch, that batch is the suspect. It is split in half and
    retried, each half in its own isolated host, until one run is left. That run is the crasher.
  - Once the whole shard has been adopted without a crash, the isolated host is an ordinary host.
- **Steady-state crashes** (a parser abort long after adoption) are attributed the same way: the
  restarted shard is adopted in safe mode, and bisection finds the run.
- **Bisection assumes a crash reproduces.** Two cases where it doesn't:
  - **Aggregate load** (an OOM from the shard's total, not one run). The shard crashes again only
    once most of it is adopted, whatever the batch. When the crash comes after more than half the
    shard is adopted and the in-flight batch, re-run alone, doesn't crash, the shard is split in two
    isolated hosts of half the runs each, and no run is blamed. A shard split for load twice in an
    hour lowers that host's shard bound and is audited (`supervisor.overloaded`).
  - **Halves that don't reproduce.** When neither half crashes on its own, both are adopted as
    ordinary hosts and the crash is recorded as unattributed. It counts against no run (#688
    included). Three unattributed crashes of one shard in an hour stop safe mode's retries for it.
    The shard is then supervised as runs alone (a host each), until an operator looks.
- **Quarantine.** A run found by bisection is supervised alone: a host of one run, today's process
  model, leased like any host. Quarantine is audited (`supervisor.quarantined`) and shown in the
  console.
- **Attach failures (#688).** Only failures attributable to the run count towards #688's limit of 5
  before its box is stopped:
  - the run's own task failing to adopt it;
  - a quarantined run's host failing.
  - A host-wide crash counts against no run until bisection names one. In-process adoption backs
    off per run (1 s doubling to 60 s), so a shard's runs aren't retried in a tight loop.
- **systemd's start limit.** Bisection restarts hosts quickly. Hosts are started by wicketd (§5.2),
  which applies its own backoff, rather than relying on `Restart=` with `StartLimitBurst`, which would
  stop restarting a crashing unit after a few tries.
- **Hung tasks.**
  - Each task reports progress (a counter its loop moves) to the periodic writer.
  - A task whose counter hasn't moved for 60 s while its run is live is cancelled by the host.
  - **A task blocked in a synchronous call can't be cancelled.** It still holds the run's
    `ctl/supervisor.lock`, and no second supervisor may start beside it. The host then escalates:
    - a run with no other hung task: the host marks it hung and the run is quarantined. Its new
      supervisor, a host of one run, starts only after this host has restarted and released the
      lock;
    - several hung tasks, or one that hangs again after quarantine: the host restarts (a planned
      stop, clean-stop marker first), and the shard is adopted again in safe mode.
    - It never starts a second supervisor for a run whose lock is held.
  - Then `runs.owner`'s host being alive no longer means the run is supervised: the run's own record
    says whether its task is.

### 3.5 What `catch_unwind` contains, and what it doesn't

- **A panic in a task's own code** is caught, and the task ends. But the shared services are behind
  `std::sync::Mutex` today: the ledger (`Arc<Mutex<Ledger>>`, `noderun.rs`) and much else, with about
  170 `lock().expect(...)` calls. A panic while holding one poisons it, and every other task's next
  `expect` panics too.
- So in a host:
  - **Shared services are actors** (the ledger writer, the change watch, the periodic writer, node
    links, feed publishers). Each owns its state on its own task, and run tasks send them messages.
    No run task holds a shared lock.
  - **Locks that stay shared are non-poisoning** (`parking_lot`), or are taken with
    `unwrap_or_else(PoisonError::into_inner)` where the state is sound after a panic. The feed's
    `SharedFeed` already reopens itself from its files after one.
- **`catch_unwind` doesn't catch any of these:** a stack overflow, an allocation failure, a panic
  while panicking, a panic across an FFI boundary (SQLite's callbacks), `std::process::abort`, or a
  build with `panic = "abort"`. Each takes the host down, and §3.4's attribution handles it.

### 3.6 Security

- **What this doesn't change.** Today every supervisor already runs as the same `wicket` user, and a
  child's supervisor already shares its parent's process. So one host holding many runs' in-memory
  state doesn't cross a boundary that exists today: secrets fetched for swaps, budget slices,
  identity issuers.
- **What it does change.** An exploit in a run's supervision code, through a node's frames or a
  harness's output parser, now sits in a process with its shard's runs rather than alone. The
  existing defences stay, and are unchanged:
  - frames are authenticated per connection;
  - the node is the one that decides;
  - nothing the box writes is executed on the control host.
- **Hardening.**
  - Hosts are wicketd's children, so they run under its unit's hardening (`NoNewPrivileges`,
    `ProtectSystem`, its mount namespace) and limits. No unit of their own is needed.
  - It doesn't need Docker, since the node runs the boxes, except for the local node.
  - Who may call a host's API, and a uid per host for dedicated tenants, are open (§8, §9).

---

## 4. What doesn't move in this step

- **Stdout parsing and the transcript.** These stay on the control host, in the run task: harness
  events, ACP, the remote-session URL. Moving per-box relay work to the node is step 7.
- **The ledger.** It stays one SQLite file with one write lock. The periodic writer reduces how
  often the lock is taken, but not how many writers there are. Sharding it is step 6.
- **Approvals.** A human's or a delegate's throughput (#572) is unchanged.

---

## 5. Migration from today

### 5.1 Steps

Each step ships on its own, keeps the previous behaviour behind a setting until the next, and can be
rolled back by running the previous build.

1. **Two hosts, static by node, opt-in.** Built so far: the ledger's shards, leases, epochs and
   epoch-conditional writes (schema 42, `wicket-store/src/hosts.rs`); the static shard of a node,
   the lease renewed only on runtime progress, and wicketd's start-or-fence rule
   (`wicket-control/src/supervise.rs`); and the rollback reading below (`wicket-home/src/owner.rs`).
   Nothing starts a host yet.

   **Conditions on the PR that first writes a host label** (`host:<shard>:<epoch>` in `runs.owner`;
   #781 review):
   - **The reconciler reads `runs.host` before `runs.owner`, in that same PR.** This build reads a
     host label as a gone owner (the rollback reading), so without it, this build's own reconciler
     would adopt a live host's runs with `wicket attach`.
   - **Raise the floor to 42 and add `previous_build` entries** for the queries an older build runs on
     `runs.owner`: a host label misleads a build that predates it, which is then no longer a safe
     rollback target while hosts hold runs.
   - **`as_shard` doesn't nest.** Methods that open their own transaction (`immediate`, `run_ended`'s
     own, the start's) can't run inside it, and the audit writer (`AuditWriter`) writes on its own
     connection, outside the epoch check. Each host write path has to be made epoch-conditional on
     its own terms (a plain-statement variant inside `as_shard`, or the epoch check in the method's
     own transaction), and the audit writer's records checked against the shard where they matter.
   - **`runs.host` goes stale**: a run that ends keeps it, and a run started on a node after its
     shard was taken has none until the shard is taken again. The start must set it in its one
     transaction (from `shard_nodes`), and readers must treat it as meaningful only for running runs.
   - **Only running runs are labelled**, and a run has no `runs.node` until its box is placed
     (`set_run_node`, the local node included), so `take_shard` labels neither a run not yet placed
     nor one that isn't `running`. The start (and an adoption) must set `runs.host` itself, and a
     hibernated run woken later gets it from its new start.
   - **A renewal doesn't need a live lease**, on purpose: after a ledger stall every lease has
     lapsed, and a host must be able to renew its own. What stops a lapsed holder is its epoch moving:
     `fence_shard`, or `take_shard` moving one of its nodes, which fences it in the same transaction.
   - **The first renewal needs progress too** (fixed here: `Lease::take` records the runtime's
     progress at the take, so a runtime that wedges right after taking its shard still lapses).
   - **One clock.** Leases, heartbeats and the stall window are wall-clock seconds from the control
     host's clock: every host and wicketd run on that one machine in this version. Hosts on other
     machines (§9) need the epoch at the node, not lease times compared across clocks.
   - `wicket supervise` runs today's supervisor, `run_to_end`, as **a thread per run** with a
     current-thread runtime each, as child supervisors do. That is one thread a run, up to the host's
     bound (2,000), plus each runtime's blocking threads while they're busy (ledger and file work).
     Those are capped at 4 a run (`max_blocking_threads(4)`), so 2,000 runs make at most about
     10,000 threads at a burst, and about 2,000 at rest. It is safer than tasks on a shared runtime
     for a first step: `crate::out::to` (the run's output sink) is `thread_local!`.
   - There are two hosts, each holding a static half of the nodes (by a hash of the node's name).
     The local node goes with the first.
   - Each host holds at most 2,000 runs, so step 1 supervises at most 4,000. A run that would take
     its host past the bound is supervised as a process, as today, until step 4's dynamic shards.
   - It has crash attribution from the start (§3.4: clean-stop markers, safe-mode adoption,
     quarantine), and leases, epochs and fencing (§3.1).
   - It is opt-in (`supervise: hosts` in the daemon's configuration). Otherwise runs are processes,
     as today.
   - Each run keeps its own ssh session and ledger connection, so its behaviour is today's in fewer
     processes.
   - wicketd, the console, triggers and services ask a host to start runs. `wicket run` becomes a
     client. The reconciler adopts in-process when the run's host is up, with `spawn_attach` as the
     fallback.
2. **Shared services.**
   - Actors for the ledger (one writer and a bounded reader pool) and the change watch.
   - The periodic writer, and one statement tick per node.
   - Tasks on a shared runtime, once `crate::out::to` and the other thread-locals are per task.
   - The protocol is unchanged.
3. **One channel per node** (the node-link protocol, §2.2).
   - A node link per node in the host, with today's per-run channel for nodes below the node-link
     version (21 or later, §2.2).
   - The node side demultiplexes.
   - Feed deltas are batched across runs on a node.
4. **Dynamic shards.** Hand-off by lease, the shard reconciler, the global reconciler's slow pass, and
   rebalancing when nodes are added or removed (§9).
5. **Retire the process per run** under the daemon: `wicket attach` becomes "adopt in a host". The
   one-process mode stays for running without the daemon.

### 5.2 Updates and rollback

- **Who starts hosts.** `wicket self update` doesn't install systemd units, and new units need root.
  So hosts are started and supervised by wicketd (as it supervises its children today), not by units
  of their own.
  - wicketd watches each host (its heartbeat, §3.1), applies its memory limit (a delegated
    sub-cgroup, §3.3), and restarts a host that dies, with its own backoff.
  - Hosts inherit wicketd's unit's hardening as its children (§3.6).
  - A build without hosts simply doesn't start them.
  - This is the choice: no units of their own, no `WatchdogSec`, no `Restart=`.
- **A rolling update, with a canary.**
  - The first host is the canary. It is re-executed (SIGHUP, as `serve` does) or SIGKILLed with a
    clean-stop marker. It comes back on the new build, takes its shard back at a higher epoch, and
    adopts its runs.
  - **The gate** before the next host:
    - every run in the canary's shard is supervised (its task live, its progress heartbeat moving);
    - **the count of supervised runs after the switch is the count before it**, so none was left
      behind or lost;
    - the shard's lease is live;
    - every node link is up with a fresh feed.
  - Then each other host in turn, with the same gate. A failed gate switches the canary back to the
    old build and stops the rollout. The hosts not yet restarted stay on the old build.
- **Rollback.** (See the conditions in §5.1, step 1: the floor rises to 42 when hosts first write
  their labels.)
  - An older build doesn't know `runs.host` or `supervisor_hosts`. Its reconciler reads `runs.owner`,
    which a host writes as `host:<k>:<epoch>`: an older build must see that as "not alive" and adopt
    with a process.
    - Step 1 has to ship that reading first, in a release before hosts are used: an owner that isn't
      `machine:pid:start` is dead.
  - Rolling back from hosts to processes: stop the hosts with clean-stop markers. The older build's
    reconciler adopts every run with a process, as on any update today.
  - `runs.host` is then stale. A build with hosts clears it when it takes a shard again, so nothing
    reads it before then.

---

## 6. Gains, against the 100k analysis

**Assumptions** [L]:
- 10,000 boxes on 100 nodes (100 a node);
- 30% long-lived agents, as in #582's mix;
- 8 hosts of 1,250 runs each: under the 2,000 bound (§3.3). Shards aren't merged, so a crashed
  shard's fresh host is a ninth process for a while;
- the 1 s tick of §2.3;
- defaults as in §1, with step 4's runtime (#689).

| | today: steps 1–4 | step 5 | how |
|---|---|---|---|
| Supervisor processes on the control host | 10,000 | 8 | one host per shard |
| `wicket node attach` processes on each node | about 100 | 1 | one link per node |
| Threads (about 6 a supervisor with #689's runtime) | about 60,000 | about 300 at step 5's end (8 × (8 workers + 32 blocking)); at migration step 1, a thread each for the 4,000 runs two hosts hold, and the other 6,000 as processes (about 40,000 threads) | tasks, not processes |
| ssh sessions to nodes | 10,000 (100 a node) | 100 | one link per node |
| Agent heartbeat transactions | 3,000 agents / 5 s = 600 a second | 8 a second: one transaction a tick per host, holding about 75 heartbeat rows each | the periodic writer |
| Presence writes (`runs.activity`), on change | up to 10,000 rows a second at a burst, one transaction each | the same rows, in the same 8 transactions a second | the periodic writer |
| `PRAGMA data_version` polls | about 70,000 a second: 40,000 for grant sync (4 a second a run) and 30,000 more for the 1 s checks of revocations, node CAs and asks | about 32 a second for the topics behind counters (4 a second a host), plus per-task polls for what isn't behind one yet (§2.3) | one watch per host |
| Feed lock and refresh for statements (1 a second a session) | 10,000 a second | 100 a second | one tick per node |
| Token compiles per feed delta (step 3: one per publisher on the node) | 100 | 1 | one publisher per node |
| Audit writer and exporter threads | 20,000 | 16 | one per process |
| Ledger connections (file descriptors, WAL readers) | 10,000 | 8 writers plus a bounded reader pool each | the ledger actor |
| Resident memory | not measured; at an assumed 15–30 MB a process [L], 150–300 GB | not measured; a few GB [L] | one binary, runtime and ledger cache per host |
| Adoption after an update | 10,000 `wicket attach` processes, each with a handshake and a token mint | a rolling restart of 8 hosts; 100 links, each adoption a task | in-process adoption |

**What it doesn't change:**
- the per-run work proportional to what the run does: output, gateway calls, asks, grants;
- the ledger's one write lock for writes a person waits on.

**Against #582's order.** Steps 1–4 aim at about 10,000 boxes on NVMe, and their limits are process
and thread counts, ssh sessions, and the ledger's write rate. This step takes those out of the per-box
cost. What bites next at 100,000:
- **the ledger's write lock**, now under the work runs actually do (asks, grants, messages, audit),
  not their idling (step 6, sharding the ledger);
- **the control host's CPU spent parsing output** (step 7, moving relay work to the node);
- **approval throughput** (#572).
- My estimate [L], from the table above and nothing measured: a single control host with step 5
  reaches a few tens of thousands of boxes before the ledger's write lock binds. It is reasoned
  from the idle costs going away, not from a model of the busy ones, and §7's harness has to
  confirm or replace it.

**Not measured here.** This box has no Docker or nodes, so I couldn't run a supervisor. Three numbers
matter most, and none of them is known:
- a supervisor's idle CPU after step 2;
- its resident memory (each process maps the binary's private pages, a runtime, a ledger cache, and
  its node's feed state);
- the ledger's sustained write rate with the periodic writer.
- #582's analysis gave 7.7 ms of CPU a second for a supervisor. That was measured before step 2's
  change watch, which took the idle polls' queries away. So it is an upper bound now, not today's
  figure. If anything close to it still holds, 10,000 supervisors are tens of cores of idle work.
  That is the strongest reason for this step, if true, and the first thing to measure.

---

## 7. Measuring it first

Before implementing, build a scale harness: in `experiments/` (as `feed_scale` did for step 3), or in
wicket-sim. It should:

- run N supervisors against a fake node, a `wicket node serve` stub that answers the handshake,
  acknowledges output, and sends health and feed status at the real rates;
- run them as processes (today) and as threads in one process (a step 1 prototype);
- measure each at N = 100, 1,000 and 5,000:
  - idle CPU and resident memory per supervisor;
  - ledger transactions a second and write-lock wait;
  - feed lock ticks;
  - adoption time after a SIGKILL, and the time until every node's feed is fresh again (§3.2).

Done when the table in §6 has measured numbers in place of estimates, and the shard size in §3.3 is
set from them.

---

## 8. Decisions for the owner

1. **Shard by node (proposed) or by run.** By node gives exactly one channel per node and one feed
   publisher, and makes the node the unit of hand-off. A node with more runs than a host should hold
   would need splitting. That's unlikely at about 100 boxes a node, but it caps a node at one host's
   capacity. By run spreads load evenly, but needs a link per node per host and loses single
   ownership of the feed.
2. **How many hosts, and how big a shard.** Proposed: at most 2,000 runs a host, at least two hosts,
   and a ceiling set from §7's measurements.
3. **After a crash or a stall: settled, a fresh host.** The shard always goes to a fresh, isolated
   host, in safe mode after a crash (§3.4). Once adopted, it is an ordinary host. A shard is never
   merged into a live host, so the 2,000-run bound holds.
4. **The one-process mode without the daemon.** Proposed: keep it. It is the same code as a host of
   one run.
5. **Harness code outside the trait.** Move the stream-json "between turns" check and the attribution
   tracker behind `Adapter` in step 1, so the host never needs to know a harness.
6. **Who starts hosts: settled, wicketd** (§5.2), since self update doesn't install units. Its
   watchdog is wicketd's heartbeat, its memory a delegated sub-cgroup, and its hardening wicketd's
   own. What's left to decide is `Delegate=yes` on wicketd's unit, which installs must take up.
7. **Spawn trees across shards** (review item 10). Today a child's supervisor runs in its parent's
   process (#409, slice 4c).
   - One rule: **a child is supervised by the host of its own node's shard**, like any run. The
     parent's task talks to it through the ledger and the host API, as it does to any run. Spawns
     then work across shards, at the cost of the in-process shortcut.
   - The other rule: a child stays in its parent's host whatever its node, which breaks "one host per
     node" for that node's link.
   - Proposed: the first. To decide.
8. **Tenancy** (review item 14). The shard key could include the tenant or the isolation tier, with a
   host per tenant for dedicated tiers (research [14](14-multi-tenancy.md)), and a uid per host. Not
   ruled out; to decide before dynamic shards (migration step 4).
9. **The ledger's read path** (review item 13). One connection would serialise 1,250 tasks' reads.
   Proposed: one writer and a bounded pool of readers per host (WAL readers don't block the writer).
   The pool's size is to be set from §7.

---

## 9. Open items

To settle before or during implementation:

- **Head-of-line blocking** (review item 8).
  - A 16 MiB feed snapshot frame can hold up a `Kill`, and the node's outbound queue is unbounded.
  - Candidates: chunk large frames; a credit-based, per-run fair scheduler both ways with control
    frames first, or yamux-style per-stream windows; a bounded queue on the node.
- **Run-scoped assumptions on the node** (review item 9).
  - Audit shipping falls back to a scope that starts with `run_` (`nodesrv/conn.rs`).
  - Correlation ids (`SecretFetch`, tunnel streams) need to be scoped by run.
  - The demultiplexer should be property-tested.
- **The change watch's remaining polls** (review item 17). Secret revocations and message delivery
  aren't behind a change counter yet (§2.3). Until they are, §6's polling figure is a floor, not the
  number.
- **#692's session files** (`nodes/<n>/sessions/<pid>-<n>`) are keyed by pid. With hosts they must be
  per link, and checked against the host's lease, so a stale host's session doesn't count.
- **Task cancellation never sends `Kill`.** Ending a task (watchdog, hand-off, a lost epoch) must leave
  the box running. Only a run's own stop sends `Kill`.
- **The client path.**
  - stdin through wicketd to the host;
  - the exit code across a host restart;
  - reconnecting a client to a run that has moved host.
- **Rebalancing** when nodes are added or removed: which host takes a new node, and how a node moves
  between hosts, by lease and epoch, without a gap in its feed.
- **The host's API and who may call it.** wicketd only, over a socket only the `wicket` user can
  reach, with the caller's identity passed as wicketd passes it to a child today.
- **Per-host limits and admission**: refusing a new run when a host is at its shard bound, and what
  placement does then.
- **Observability.** Per-task poll time, queue depth, lease margin, batch latency, link lag, and time
  since each node's last fresh feed. These belong in `wicket doctor` and the console.
- **Hosts on several machines.** This version runs every host on the control host's one machine, so
  fencing can SIGKILL a pid (§3.1). Hosts elsewhere need another fence: the epoch alone at the node,
  plus a self-fence on lease loss.

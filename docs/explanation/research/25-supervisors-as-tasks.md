# 25 — Supervisors as tasks in a few processes

Research date: 2026-11-20. Scope: [#582](https://github.com/public/wicket/issues/582) step 5. It
covers moving a run's supervisor from its own OS process into a task inside one of a few
long-lived supervisor processes, with one channel per node, periodic writes batched in shared
transactions, and a sharded, event-driven reconciler. It is a design only, with no code changes.

Context: #582 (the analysis and its order of changes) and steps 1–4; [the feed publisher
note](../feed-publisher.md) (step 3, which left cross-run batching to this step);
[one decision path](../one-decision-path.md) (#257: only the node decides); research
[24](24-control-plane-ha.md) (#151–#153: runs live on their node, bounded node autonomy, the
fence); [updates](../updates.md) (supervisors are killed and adopted on an update);
`crates/wicket-control/src/{run,noderun,spawn,hibernate}.rs`, `crates/wicket-cli/src/reconcile.rs`.

Confidence tags, as in note 24: **[H]** verified against the code at `main` (2026-11-20, after
#682); **[M]** measured elsewhere or partly checked; **[L]** inference or estimate, not measured.

---

## 0. Summary

- **What a supervisor is now.**
  - Every run has a `wicket run`, `attach`, `wrap` or `wake` process on the control host [H].
  - It holds an ssh session to its node, multiplexed over one ssh master per node.
  - It opens its own ledger connection and runs its own audit writer thread and audit-sink exporter thread.
  - It opens its own publisher on its node's feed: one per node per process since step 3.
  - It runs about ten timers between 250 ms and 600 s.
  - The node decides everything (#257). What is left on the control host is bookkeeping, plus
    relaying the run's output and answering its gateway calls.
- **What costs, per box, at 10,000 boxes.** Each cost is paid once per run even when nothing
  happens:
  - a process and its threads;
  - an ssh session;
  - a ledger connection polling `PRAGMA data_version` four times a second;
  - a feed lock and refresh every second;
  - an agent's claim written every 5 s, in its own transaction;
  - a token compiled by every publisher on the node for each delta.
  - Each is cheap. Together they grow with boxes, not with work. Step 4 raised the limits these hit;
    this step removes most of them.
- **Proposal: `wicket supervise`.**
  - A few long-lived **supervisor hosts** each run many runs as tasks. Runs are sharded **by node**,
    so each node has exactly one host and one channel.
  - Inside a host, a run task is today's supervisor loop, harness adapter and all. What a host shares
    is what doesn't depend on the run:
    - the ledger connection and its change watch;
    - a **periodic writer** that batches every task's heartbeats, activity and renewals into one
      transaction a tick;
    - one **node link** per node, which multiplexes every run's frames;
    - the node's feed publisher;
    - a per-shard **reconciler** driven by events, with a slow level-triggered pass as a backstop.
- **What doesn't change.** Each of these still holds as it does today; §3 says why:
  - the node decides;
  - block 0's end is the box's authority (#153);
  - `ctl/authority.json` fences a wake;
  - one supervisor per run (`ctl/supervisor.lock`);
  - a supervisor's death leaves its box running.
- **What gets worse: the blast radius.** A host that crashes takes its whole shard's supervisors at
  once.
  - Boxes keep running under bounded autonomy, and the host's replacement adopts the shard in one
    process, one node link at a time. That is cheaper than today's thousands of `wicket attach`
    processes after an update.
  - A run that crashes its host repeatedly is moved out of the shard and supervised alone, as today
    (§3.4).
- **Estimated gains** at 10,000 boxes on 100 nodes [L]: see §6 for the arithmetic. They need measuring
  before and after, with a scale harness (§7).
  - processes: from 10,000 to about 8;
  - threads: from about 60,000 to about 300;
  - ssh sessions: from 10,000 to 100;
  - agent heartbeat write transactions: from 600 a second to under 2;
  - `data_version` polls: from 40,000 a second to about 40;
  - feed lock ticks: from 10,000 a second to 100;
  - token compiles per feed delta: from 100 to 1.
- **Decisions for the owner** (§8):
  - shard by node, or by run with several links per node;
  - how many hosts, and how big a shard may grow;
  - whether a crashed shard is re-adopted by its restarted host or handed to the others;
  - whether `wicket run` without the daemon keeps today's one-process mode (proposed: yes).

---

## 1. Today: what one supervisor does

This section is from the code at `main` [H].

| Work | How often | State | Ledger writes |
|---|---|---|---|
| Start: run row, owner, lease, identity, token mint, feed `PutZone`, `ctl/authority.json`, trees, image, `Start` (`run::run_to_end`, `noderun::start`) | once | `ctl/run.json`, `ctl/authority.json`, feed files | `runs`, `agents`, `identities`, `placements`, audit |
| The node channel: an `ssh … wicket node attach` session (`Via::Ssh`), with a handshake scoped to the run | for the run's life; reconnect backoff 0.5–5 s | `Progress` (memory), `ctl/link.json` | `node_feed_at` on `FeedStatus` |
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

---

## 2. The design

### 2.1 What moves where

```
today                                   step 5
─────                                   ──────
wicketd ─┬─ wicket run (run A) ─ssh─┐   wicketd ─── wicket run (client: start, stream, exit code)
         ├─ wicket run (run B) ─ssh─┤                    │ asks
console ─┼─ wicket run (run C) ─ssh─┼─ node 1           ▼
reconcile┴─ wicket attach (D) ─ssh─┘   wicket supervise #k  (shard: nodes 1..n)
                                          ├─ run tasks A, B, C, D … (today's loop, per run)
                                          ├─ node link 1 ──── one channel ──── node 1
                                          ├─ node link 2 ──── one channel ──── node 2
                                          ├─ feed publisher per node (as today)
                                          ├─ ledger connection + change watch + audit writer
                                          ├─ periodic writer (one transaction a tick)
                                          └─ shard reconciler (events; slow pass)
```

- **`wicket supervise`** is a new long-lived process. There are a few of them, one per systemd unit
  instance (`wicket-supervise@<k>`), running as the `wicket` user under the same limits as today's
  units (step 4).
  - It owns a **shard**: a set of nodes, and with them every run placed on them.
  - It takes a lease on its shard in the ledger (§3.1), and renews it with its periodic writer.
- **A run task** is today's per-run code, `run_to_end` and `noderun`'s `manage` and `session`, on the
  host's runtime instead of its own. What stays per run:
  - the harness adapter, the transcript, the ACP client;
  - `Progress`, the budget, `ctl/*`;
  - the run's identity, its token issuer, and its gateway calls.
  - It doesn't open its own ledger, write its own heartbeats, dial its own node or sign statements;
    it asks the host's shared services.
  - Each task runs under `catch_unwind`, as a child supervisor does today. A panic ends that run's
    supervision, recorded like a supervisor's death today, and the shard reconciler adopts it again
    (§3.4).
- **`wicket run` becomes a client** when the daemon is installed.
  - It asks wicketd to start the run; wicketd hands it to the host whose shard holds the run's node,
    after placement.
  - The client then streams the run's output from the host and returns its exit code, as wicketd
    relays a child's exit code today.
  - Its SIGTERM or Ctrl-C asks the host to stop the run, keeping today's meaning: the box is stopped
    and the status is `interrupted`.
  - Without the daemon (development mode, `--node` on a laptop), `wicket run` keeps running its run
    in its own process, as today. That is a host of one run, the same code.
- **The console, triggers and services** ask a host to start or wake a run, instead of spawning a
  detached process.

### 2.2 One channel per node

- A host has one **node link** per node in its shard: one connection (one ssh session) over which
  every run on that node talks.
- **Protocol 20 (proposed): `Run { run, frame }`.**
  - It wraps today's per-run frames, so `Msg::Data`, `Started`, `Exited`, `Call`, `Ask`, `Audit` and
    the rest are unchanged inside it.
  - The handshake is scoped to a host (`scope: "host:<k>"`) instead of a run.
  - The welcome already lists the node's runs. The link routes each run's frames to its task, and a
    task's frames out over the link.
  - The node side, `wicket node attach`/`serve`, already serves many runs. It gains the demultiplexer.
  - **A node below 20** gets today's channel per run from the same host, so a mixed fleet works within
    the skew.
- **Node-wide messages go once per node.** Today `FeedStatus`, `Health`, statements, catch-ups, the
  node certificate and the node CA are handled per run, deduplicated after the fact; the 20 s health
  write is one example.
- **Flow control.** One run's output must not stall another's.
  - Each run's `Data` keeps its own offsets and acknowledgements as today. The link writes frames
    from a fair queue across runs, with a per-run bound.
  - A run whose consumer (its transcript) falls behind stops being acknowledged. The node buffers it,
    as it does for a slow session now (`OUTPUT_CAP`).
  - Control frames (revocations, `Kill`, statements) jump the queue.
- **Revocation latency doesn't get worse.**
  - A revocation is a feed delta. With one owner of the node's connection, the host can batch
    deltas across runs: the feed publisher note left this for step 5, because without a single owner
    one run's delta could reach the node over another run's dead connection.
  - If the link is down, the node treats it exactly as it treats a lost session now: the feed's TTL
    (30 s) and bounded autonomy (#153) decide.
- **`MaxSessions` stops mattering.** It is one session per node per host, so step 4's 512 becomes a
  ceiling nothing reaches.

### 2.3 Periodic writes in shared transactions

- **The periodic writer** is one task per host, and every run task writes through it:
  - agent heartbeats (`renew_agent_claim`, usage);
  - presence (`set_run_activity`);
  - quota renewals;
  - progress;
  - the host's own lease.
- **On a tick** (1 s), it writes everything queued in one `BEGIN IMMEDIATE` transaction, and tells
  each caller its own result.
  - A claim that fails because the agent was superseded fails for that run alone, inside a
    savepoint, as `hear_records` does for triggers.
- **What stays immediate.** Writes a decision or a human waits on aren't batched:
  - a granted request's audit commit, which already waits for its batch;
  - a run's start, already one transaction (step 2);
  - asks, messages, a grant handed to a node;
  - the end of a run.
- **Timing.** An agent's claim still lasts 30 s from its write and is still written every 5 s, so
  the batch adds at most the tick (1 s) to its age. That is far inside the 30 s, and the fence
  doesn't depend on it (§3.2).
- **`ctl/progress.json` stays a per-run file.** It is written every 3 s, and nothing in the ledger
  depends on it.

**One change watch per host.**
- One task reads `PRAGMA data_version` and the change counters.
- It wakes only the tasks whose topic moved: grants for the runs whose rows changed, using a
  `grants` row's `run` and `scope` (step 1 indexed both).
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
  - a run task's end or panic;
  - a host lease that lapsed (§3.1: another host or the reconciler adopts that shard);
  - the ledger's change counters for runs.
  - The same rules apply as now (`reconcile::runs`): adopt if the node lists the box, end as `lost`
    if it doesn't, wait while the node is unreachable and the run is fenced. Adoption is a new task
    in the same process, not a spawned `wicket attach`.
- **The global `wicket reconcile` keeps what isn't per shard**, now with a slower level-triggered pass
  (every 10 min) that checks every shard's runs as a backstop:
  - triggers, leases and machines (#579), placed nodes, signers, services;
  - the ledger's upkeep;
  - **hosts whose leases have lapsed**: it hands their shards to live hosts (§3.1).
- **Box listing moves off ssh.** The node link's welcome and the node's health report already say
  which boxes a node runs. Docker listing over ssh stays only in the backstop pass, for boxes with no
  record.

### 2.5 What stays at the edge, and harness-agnostic

- **Decisions.**
  - The host decides nothing the supervisor didn't decide before. The node still decides egress, the
    model gate, secrets, spawns and the box's limits, from its feed and its own records (#257).
  - The host only publishes what the ledger says (tokens, grants, revocations), relays what the node
    sends, and answers the control-host tools (`ControlTool` through `Msg::Call`), as today.
  - Batching changes when a write lands, not what is decided.
- **Harnesses.**
  - Harness code stays inside the run task, behind `wicket_agent::harness::Adapter`.
  - The host's shared parts (node link, periodic writer, change watch, feed, reconciler) see only run
    ids, frames and ledger rows. None of them reads a transcript or knows Claude Code from an ACP
    agent.
  - The run task keeps the two harness-specific pieces that live outside the trait today: the
    stream-json "between turns" check on re-attach and `attribution::Tracker`. §8 suggests moving them
    behind the trait in the same change.

---

## 3. The failure model

### 3.1 Host leases and shards

- **New table `supervisor_hosts`** (an expand step): `host`, `owner` (`machine:pid:start`, as
  `runs.owner`), `lease_until`, `updated_at`.
- **New column `runs.host`**, and the shard map `shard_nodes` (`node` → `host`).
- **Taking a shard.**
  - A host takes a shard when the shard's previous host's lease has lapsed. The lease is 30 s,
    renewed every 5 s by its periodic writer.
  - It does so in one transaction that also moves the shard's runs' `runs.host`.
- **Keeping it.**
  - Losing the lease, because the host is stalled past 30 s, makes the host stop the shard's tasks
    *without stopping their boxes* (as a SIGKILL does today), drop its node links, and exit.
  - systemd restarts it and it takes a shard again.
- **One supervisor per run still holds**, on two levels:
  - the shard lease (one host per node);
  - `ctl/supervisor.lock` per run, which the task takes before it touches the run. The `flock` is
    released by the kernel when the host dies, so a new owner never waits on a dead one.
  - A `wicket attach` from an old build still finds the run's lock taken, and fails as today.

### 3.2 The fence and the authority rules

None of these depends on the process model, and each is kept as it is [H]:

- **Block 0's end is the box's authority** (#153). The node stops the box then, with or without a
  supervisor. A host that is down renews nothing (authority renewal, #56, re-mints block 0), so a
  shard down for longer than its runs' authority loses those boxes. That is as today, for one
  supervisor.
- **`ctl/authority.json`** is still written by the run's task, durably, before the start and on each
  renewal. `fenced_in` and `claim_wake` (`FENCING_RUNS`) still refuse a wake elsewhere while the box
  may run. Batching the agent claim doesn't touch this fence: the fence is the authority's end, not
  the claim.
- **The agent claim** (`claim_until`, 30 s) still lapses if the host stops writing. A lapsed claim
  doesn't let a second supervisor in, because the fence above still holds while the box's authority
  lasts. After that the box has stopped anyway.
- **Nodes run alone.** While a node link is down, the node runs on its feed and its leases (bounded
  autonomy, #153), exactly as when one run's session is down today.

### 3.3 One process crashing takes many supervisors

| Failure | Today | Step 5 |
|---|---|---|
| A bug panics one run's code | that run's process exits, and the reconciler adopts it within about a minute | that task ends (`catch_unwind`), and the shard reconciler adopts it at once |
| Abort, OOM or SIGKILL of the process | one run | the shard: every box keeps running; systemd restarts the host, which takes its shard back and adopts its runs one node link at a time |
| The host stalls (a full disk, a ledger lock held for long) | one run | the shard's lease lapses after 30 s; the global reconciler hands the shard to another host (§3.1) |
| A node link breaks | one run reconnects | every run on the node waits for one reconnect (backoff 0.5–5 s), then all resume from their offsets |
| An update | every supervisor is SIGKILLed; the reconciler spawns thousands of `wicket attach` | each host gets SIGHUP and re-executes itself (as `serve` does), or is SIGKILLed, and adopts its shard in process |

- **The blast radius is bounded by the shard size.** Proposed: at most 2,000 runs a host; to be set
  from measurements (§7).
- **Every host gets a memory cgroup** (`MemoryMax` in its unit), so one host's leak doesn't take the
  others down with the control host.

### 3.4 A run that kills its host

- A run whose code crashes the whole process, on start or on each adoption, would otherwise take its
  shard down in a loop.
- **The host counts deaths.** It records which runs it was adopting or starting when it began
  (`supervisor_hosts.adopting`). After a host death, those runs' crash counts go up.
- **Quarantine.** A run at 3 crashes is supervised alone: a host of one run, today's process model,
  started by wicketd and leased like any host.
- Quarantine is audited (`supervisor.quarantined`) and shown in the console.

### 3.5 Security

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
- The host's unit gets the same hardening as wicketd's (`NoNewPrivileges`, `ProtectSystem`). It
  doesn't need Docker, since the node runs the boxes, except for the local node.

---

## 4. What doesn't move in this step

- **Stdout parsing and the transcript.** These stay on the control host, in the run task: harness
  events, ACP, the remote-session URL. Moving per-box relay work to the node is step 7.
- **The ledger.** It stays one SQLite file with one write lock. The periodic writer reduces how
  often the lock is taken, but not how many writers there are. Sharding it is step 6.
- **Approvals.** A human's or a delegate's throughput (#572) is unchanged.

---

## 5. Migration from today

Each step ships on its own, keeps the previous behaviour behind a setting until the next, and can be
rolled back by running the previous build.

1. **A host process, without sharing.**
   - `wicket supervise` runs today's supervisor, `run_to_end`, as tasks, using what child supervisors
     already do (a thread and a current-thread runtime each, or tasks on a multi-thread runtime).
   - wicketd, the console, triggers and services ask it to start runs instead of spawning processes.
     `wicket run` becomes a client.
   - It's one host and no shard yet: every run is in it.
   - It keeps each run's own ssh session and ledger connection, so its behaviour is today's in fewer
     processes.
   - The reconciler adopts with an in-process call when a host is up, with `spawn_attach` as the
     fallback.
   - Ledger: `runs.host` (an expand step).
2. **Shared services.**
   - One ledger connection and change watch per host.
   - The periodic writer, and one statement tick per node.
   - The ledger and the protocol are unchanged.
3. **One channel per node** (protocol 20).
   - A node link per node in the host, with today's per-run channel for nodes below 20.
   - The node side demultiplexes.
   - Feed deltas are batched across runs on a node.
4. **Shards and leases.**
   - `supervisor_hosts` and `shard_nodes` (expand steps).
   - Several hosts, and the shard reconciler.
   - Lease hand-off, quarantine.
   - The global reconciler's slow pass.
5. **Retire the process per run** under the daemon: `wicket attach` becomes "adopt in a host". The
   one-process mode stays for running without the daemon.

On an update during the migration, a build with hosts adopts the runs a build without them left
behind. The reverse also works: an older build's reconciler sees `runs.owner` dead and attaches with a
process, which still works, because `runs.host` is only read by builds that know it.

---

## 6. Gains, against the 100k analysis

**Assumptions** [L]:
- 10,000 boxes on 100 nodes (100 a node);
- 30% long-lived agents, as in #582's mix;
- 8 hosts of 1,250 runs, each on a runtime with about 8 workers;
- defaults as in §1.

| | today, after steps 1–4 | step 5 | how |
|---|---|---|---|
| Supervisor processes | 10,000 | 8 | one host per shard |
| Threads (about 6 a supervisor, step 4) | about 60,000 | about 300 (8 × (8 workers + 32 blocking)) | tasks, not processes |
| ssh sessions to nodes | 10,000 (100 a node) | 100 | one link per node |
| Agent heartbeat transactions | 3,000 agents / 5 s = 600 a second | under 2 a second (8 hosts / 5 s, plus leases) | the periodic writer |
| Presence writes (`runs.activity`), on change | up to 10,000 a second at a burst | at most 8 a second | the periodic writer |
| `PRAGMA data_version` polls (grant sync 4/s) | about 40,000 a second | about 32–40 a second | one watch per host |
| Feed lock and refresh for statements (1/s a session) | 10,000 a second | 100 a second | one tick per node |
| Token compiles per feed delta (step 3: one per publisher on the node) | 100 | 1 | one publisher per node |
| Audit writer and exporter threads | 20,000 | 16 | one per process |
| Ledger connections (file descriptors, WAL readers) | 10,000 | 8 | one per process |
| Adoption after an update | 10,000 `wicket attach` processes, each with a handshake and a token mint | 8 hosts × 100 links, each adoption a task | in-process adoption |

**What it doesn't change:**
- the per-run work proportional to what the run does: output, gateway calls, asks, grants;
- the ledger's one write lock for writes a person waits on.

**Against #582's order** [L]. Steps 1–4 aim at about 10,000 boxes on NVMe, and their limits are
process and thread counts, ssh sessions, and the ledger's write rate. This step takes those out of
the per-box cost. What bites next at 100,000:
- **the ledger's write lock**, now under the work runs actually do (asks, grants, messages, audit),
  not their idling (step 6, sharding the ledger);
- **the control host's CPU spent parsing output** (step 7, moving relay work to the node);
- **approval throughput** (#572).
- One estimate puts a single control host with step 5 at a few tens of thousands of boxes. That
  needs §7's harness to confirm.

**Not measured here.** This box has no Docker or nodes, so I couldn't run a supervisor. Three numbers
matter most, and none of them is known:
- a supervisor's idle CPU after step 2;
- its resident memory (each process maps the binary's private pages, a runtime, a ledger cache, and
  its node's feed state);
- the ledger's sustained write rate with the periodic writer.
- #582's analysis gave 7.7 ms of CPU a second for a supervisor before step 2's change watch. If that
  still holds for an idle supervisor, 10,000 of them are 77 cores of work. That is the strongest
  reason for this step, if true, and the first thing to measure.

---

## 7. Measuring it first

Before implementing, build a scale harness: in `experiments/` (as `feed_scale` did for step 3), or in
wicket-sim. It should:

- run N supervisors against a fake node, a `wicket node serve` stub that answers the handshake,
  acknowledges output, and sends health and feed status at the real rates;
- run them as processes (today) and as tasks in one process (a step 1 prototype);
- measure each at N = 100, 1,000 and 5,000:
  - idle CPU and resident memory per supervisor;
  - ledger transactions a second and write-lock wait;
  - feed lock ticks;
  - adoption time after a SIGKILL.

Done when the table in §6 has measured numbers in place of estimates, and the shard size in §3.3 is
set from them.

---

## 8. Decisions for the owner

1. **Shard by node (proposed) or by run.** By node gives exactly one channel per node and one feed
   publisher, and makes the node the unit of hand-off. A node with more runs than a host should hold
   would need splitting. That's unlikely at about 100 boxes a node, but it caps a node at one host's
   capacity. By run spreads load evenly, but needs a link per node per host and loses single
   ownership of the feed.
2. **How many hosts, and how big a shard.** Proposed: one host per 2,000 runs, at least two hosts so
   one crash doesn't take every run, and a ceiling set from §7's measurements.
3. **After a crash: the same host, or the others.** Proposed: the restarted host takes its shard
   back if it's up within the lease (30 s). Otherwise the global reconciler spreads the shard over
   the live hosts.
4. **The one-process mode without the daemon.** Proposed: keep it. It is the same code as a host
   of one run.
5. **Harness code outside the trait.** Move the stream-json "between turns" check and the
   attribution tracker behind `Adapter` in step 1, so the host never needs to know a harness.

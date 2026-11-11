# Experiment #70: hibernate and wake

**Question (#70, research 22 §9.6 E1, E3 and E4):** what does it take for a Claude Code agent in a
wicket box to sleep and wake? Which state has to be kept, how big is it, and how long do hibernate and
wake take by rebuild + `claude --resume`? Does gVisor checkpoint/restore work with wicket's box shape
(host unix sockets, `--network none`, the in-box socat forwarders), and what breaks? What must be
re-established on wake, and how is a box woken twice kept from splitting the agent's state?

**Answer: build rebuild + resume (H0) for 0.0.1, with `docker pause` for Idle. Leave gVisor
checkpoint (H2) for later. It works and is fast, but it needs direct runsc, a restore hook and
restore-once fencing, and it only saves Claude Code's ~3.5 s start.**

- **Rebuild + resume works.** The minimal bundle is `CLAUDE_CONFIG_DIR/projects/`, the workspace and
  the volumes. Nothing else in `state/` is needed. A fresh gVisor box resumed the session with all 46
  prior messages.
  - Hibernate (digest, tar+zstd, upload to a directory store): 0.49 s for 9.6 MB stored.
  - Wake (download, unpack, verify, start the box, resume): first assistant event 3.9 s after
    `docker run`, 5.2 s from the start of the pull to the end of the turn.
- **gVisor checkpoint/restore works**: the host sockets, `--network=none` and the forwarders are fine.
  - Checkpoint 0.2 s. The image is 114 MB, or 20 MB after zstd.
  - Restore 0.13 s, and 2.0 s to a finished turn.
  - **One thing breaks:** the restore drops `wicket.internal`'s address (198.18.0.1 on `lo`).
    Claude Code then retries with backoff (0.5 s up to 39 s) and never reaches the proxy. A gVisor
    restore hook that puts the address back fixes it.
- **Nothing in runsc stops a double wake.** The same image restored twice gave two live agents
  appending to one transcript. The fencing has to come from wicket: a compare-and-set claim with a
  generation number that the proxies and the push both check. Prototyped: 500 races of 8 wakers, one
  winner every time.
- **Storage is cheap.** A typical hibernated agent is about 10 MB, about $0.0002 a month. Re-derivable
  caches (`node_modules`, `target/`) dominate when they're bundled: 156 MB and 327 MB compressed.

Order for #70:
1. `--session-id` chosen by wicket, and `cleanupPeriodDays` forced in the generated settings.
2. The ledger's agent row, with a generation number and the compare-and-set wake claim.
3. Stop at a turn boundary, then push the bundle (an object-store trait with a directory backend).
4. Wake = rebuild + `--resume`, with fresh identity, sockets, CA and placeholders.
5. `docker pause` for Idle.
6. Encryption and signing of the bundle, then the S3 backend.

H2 (checkpoint as a cache) waits for direct runsc (§8.3).

All runs were on 2026-11-11, on the shared 4 vCPU VPS with runsc release-20261102.0 and Claude Code
2.1.319 (`wicket/claude-code:poc`). Expect ±30% noise on timings, as in the sibling experiments.

## 1. What was built

Scripts only, no Cargo project. Nothing in `crates/` was changed.

| file | role |
|---|---|
| `mock_llm.py` | A scripted Anthropic Messages mock, extended from `wicket dev mock-llm`. The task turn is a 20-step coding session: Bash, Read, Write, Edit, and writes to a volume. On a wake turn, it reports how many prior messages the request carried and whether the task and turn-1 markers were present. That report is the proof that `--resume` sent the old conversation. `HIB-SLOW` holds a reply for 20 s, to leave a request in flight. |
| `session1.yaml`, `session1.sh` | Session 1 is a real `wicket run`: a gVisor box behind wicket's proxies, an in-place `--workspace-dir` (a clone of this repo) and one volume. |
| `box.sh` | Starts a wicket-shaped box without wicket. It uses `build_args`' Docker arguments and `claude_code_plan`'s environment, plus extra Claude arguments (`--resume`). The differences: no MCP gateway (empty `--mcp-config`) and no egress proxy. `wicket run` has no way to resume yet. |
| `bundle.sh` | The H0 bundle: one tar+zstd blob per tree, content-addressed under `a/<agent>/p/`. A tree digest (paths, types, modes, file sizes, contents) is checked after unpack. The manifest at `a/<agent>/m/<seq>` is written put-if-absent. No encryption or signing (§6). |
| `e4-resume.sh` | E4: inventory of `state/`, push, pull, wake by rebuild, and four checks: no `projects/`, a different cwd, `--fork-session`, and `cleanupPeriodDays`. |
| `oci_config.py`, `e1-checkpoint.sh`, `restore-hook.sh` | E1/E3: the same box run with `runsc` directly from an OCI bundle (the image's rootfs). Checkpoint, restore, clocks, a request in flight, a double restore, and gVisor's save/restore hook. |
| `e1-docker.sh` | `runsc checkpoint` of a Docker-managed box. |
| `e2-pause.sh` | Idle: `docker pause` and `unpause` of a box with an open session. |
| `fence.py` | The lease and fencing sketch on SQLite, raced with threads. |
| `sizes.sh` | Bundle cost for realistic trees. |

Raw outputs are in `logs/`. Session ids, run ids, the user name and temp paths are scrubbed.

## 2. Rebuild + resume (E4)

### 2.1 What Claude Code keeps, and what has to be saved

After the 20-step session (`logs/e4.txt`):

| path under `state/` | bytes | needed to resume? |
|---|---|---|
| `claude/projects/-workspace/<session>.jsonl` | 1,009,715 (113 lines) | **yes**: the session |
| `claude/projects/-workspace/memory/` | 0 | yes if used: Claude Code's per-project memory (keyed by cwd) |
| `claude/.claude.json` | 892 | no: regenerated on start |
| `claude/.last-cleanup` | 24 | no; dropping it makes the next start sweep (§2.3) |
| `claude/backups`, `plugins`, `session-env`, `sessions`, `shell-snapshots` | < 200 | no |
| `home/.cache` | 3,316 | no |

- In `-p` stream-json mode, this version writes no `file-history/` or `todos/`. Research 22's list
  (`projects, file-history, tasks`) is a superset. Bundle all of `CLAUDE_CONFIG_DIR` except caches,
  since it costs almost nothing, but only `projects/` is load-bearing.
- **Without `projects/`, the wake fails cleanly:** `No conversation found with session ID`, with a
  `result` of `error_during_execution` 2.6 s after start. wicket must treat that as a failed wake,
  not start a new session silently.
- **A different cwd still resumes** in 2.1.319. With the workspace at `/work`, Claude Code found the
  session under `projects/-workspace/` and kept appending there. Its per-project memory directory is
  keyed by cwd, though, and a new empty `-work/` was made. So wicket should keep the cwd fixed
  across wakes, which `/workspace` already does. Wrapped agents (`wicket wrap`) mount the
  launcher's own path, so that path has to be kept too.
- **`--fork-session` works:** a new session id, the original JSONL byte-identical, and the full
  history in the request. It's the tool for shedding taint on wake (research 22 §6.6).

### 2.2 Timings (`logs/e4.txt`)

| step | time |
|---|---|
| push: digest + pack + upload, 3 trees (11.3 MB raw → 9.6 MB stored) | 0.49 s |
| pull: download + verify blob + unpack + verify tree digest | 0.45 s |
| `docker run` → Claude Code's `system/init` line | 3.54 s |
| → first assistant event (time to first token) | 3.94 s |
| → `result` (one Bash call + answer) | 4.50 s |
| **whole wake, from the start of the pull to the end of the turn** | **5.23 s** |

- The wake is dominated by the box and Claude Code starting in gVisor (3.5 s to `init`). The bundle
  steps take under 1 s at this size. A cold first run wasn't timed separately.
- The resumed request carried 46 messages (424 KB of JSON for the mock). With a real model, the
  first turn after a long sleep pays for that whole context uncached. A memory snapshot wouldn't
  avoid that either, because the prompt cache has expired. That is #70's argument for H0.

### 2.3 `cleanupPeriodDays` is required

| settings.json | 40-day-old transcript after a new session ran 30 s |
|---|---|
| none (default 30 days) | **deleted**, `.last-cleanup` written |
| `{"cleanupPeriodDays": 3650}` | kept |
| none, but the wake itself is `--resume` of the old session | kept (the resume appends first, which refreshes the file) |

- The sweep isn't immediate: a session that exits after 2 s didn't trigger it, one kept open for
  30 s did.
- **A plain wake by `--resume` survives.** The hazard is narrower than research 22 assumed, but
  still real. Every *other* session in the agent's config dir older than 30 days is deleted on any
  start: forked sessions, the pre-fork original, and sessions of a crew sharing the dir. A wake that
  fails before its first append (the proxy down, a crash at start) leaves the transcript stale for
  the next sweep. And the order (append before sweep) is an implementation detail of 2.1.319.
- Today `cleanupPeriodDays` is one of the manifest's *allowed* adapter settings. For agents that sleep,
  wicket has to own it: force it to at least the agent's retention, and refuse lower values.

### 2.4 A pitfall found on the way

Claude Code merges transcript entries that share a `message.id` when it loads a session. The stock
`wicket dev mock-llm` (`crates/wicket-cli/src/mock.rs`) answers every request with the id
`msg_mock`. On `--resume`, every assistant turn folded into one message, and the mock's script looped
forever. `mock_llm.py` uses a fresh id per response. Any resume test built on the stock mock needs
the same fix.

## 3. gVisor checkpoint and restore (E1, E3)

The box was run with `runsc` directly (`--network=none --host-uds=open`). It used an OCI bundle made
from the image's rootfs, with the same binds, capabilities and `wicket-entry` as a Docker box. Docker
was not used for this part, because:
- the daemon here isn't experimental, so `docker checkpoint` is off;
- Docker restores only into the same container (research 22 §3.1);
- turning on experimental would restart the shared daemon.

`e1-docker.sh` shows that `runsc --root /run/docker/runtime-runc/moby checkpoint` *can* checkpoint a
Docker-managed box: 0.26 s, 115 MB. Docker then sees the box exit, and `--rm` removes it, so there is
no Docker restore path. H2 therefore means direct runsc.

### 3.1 Numbers (`logs/e1.txt`; the box idle after a resumed turn)

| what | value |
|---|---|
| memory in use (`runsc events --stats`) | 466 MB |
| checkpoint, uncompressed (the box stops) | 0.23 s |
| image: `pages.img` / `checkpoint.img` / `pages_meta.img` | 114.3 MB / 187 KB / 41 KB |
| `pages.img` after `zstd -3 -T2` (0.48 s) | 19.7 MB |
| checkpoint `--leave-running --compression=flate-best-speed` | 0.72 s, 26.4 MB |
| restore (`--background`, the default) | 0.13–0.16 s |
| restore `--background=false` | 0.18–0.31 s |
| restore → address back → message → `result` | 2.0 s |
| image fingerprint | runsc version string, 57 CPU feature flags |

### 3.2 What works

- **Host sockets (`--host-uds=open`).** After restore, a new connection to `/wicket/sock/llm.sock`
  works, even after the host listener was restarted with a new socket inode. socat dials the path
  once per connection, so the forwarders need no re-dial logic.
- **stdin.** The restored agent reads the *restore* process's stdin (a new pipe). A follow-up message
  written there was answered, so a wake message can be delivered the same way as `wicket say`.
- **A request in flight.** The mock held a reply for 20 s, and the checkpoint was taken 3 s in.
  After restore:
  - the host side of the socket was gone, and the mock's reply hit a broken pipe;
  - Claude Code logged one `api_retry`, re-sent the request and finished the turn.

  So nothing hangs. But the upstream saw the request twice, which means double cost and possibly a
  double side effect for egress. That is why checkpoints must be quiescent (§4).
- **Clocks (E3).** Over 32.4 s on the host: `CLOCK_MONOTONIC` advanced 0.4 s, while `CLOCK_REALTIME`
  and `/proc/uptime` (boottime) advanced 32.4 s. Node timers, such as `MCP_TOOL_TIMEOUT` on a
  pending `await_grant`, keep their remaining time. Wall-clock logic sees the jump.

### 3.3 What breaks

- **The forwarders' address is lost.** `wicket-entry` adds 198.18.0.1/32 to `lo`. After restore,
  `ip addr` no longer shows it. The socat listeners still exist, but every connect fails. The direct
  UDS path still works.
  - Restore without fixing it: 7 `api_retry` events in 40 s, with delays 0.5, 1.2, 2.2, 4.6, 10, 20
    and 39 s (10 retries at most).
  - Putting the address back late: the turn completed 38.8 s later, at the next retry.

  So the fix has to land before the wake message, from inside the restore:
  - **gVisor's save/restore hook does it.** `runsc checkpoint --save-restore-exec-argv=<hook>` ran
    the hook as uid 0 in the sandbox, with `GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE=save`, then
    `restore`.
  - `ip addr add` in the hook worked. The forwarder answered at once, and the turn took 0.53 s.
  - **The hook persists:** a later checkpoint without the flag still ran it on restore (H1).
  - This is research 22's `wicket-entry --hook`. It needs `NET_ADMIN`, which the agent's process
    dropped. The hook ran as uid 0, and its `ip addr add` succeeded.

  `--leave-running` kept the address.
- **Restored stdout keeps its old file offset.** When stdout was a file, the restored process wrote at
  its old offset, leaving 6,779 NUL bytes at the start of the new file. wicket reads the agent's
  stdout through a pipe, which is fine, but it must never hand a restored box a regular file.
- **No restore-once.** `img-a` was restored three times (C, F, H2). The second time it ran
  *concurrently* with the first box, from another image. Both answered, and both appended to the same
  transcript through the shared bind mount. runsc validates neither the trees nor the image's use
  count (research 22 §3.1). Restore-once and tree digests are wicket's job.
- `runsc statefile` has a `-key` ("integrity key for the file") option. It wasn't tested, and doesn't
  replace wicket's signed manifest.

### 3.4 Idle: `docker pause` (`logs/e2-pause.txt`)

| what | value |
|---|---|
| pause | 0.16 s |
| memory held while paused | 240 MiB |
| unpause | 0.08–0.14 s |
| next turn after 5 s paused | 1.07 s |
| next turn after 60 s paused | 0.55 s |
| `api_retry` events | 0 |

Pause keeps the address, the sockets and the stdin pipe. It's a free Idle tier with the current
Docker launch.

## 4. Correctness hazards on wake

| hazard | on rebuild (H0) | on memory restore (H2) |
|---|---|---|
| Proxy sockets | Fresh per activation: a new run dir and new listeners. | The address must be re-added by the restore hook (§3.3). Per-connection re-dial already works. In-flight requests are re-sent by Claude Code, so a checkpoint is allowed only at a quiescent point. The save hook vetoes if a forwarder has an open request, and wicket parks only after `result`. |
| Identity | A fresh 10-minute document naming the new activation and node. The old one expired while asleep, which is fine. | The same. The box holds no identity key. |
| CA trust | A new CA from the ceiling. `NODE_EXTRA_CA_CERTS` is read at start. | The process keeps the CA it loaded, so it must be a per-agent CA that outlives the image. Rotating it forces a rebuild. |
| Placeholders | New. | The old values, re-bound to the new socket. Per-agent placeholders make that trivial. |
| Grants and the feed | Grants are work-item scoped and don't survive sleep. A pending request survives as a ledger entry, which can itself wake the agent. Before waking, the node needs a feed fresh within the TTL (#60: 30 s), so a revocation issued during the sleep applies on the first request. | The same. Leases are judged on wicket's clock; the box's realtime jump (§3.2) can't extend anything. |
| Charter, image, adapter pin | Applied naturally. | A change forces a rebuild. |
| Transcript retention | `cleanupPeriodDays` forced (§2.3). | The same. |
| Taint | Rebuild declassifies to what's kept; `--fork-session` sheds more. | Keeps the full floating label. |
| Double wake / split brain | Below. | Below, plus restore-once per image. |

**Lease and fencing (prototyped in `fence.py`, `logs/fence.txt`):**
- **One agent row in the ledger:** `state`, `generation`, `activation`, `lease_until` (wicket's
  clock) and `head_seq`.
- **Wake claim.** A single conditional update moves the row from Hibernated to Waking, increments
  the generation and sets this activation's lease:
  `UPDATE … SET state='waking', gen=gen+1 … WHERE state='hibernated' OR lease expired`.
  - In 500 races of 8 concurrent wakers, there was exactly 1 winner every time, at 9.6 ms per race
    for the claim and the commit, on SQLite WAL.
  - A second waker during a live lease gets nothing.
- **The fencing token is the generation.** wicket binds it to the activation's sockets; the box
  never sees it. The LLM and egress proxies refuse a stale generation. A twin, from a restored old
  image or a node that went silent and lost its lease, can neither call the model nor reach the
  network: the proxy accepted the stale twin `False`.
- **Commit point.** A push writes its blobs and a manifest object under a key naming the generation
  (`m/<seq>.<gen>`). Then one ledger transaction checks `gen` and `head_seq` and moves the head.
  The stale twin's push was refused, and the current one committed. A stale writer only leaves
  orphans, which GC removes.
  - In object-store terms: blobs and manifests are put-if-absent (`If-None-Match: *` on S3, R2 and
    GCS), and the ledger pointer is the truth. Wakes never list the bucket.
- **Restore-once.** A memory image is marked consumed in the same transaction as the claim, and the
  node cache honours the flag. Revocation sets `restorable=false` on the row, and every wake path
  checks it.
- **Volumes are trees under the same lease.** They have one writer, the activation holding the
  generation, and are pushed with the bundle. That replaces today's host directories, which two boxes
  on one host can open at once.

## 5. Storage cost per hibernated agent (`logs/sizes.txt`)

| tree | raw | files | stored (tar+zstd -3) | ratio | pack | upload (local) | unpack | verify |
|---|---|---|---|---|---|---|---|---|
| session (20 steps) | 1.0 MB | 1 | 0.20 MB | 5.0 | 0.02 s | 0.01 s | 0.02 s | 0.03 s |
| workspace: this repo with `.git` | 11.3 MB | 1,411 | 9.4 MB | 1.2 | 0.14 s | 0.02 s | 0.16 s | 0.14 s |
| `node_modules` (Claude Code's) | 352 MB | 2,029 | 156 MB | 2.3 | 3.1 s | 0.15 s | 2.2 s | 2.5 s |
| cargo `target/` (debug, wicket-cli) | 1,316 MB | 3,037 | 327 MB | 4.0 | 7.2 s | 0.37 s | 5.2 s | 6.1 s |

- **Real transcripts are bigger than the mock's.** The 235 non-empty session JSONL files on this
  development box were: median 0.9 MB, p90 4.5 MB, p99 20 MB, max 36 MB (sizes from `find`). 60 of
  them, streamed through zstd -3 with only the byte counts kept, compress 6.2×. Nothing else was
  inspected or kept. A long-lived agent's session is likely
  1–20 MB raw, so 0.2–4 MB stored.
- **Pack runs at about 110–180 MB/s raw** on 2 zstd threads.
- **AEAD is not the bottleneck.** ChaCha20-Poly1305 runs at 1.26 GB/s on one core here
  (`openssl speed`), so encryption adds under 10% to pack.
- **Upload to real object storage was not measured.** At an assumed 30–100 MB/s from a node, 10 MB
  takes 0.1–0.3 s and 330 MB takes 3–11 s.
- **Per agent:**
  - typical (session + repo + small volumes): about 10 MB;
  - with bundled build caches: 0.2–0.5 GB;
  - an H2/H3 memory image adds about 20 MB compressed.
- **Cost.** At list prices of about $0.015–0.023 per GB-month (R2, S3 Standard; Vultr Object
  Storage's flat tier is similar), 10 MB is about $0.0002 a month and 0.5 GB about $0.01 a month.
  Each hibernate is 1 manifest PUT plus 1 PUT per tree, or 0 for an unchanged tree, since blobs are
  content-addressed. Requests cost nothing worth tracking.
- **So the cost lever is caches, not sessions.** Volumes should say whether they are `durable`
  (bundled), `node` (kept on the node only, rebuilt elsewhere) or `cache` (never kept). The default
  for build caches should be `node`.

**GC and retention sketch:**
- Keep the head manifest and one previous one, as a rollback point.
- Content-addressed blobs are per agent, so mark-and-sweep from the ledger's live manifests needs no
  cross-agent reference counts.
- Orphan manifests from stale generations, and blobs older than a grace period (24 h) that no live
  manifest names, are deleted.
- Archive drops memory images and older seqs, and keeps the head bundle.
- Delete destroys the agent's data key first (crypto-shred), then the `t/<tenant>/a/<agent>/` prefix,
  and writes a tombstone.
- Storage caps per agent and per tenant push agents down the ladder early (design §13.6).

## 6. Implementation plan for #70

**States** (design §13.2), with what holds each:

| state | box | trees | wake path | measured wake |
|---|---|---|---|---|
| Active | running, turn in progress | node disk | n/a | n/a |
| Idle | running, stdin open (the existing `agent.idle_timeout`), then `docker pause` | node disk | unpause + message on stdin | 0.1 s unpause, then the turn |
| Sleeping | stopped at a turn boundary; bundle pushed | node disk (cached) + object store | rebuild from the local copy (skip the pull) + `--resume` | 3.9 s to first token |
| Hibernated | none; node released | object store | pull + verify + rebuild + `--resume` | 3.9 s + 0.45 s pull at 10 MB, plus the network download |
| Archived | none | head bundle only; images and older seqs dropped | the same as Hibernated | the same |
| Deleted | none | crypto-shredded; tombstone | none | none |

Sleeping with a memory image (H2) is only an option once direct runsc exists. It saves about 3.5 s
per wake.

**Wake sources** (authenticated, design §13.2):
- `wicket say <agent>`, which wakes the agent if it isn't Active;
- `wicket wake <agent>`;
- a schedule;
- an event subscription;
- a decided grant.

Each one becomes a `WorkItem` whose text is written to stdin as the first stream-json turn after
`--resume`.

**APIs and code** (new code outside `crates/wicket-cli/src/run.rs`'s current shape where possible):
- **`wicket-agent`:**
  - `claude_code_plan` takes an `AgentSession { session_id, resume: bool, fork: bool }`.
  - The first activation passes `--session-id <uuid>`; later ones pass `--resume <uuid>`, plus
    `--fork-session` when declassifying.
  - The generated `settings.json` always sets `cleanupPeriodDays` to at least the agent's retention,
    and the manifest can't lower it.
- **`wicket-store`:**
  - `trait ObjectStore { put_if_absent, get, delete, list_prefix /* GC only */ }`, with a `Dir`
    backend now and S3-compatible later (Vultr, R2, S3, GCS, Garage, SeaweedFS).
  - `Bundle::push(trees) -> StateManifest` and `Bundle::pull(manifest, dest)`: one blob per tree,
    tar+zstd, then XChaCha20-Poly1305 STREAM in 64 KiB chunks under the agent data key, with the
    tree digest checked after unpack.
  - `StateManifest` as in research 22 §9.4, plus `generation`, with `live: None` in 0.0.1. It is
    signed by the issuing key and verified before anything is unpacked.
- **The ledger:**
  - `agents (id, tenant, state, generation, activation, lease_until, head_seq, restorable, session_id)`;
  - `claim_wake(agent, activation) -> Option<Generation>` (the compare-and-set);
  - `commit_push(agent, gen, seq, manifest_digest)` (the transaction);
  - `revoke(agent)` sets `restorable = false`.
- **Proxies:** each activation's listener carries `(agent, generation)`. A request is refused when
  the feed's generation for the agent is newer. That uses the #60 feed, so revocation and
  supersession reach a partitioned node within the TTL.
- **Run loop (`run.rs`, after the parallel change lands):**
  - After `result` with no pending requests and no in-flight proxy request: close stdin, wait for the
    box to exit, freeze the trees, push, commit, then mark the agent Sleeping (node copy kept) or
    Hibernated (node copy dropped).
  - On wake:
    1. claim;
    2. pick a node and check the feed's freshness;
    3. pull and verify (or reuse the node copy if its digest matches);
    4. regenerate the config, CA, placeholders and identity;
    5. `--resume`, and deliver the work item;
    6. Active.
  - A `No conversation found` result fails the wake loudly.
- **Volumes:** `zone.volumes[].persist: durable | node | cache`. Durable volumes are pushed with the
  bundle under the agent's lease.
- **Tests:**
  - wake every agent once by rebuild in CI, with `mock_llm.py`'s marker check as the oracle;
  - a 40-day-old-transcript test for `cleanupPeriodDays`;
  - a double-claim race test.

**Done-when for #70, as measured here:**
- stop at a turn boundary;
- one bundle per agent;
- wake on a fresh box with the conversation and workspace intact;
- the bundle verifies.

Not yet done here: "another node, days later". That needs the S3 backend, a second node, and a test
that the 30-day sweep doesn't fire.

## 7. Open risks

- **Claude Code internals are not a contract:**
  - the session lookup across project directories;
  - message-id merging on load;
  - when the cleanup sweep runs;
  - the stream-json resume behaviour.

  All were observed on 2.1.319 only. Pin the adapter version (`adapter_pin`), and re-run E4 on every
  bump. Resuming a transcript written by an older Claude Code version was not tested.
- **What a rebuild loses:** background shells, running subagents and in-memory task state. Only the
  transcript survives. The agent must be told it woke from sleep: the wake message does that.
- **First-turn cost after a long sleep.** The whole transcript is re-sent uncached. Compaction before
  hibernating, or `--fork-session` from a summary, may be worth it for large sessions. Not measured
  with a real model.
- **Real object storage** (latency, throughput, `If-None-Match` support per provider) was not
  measured. Nor were encryption and signing; only their throughput was estimated.
- **H2-specific risks:**
  - the restore hook is the only thing re-adding the address, and a hook failure fails the restore;
  - the CA and placeholders must outlive the image;
  - runsc version changes invalidate images;
  - the in-flight retry duplicates upstream requests.
- **Twin pushes race the ledger, not the object store.** The single-host ledger is fine. Cluster mode
  needs the same compare-and-set on Postgres.

## Reproducing

Run from this directory. You need Docker with `runsc`, the `wicket/claude-code:poc` image,
`cargo build -p wicket-cli`, plus `socat`, `zstd`, `bc` and `python3`. Root access is needed only for
docker and runsc.

```sh
sudo systemctl start docker
git clone ../.. /tmp/hib/ws                   # any repo works as the workspace
WICKET=../../target/debug/wicket WS=/tmp/hib/ws WICKET_HOME=/tmp/hib/home ./session1.sh
R=$(ls -d /tmp/hib/home/runs/run_*)
RUN_STATE=$R/state VOL=/tmp/hib/home/volumes/t0/hib/cache WS=/tmp/hib/ws WORK=/tmp/hib/e4 ./e4-resume.sh
# runsc directly: an OCI bundle from the image's rootfs
mkdir -p /tmp/hib/oci/rootfs && sudo docker create --name hib-export wicket/claude-code:poc true \
  && sudo docker export hib-export | tar -C /tmp/hib/oci/rootfs -xf - && sudo docker rm hib-export
cp -a /tmp/hib/e4/r2 /tmp/hib/ck-root && rm -f /tmp/hib/ck-root/sock/*
SID=$(basename $(ls /tmp/hib/ck-root/state/claude/projects/-workspace/*.jsonl) .jsonl)
BUNDLE=/tmp/hib/oci ROOT=/tmp/hib/ck-root SID=$SID WORK=/tmp/hib/e1 ./e1-checkpoint.sh
cp -a /tmp/hib/e4/r2 /tmp/hib/dk-root && ROOT=/tmp/hib/dk-root SID=$SID WORK=/tmp/hib/e1dk ./e1-docker.sh
cp -a /tmp/hib/e4/r2 /tmp/hib/pz-root && ROOT=/tmp/hib/pz-root SID=$SID WORK=/tmp/hib/e2 ./e2-pause.sh
python3 fence.py 500
./sizes.sh session=$R/state/claude/projects repo=/tmp/hib/ws node_modules=/tmp/hib/oci/rootfs/usr/local/lib/node_modules
sudo systemctl stop docker docker.socket      # only if nothing else is running
```

Each heavy step ran alone, under a 1-hour timeout. All containers are named `hib-*` and removed by
the scripts. The direct-runsc state lives under `$WORK/runsc-root`. Unmount its `null-netns`
(`sudo umount $WORK/runsc-root/null-netns`) before deleting it.

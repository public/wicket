# Experiment #60: control-plane failure, freshness and fail-narrow

**Question (#60, for #57 and research 18 §5.1, architecture A):** a node decides locally from a signed
snapshot-and-delta feed with a TUF-style freshness statement. When the control plane fails, does the
node keep allowing plainly allowed ops until a deadline and stop new leases, spawns and approvals?
Does it catch up when the control plane returns, refuse tampered, replayed and rolled-back updates,
and keep revocation latency bounded?

**Answer: yes on every point, with two protocol details that #57 needs to adopt (§7).**
- Revocation latency: 0.74 ms p50 with push; at most the polling interval with polling; and at most
  the freshness TTL when the node hears nothing at all (measured 2.95 s max against a 3 s TTL).
- All 14 kinds of bad update and the control plane restored from an old backup are refused.
- The prototype is about 1,050 lines without tests, at the low end of research 18's 1–2k estimate.

## 1. What was built

This is a standalone Cargo project with its own `[workspace]`. It depends on `wicket-core` by path
for `ZoneSpec`, `Op` and `evaluate`, and on `ed25519-dalek`, `sha2`, `base64`, `serde_json` and std
threads (no async runtime).

| file | role |
|---|---|
| `src/feed.rs` | Feed format, JWS signing and verification, replicated `State`, and `Replica` (node-side verify/apply/refuse plus mode). Includes unit tests. |
| `src/node.rs` | Node: `decide` with the fail-narrow rule, a feed subscriber (push or poll), a line-JSON query socket, and a mode-transition log. |
| `src/cp.rs` | Control plane: persistent signed delta log, freshness ticker, push to subscribers, polls, catch-up from deltas or a snapshot, admin socket, churn generator. |
| `src/bin/{cp,node}.rs` | Process entry points. |
| `src/bin/harness.rs` | Starts the processes, runs a proxy that can cut the node's link or inject frames, runs every scenario, and writes `logs/*.json`. |

Run it with `cargo build --release && target/release/harness all` from this directory. The final run
ran single-threaded under a 1-hour timeout with `CARGO_BUILD_JOBS=1`. The harness
writes results and process logs to `logs/` (`harness.log`, `<scenario>.json`, `*-node.log`,
`*-cp.log`, `kill*-timeline.json`). The control-plane state directories (throwaway keys and delta
logs) were deleted after the run.

## 2. Feed format

Every artifact is a compact JWS (EdDSA, Ed25519). The `typ` header separates the four kinds, so one
kind can't be replayed as another.

| artifact | `typ` | signed by | payload |
|---|---|---|---|
| key certificate | `wicket-feed-key+jws` | root key (pinned on the node; offline in production) | `kid, x, version, not_after, max_ttl_ms, max_narrow_ms` |
| snapshot | `wicket-feed-snapshot+jws` | feed key | `feed, epoch, head, issued_at, zones[ZoneSpec], grants[Grant], revoked{id: until}` |
| delta | `wicket-feed-delta+jws` | feed key | `feed, epoch, prev, issued_at, changes[put_zone, drop_zone, add_grant, revoke]` |
| freshness | `wicket-feed-fresh+jws` | feed key | `feed, epoch, head, issued_at, fresh_until, narrow_until` |

- **Audience.** `feed` is the node id. A node accepts only its own feed, which stops artifacts from
  one node's feed being mixed into another's.
- **Hash chain.** `head(n) = sha256(delta n as a JWS)`; delta n carries `prev = head(n-1)`; the
  genesis head is all zeros. Snapshots and freshness statements name the head at their epoch, so a
  node detects forks.
- **Grants and leases.** One record type: `{id, zone, op, what, not_after, uses?}`, where `op` is
  wicket-core's `Op::digest` (tenant, zone, method, host, path), the same binding as today's ledger
  grants.
  - `not_after` is checked against the node's clock.
  - `uses` is counted in the node's ledger.
- **Revocations.** `revoked{id: until}` covers grant ids and run ids (identity revocation). `until`
  is the revoked thing's own expiry, after which snapshots drop the entry, so the list stays
  bounded.
- **Key certificate limits.** The root caps the freshness the online key can ever sign: `max_ttl_ms`
  and `max_narrow_ms`. A stolen feed key can't sign "fresh for a day", and a node refuses such a
  statement (`too_long`).
- **Transport.** Line-delimited JSON frames `{"t": "key|snap|delta|fresh|end", "jws": …}` over TCP.
  - The node sends `hello{node, sub, epoch, head}`.
  - The control plane answers with: the key certificate; then either the deltas since the node's
    epoch (if the node is on the control plane's chain and at most `retain` epochs behind) or a
    snapshot; then a current freshness statement.
  - With `sub` (push), the connection stays open and every new delta and statement is pushed.
  - Without it (poll), the control plane sends `end` and the node reconnects every `poll_ms`.
  - Integrity comes from the signatures alone, end to end, so the transport (SSH or mTLS node
    channel) only has to provide confidentiality.

Sizes, measured: a one-change delta frame is 546 B on average (614 B to add a grant, 417 B to revoke);
a freshness frame is 448 B. About 300 B of every delta is signature, header and chain fields, which
is why batching helps (§6).

## 3. The fail-narrow rule (exact)

The node has three modes, computed on every decision from its own clock. Let `F` be the newest
accepted freshness statement. Let `V` be the newest statement whose epoch the node had reached when
it was accepted: `V` "vouched" for the state held.

| mode | when | ops on reach only | ops needing a grant or lease | new leases, spawns, agent approvals |
|---|---|---|---|---|
| **fresh** | `held_epoch >= F.epoch` and `now < F.fresh_until` | allowed (all risk classes, as today) | allowed if a live grant exists: not revoked, `now < not_after` on the node's clock, uses left | allowed |
| **narrow** | not fresh, and `now < V.narrow_until` | allowed only if `evaluate` says `AllowByReach` **and** risk ≤ R1 (reads) | **refused, including grants issued long before** | refused |
| **closed** | no state, or `now >= V.narrow_until` | refused | refused | refused |

These hold in every mode:
- **Forbidden stays forbidden.** `Forbidden` verdicts and revoked runs are refused in every mode.
- **Lease and grant expiry is local.** The node checks `not_after` against its own clock in every
  mode, without needing any update. A grant set to expire while the control plane was down stopped
  at its `not_after` (§5.2).
- **A node that knows it is behind is not fresh.** If it has accepted a statement naming an epoch it
  hasn't reached, it is in *lagging* state and treated as narrow until the missing deltas arrive,
  because those deltas may hold a revocation.
- **A snapshot alone vouches for nothing.** A booting node stays closed until a live statement
  names an epoch it holds.
- **The two deadlines are signed.** `narrow_until - fresh_until` is the narrow window. It is signed
  in each statement and capped by the root certificate.

Why stale grants are refused, not just ones issued after the last fresh epoch: a stale node can't
know whether a revocation was published, so honouring any grant would make the revocation bound the
grant's lifetime, not the TTL. Refusing all of them gives the bound in §4. The cost is that a
partitioned box loses its escalated ops after one TTL, and keeps only its zone's plain reads for the
narrow window.

How this maps to the ticket's wording:
- "Plainly allowed ops continue until the freshness lease ends": they run through fresh and narrow,
  until `narrow_until`.
- "New leases, spawns and approvals stop": at `fresh_until`.
- Writes allowed by reach (R2) and grant-backed ops also stop at `fresh_until`, following research
  18's "R1 or below".

## 4. Revocation bound

**Claim:** a revocation committed at `t_r` stops being honoured on every node by `t_r + TTL` (plus
node-vs-control-plane clock skew), whether or not the node hears anything.

**Proof sketch:**
1. The control plane reads the epoch for a statement under the same lock that commits deltas. So
   every statement issued at or after `t_r` names an epoch `>= e_r`, the revocation's epoch.
2. A node holding such a statement without delta `e_r` is lagging, so not fresh. It therefore stops
   honouring grants.
3. So the only statements that can keep a node fresh without the revocation were issued before
   `t_r`, and they expire before `t_r + TTL`.
4. After that, the node is narrow or closed, and honours no grant.

When the node can hear the control plane, the latency is the push latency, or at most one polling
interval plus a round trip (measured in §5.4).

**Zone policy has a different bound.** A reach rule removed from a zone stops plain reads (R1) on a
partitioned node only by `TTL + narrow window`, because narrow mode uses the cached zone policy. That
is the price of letting reads continue, and why the narrow window must be short and documented.

## 5. Results

**Environment:**
- Machine: a Vultr VPS, 4 vCPU Intel Broadwell (no TSX), 8 GB, Linux 6.8.0-147, shared
  with about 15 other sessions.
- Toolchain: rustc and cargo 1.99.1, release profile.
- Load: everything ran in one job slot (about one core, 2 GB): harness, control plane, one to
  five node processes, and the proxy.
- Clock: all processes share one host clock, so skew is 0.
- Latencies therefore include CPU contention, and the harness's JSON round trip for socket numbers.

### 5.1 Steady state: decision latency and bandwidth

The setup:
- Production parameters: TTL 30 s, refresh 5 s, narrow window 120 s.
- 50 zones (4 reach rules and 1 forbid each) and 1,000 grants.
- Churn of 10 updates/s, alternating add-grant and revoke, one change per delta, for 60 s.
- The harness queried the node continuously: about 497k decisions, 5 classes interleaved.

Over 60 s: **0 wrong answers**, the node stayed in lock-step with the control plane (epoch 610 =
610), and nothing was refused.

| decision class | over the node socket p50 / p90 / p99 (µs) | in-process `decide`, fresh (µs) | in-process, narrow (µs) |
|---|---|---|---|
| reach read (GET, R1) → allow | 117 / 172 / 242 | 36.1 | 34.9 (allow) |
| reach write (PUT, R2) → allow | 123 / 176 / 232 | 43.7 | 47.0 (refuse) |
| granted op (POST comment) → allow | 63 / 91 / 129 | 2.7 | 1.9 (refuse) |
| needs grant, none → refuse | 56 / 82 / 118 | 2.1 | 1.4 (refuse) |
| forbidden host → refuse | 97 / 136 / 181 | 22.1 | 23.0 (refuse) |

Reach decisions cost 20–40 µs because wicket-core's `evaluate` **compiles each path glob on every
call**: a compile costs 20.4 µs, a match 0.13 µs. Grant lookups are a hash lookup on `Op::digest`.
If the node compiled zone policy once, when it applies an update, every decision would drop to about
1–3 µs (§7).

Feed bandwidth per node, at 10 updates/s with one change per delta:

| stream | frames/s | bytes/s |
|---|---|---|
| deltas | 9.97 | 5,441 (546 B average) |
| freshness (refresh 5 s) | 0.20 | 90 (448 B each) |
| **total** | | **5.5 KB/s ≈ 44 kbit/s** |

- With a 500 ms refresh, freshness would be 0.9 KB/s.
- Batching 10 changes into one delta takes 2,834 B, against 6,140 B for 10 separate deltas (54%
  less).

Snapshots and crypto costs (in-process):

| | bytes | sign | verify + load |
|---|---|---|---|
| snapshot, 50 zones + 1,000 grants | 262,046 (254 KB served in the steady run) | 3.9 ms | 3.7 ms |
| snapshot, 50 zones + 10,000 grants | 2,249,246 | 29.6 ms | 41.9 ms |
| delta (1 change) | 417–614 | 48 µs | 104 µs (verify, chain checks, apply) |
| freshness statement | 394 | 37 µs | 82 µs |

### 5.2 Kill the control plane: which ops continue, and when they stop

The setup:
- The control plane was killed with SIGKILL at `t0`. The node pushes, and has 50 zones and 1,000
  grants.
- Probes ran every 50 ms (scaled run) or every 1 s (production run).
- `short_grant` is a grant whose `not_after` falls while the control plane is down and the node is
  still fresh.

| probe | scaled: TTL 3 s, refresh 0.5 s, window 6 s | production: TTL 30 s, refresh 5 s, window 120 s |
|---|---|---|
| last statement: `fresh_until`, `narrow_until` | t0+2,644 ms, t0+8,644 ms | t0+29,621 ms, t0+149,621 ms |
| `short_grant` (`not_after` = t0+1,500 / t0+15,000) | stops at **1,504** (local clock) | stops at **15,004** |
| grant-backed op (`keep-1`) | stops at **2,658** | stops at **30,007** |
| new lease on `keep-1` | stops at 2,658 | stops at 30,007 |
| spawn z0 → z1 | stops at 2,658 | stops at 30,007 |
| agent approval | stops at 2,658 | stops at 30,007 |
| reach write (R2) | stops at 2,658 | stops at 30,007 |
| **reach read (R1)** | **continues until 8,668** | **continues until 150,020** |
| forbidden host | refused throughout | refused throughout |

- **Precision.** Probe times are the first probe after each deadline, so they are within one probe
  step of it. The node's own mode log (polled every 2 ms) is more precise:
  - narrow came 2,996 ms and 29,976 ms after the last statement was received. That is TTL minus
    delivery delay, because `fresh_until` counts from issue, not from receipt;
  - closed came exactly 6,000 ms and 119,998 ms after narrow.
- **Restart.** The control plane was restarted from its persisted log after 9.7 s (scaled) and
  153 s (production).
  - Its admin port was up in 26 ms.
  - The node was fresh again 131–152 ms after the restart: one reconnect interval of 200 ms, at
    most.
  - A revocation of `keep-1` and a new grant `keep-2`, committed right after the restart, reached
    the node in 0–1 ms.
  - Afterwards: reads, writes, spawns and approvals were allowed; `keep-1`, its lease and the
    expired short grant were refused; `keep-2` was allowed.
- **Probe cost.** A probe query over the socket took 130–144 µs p50 during the run.

### 5.3 Catch-up: from deltas, and from a snapshot after a long gap

The proxy cut the node's link while churn ran at 10 updates/s. The control plane retained 150
epochs. TTL 3 s, window 6 s.

| partition | epochs behind | what the node got | bytes | link restored → reconnected | first frame → caught up | restored → fresh |
|---|---|---|---|---|---|---|
| 10 s | 100 | 101 deltas | 55.8 KB | 6 ms | 19 ms | **27 ms** |
| 30 s | 299 (> retain) | 1 snapshot (+1 delta) | 262.5 KB | 64 ms (retry timer) | 13 ms | **78 ms** |

During both cuts the node went narrow at about 2.9–3.0 s and closed at about 8.9–9.0 s. When the
link came back it went straight to fresh, and refused nothing.

### 5.4 Revocation latency

Latency is measured from the harness sending `revoke` to the control plane until the node's first
refusal of the revoked grant. It includes the admin round trip (about 0.45 ms p50).

| node feed | n | p50 | mean | max | bound |
|---|---|---|---|---|---|
| push | 50 | **0.74 ms** | 0.75 ms | 0.96 ms | push latency |
| poll every 1,000 ms | 30 | 383 ms | 416 ms | 971 ms | ≤ poll interval + RTT |
| poll every 250 ms | 30 | 139 ms | 136 ms | 226 ms | ≤ poll interval + RTT |
| partitioned (no push, no poll), TTL 3 s | 10 | 2,876 ms | 2,795 ms | **2,946 ms** | **≤ TTL** |

In the partitioned case:
- Every refusal came from narrow mode ("grants not honoured while stale"). The node never learned of
  the revocation.
- Each one landed within 0.5 ms of the node's `fresh_until` (`deny − fresh_until`: max −0.008 ms,
  mean −0.45 ms).
- Latency was `fresh_until − t_r`, always below the TTL.

### 5.5 What is refused, and why

Frames were injected on the node's link through the proxy, the way a network attacker or a confused
control plane would send them. Every case was checked for:
- the expected refusal counter incremented;
- the node's epoch unchanged;
- the node still fresh;
- `keep-1` still allowed;
- the attacker's grant (`POST …/hooks`) still refused.

All 14 cases passed:

| injected | refused as | why it can't work |
|---|---|---|
| tampered delta (payload changed to add a grant, signature kept) | `bad_signature` | the signature covers header and payload |
| replayed old delta (epoch 2, node at 6) | `replay` | epochs are strictly sequential |
| old, validly signed snapshot (epoch 3) | `rollback` | a snapshot must not go below the epoch held |
| reused freshness statement | `replay` | `issued_at` must rise strictly |
| freshness signed by an attacker key | `unknown_key` | only the root-certified `kid` is accepted |
| attacker freshness carrying the real `kid` | `bad_signature` | |
| freshness for 1 h signed by the **real** feed key (stolen online key) | `too_long` | the root certificate caps TTL at 30 s and the window at 300 s |
| freshness issued 60 s in the future | `from_future` | would otherwise lock out later statements |
| freshness already past `fresh_until` | `expired` | |
| forged feed-key certificate (attacker signs as root) | `bad_signature` | the root key is pinned |
| delta sent as a freshness frame | `wrong_type` | `typ` separates kinds |
| validly signed delta for node `n2` | `wrong_audience` | per-node feeds |
| validly signed delta skipping an epoch | `gap` | the node resubscribes from its epoch, and the control plane re-serves |
| validly signed delta on another chain (wrong `prev`) | `fork` | hash chain |

**Control plane restored from an old backup.** The control plane was killed and restarted with the
same keys but its delta log truncated by 3 epochs (epoch 3, while the node held 6).
- The node refused the backup's snapshot and every one of its statements: 20 `rollback` refusals.
- It went narrow exactly at the last legitimate `fresh_until` (t0+2.79 s) and closed at t0+8.80 s.
- It never accepted the shorter history.
- Restarting the real control plane brought it back to fresh in 198 ms.

## 6. Code size

| | lines (total) | non-blank, non-comment |
|---|---|---|
| `feed.rs` (format, verification, replica) | 602, of which 100 are unit tests | 517 |
| `node.rs` (decide, subscriber, query socket) | 252 | 223 |
| `cp.rs` (log, ticker, push, poll, catch-up, admin) | 250 | 228 |
| `lib.rs`, `bin/cp.rs`, `bin/node.rs` | 47 | 40 |
| **prototype, without tests** | **about 1,050** | **about 920** |
| harness (not product code) | 933 | 855 |

That is at the low end of research 18's 1–2k estimate. A production version would add:
- per-node fan-out in one control-plane process;
- node-side persistence;
- key rotation and recovery (§7);
- integration with the node channel;
- metrics and audit fields;
- a fuzz target for `Replica::accept`.

That probably lands near 2k. The estimate holds.

## 7. Recommendations for #57

**Keep:**
1. **Architecture A's feed as specified**:
   - per-node, root-certified online key;
   - signed snapshot plus hash-chained signed deltas;
   - a short freshness statement re-signed on a timer, pushed on the node channel, with polling as
     the fallback.

   It is small, cheap (5.5 KB/s per node at 10 updates/s; verification in microseconds) and needs no
   new dependency.
2. **The three-mode rule in §3, with both deadlines signed** and capped by the root certificate.
   - At `fresh_until`: stop grants, leases, spawns, approvals and R2+ writes.
   - At `narrow_until`: stop everything.
   - Lease and grant expiry by the node's clock in every mode.
   - Lagging counts as stale.
3. **Defaults for 0.0.1: TTL 30 s, refresh 5 s, narrow window 120 s.** Six statements per TTL means
   five can be lost before the node goes narrow. The bounds to document:
   - revocation of grants, leases and runs: ≤ 30 s worst case, about 1 ms with push;
   - removing a reach rule, for plain reads on a partitioned node: ≤ 150 s;
   - a partitioned node refuses everything after 150 s.
4. **Grants bound to `Op::digest`** (as today), so the escalation path is a hash lookup.
5. **Run-id revocations in the same revoked set as grants**, with `until` so the list stays bounded.

**Change or add (found by this experiment):**
1. **A freshness statement may name an epoch older than the node holds.** Deltas committed after
   the statement was signed reach the node first, in polls and in catch-up. The first version
   refused this as a rollback, which put polling nodes into narrow mode. The node must:
   - require statements to be monotonic against the *last statement*, by `issued_at` and epoch;
   - accept an older epoch only if its head matches the node's own recorded head at that epoch
     (a ring of the last 4,096 heads; a different head is a `fork`).

   This rule still refuses the backup-restore case and still gives the §4 bound.
2. **The control plane re-signs a statement when it serves a catch-up**, if its cached statement is
   behind its epoch. Otherwise a node that just loaded a snapshot can't check the older statement
   (it has no history before the snapshot) and waits up to one refresh. With the fix, the
   snapshot-to-fresh time was 78 ms instead of 375 ms.
3. **Compile zone policy once on the node.** wicket-core's `evaluate` compiles globs per call, which is
   nearly all of a reach decision: a read compiles two globs (the forbid rule's and the matching reach
   rule's), about 40 µs, against 0.13 µs per match. A `CompiledZone` built when an
   update is applied would make every decision about 1–3 µs. The proxy pays the same cost today.
4. **Make the control plane durable before it publishes.** fsync the delta log before pushing (the
   prototype doesn't). Then a crash can only lose deltas no node has seen.
5. **Plan a root-signed recovery path.** A restore from an old backup is refused, correctly, but a
   node can't recover from it on its own: the shorter chain is never accepted. Add a root-signed
   "re-genesis" that raises the feed key certificate's `version` and lets nodes accept a snapshot
   at a lower epoch under the new version. This is TUF's root rotation, applied to the feed.
6. **Persist the verified feed on the node**: snapshot, deltas, and the last statement's `issued_at`.
   - Without it, a node that reboots during an outage comes up closed.
   - With it, the node re-verifies and resumes in whatever mode its signed deadlines allow, and
     replay protection survives the reboot.
   - A node with no state is protected anyway: it stays closed until a *live* statement arrives,
     and statements expire within a TTL.
7. **Clock-skew guard.** Cap the effective deadline at `receipt_time + (fresh_until − issued_at)`.
   Then a node whose clock runs behind the control plane can't stretch freshness. Run NTP and keep
   the tolerance for statements issued in the future small.
8. **Batch deltas when updates are frequent**, e.g. one delta per 100 ms window: 54% less traffic at
   10 changes per delta. Compress snapshots or use a binary encoding before tenants reach 10k grants
   per node (2.25 MB of JSON today).
9. **Fuzz `Replica::accept`.** It is the only code in the trusted computing base that parses
   attacker-reachable input, and research 18 already plans fuzzing.

**For the research 18 write-up:** "Revocation latency is about push latency, at worst one freshness
interval" holds as stated. Measured: 0.74 ms p50 with push, ≤ poll interval when polling, and
≤ TTL (2.95 s against 3 s) with no contact at all. The new bound #57 needs to state is the
reads-only narrow window (TTL + window for zone-policy changes).

## 8. Limits of this experiment

- One feed per control-plane process: one node audience. Production keys the same code by node id.
- A single host, so there was no real network latency, loss, or clock skew.
- Plain TCP, not the SSH or mTLS node channel. Signatures make the feed's integrity independent of
  the transport anyway.
- `evaluate` is wicket-core's current function. Cedar org rules and Biscuit chains (#58, #59) aren't
  in the decision path. The distribution layer doesn't depend on which evaluator runs behind it.
- A shared, loaded 4-vCPU box: tail latencies (up to 4 ms max on the socket) are scheduling noise,
  not the design.

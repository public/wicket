# wicket-feed

The signed policy feed that lets a node decide locally while the control host is unreachable, and
fail narrow when it stays unreachable (#57, research 18 §5.1, architecture A). It ports the
`experiments/freshness-feed` prototype (experiment #60) and adds the changes its `RESULTS.md` §7
asks for.

It is a library: no sockets, no threads, no timers. Every call that depends on time takes `now`
(Unix ms) from the caller. The transport (ssh, in a later PR) carries `Frame`s, one JSON line each:
`{"t": "key|snap|delta|fresh", "jws": "…"}`.

## Pieces

| | where | what |
|---|---|---|
| format | `src/format.rs`, `src/jws.rs` | `KeyCert`, `Snapshot`, `Delta`, `Fresh`, `Frame`; compact JWS (Ed25519), `typ` per kind |
| state | `src/state.rs` | zone policies behind the `Policy` trait (a `wicket_core::ZoneSpec`, compiled once into a `CompiledZone`), grants, revocations, epoch and head |
| node | `src/replica.rs` | `Replica`: verify, persist, apply, refuse; `mode`; `decide`; `escalate` |
| control plane | `src/publisher.rs` | `Publisher`: durable delta log, batching, snapshots, statements, catch-up, re-genesis |

## Format

- A pinned **root key** (offline) signs a `KeyCert` for each node feed's online **feed key**:
  `kid, x, version, not_after, max_ttl_ms, max_narrow_ms`.
- The feed key signs, for one node (`feed` = node id) and one certificate `version`:
  - a **snapshot**: zones, grants, revocations at an epoch, with the chain head;
  - **deltas**: epoch n−1 → n, a batch of changes, with `prev` = head(n−1); head(n) = sha256(delta JWS);
  - **freshness statements**: epoch, head, `issued_at`, `fresh_until`, `narrow_until`.
- **Grants** are bound to `Op::digest` (tenant, zone, method, host, path), with `not_after` (node
  clock), an optional use count (counted on the node) and an optional box (run id).
- **Revocations** name a grant, run or token id, with `until` (the revoked thing's own expiry):
  snapshots drop entries past it, so the set stays bounded.

## Modes

| mode | when | allowed |
|---|---|---|
| fresh | a statement names an epoch the node holds, before its effective `fresh_until` | reach, live grants, leases, spawns, approvals |
| narrow | stale, before the effective `narrow_until` of the last statement that vouched for the state held | reach-allowed ops at risk ≤ R1 only |
| closed | no state, feed key past its certificate, or past `narrow_until` | nothing |

`Forbidden` stays forbidden and revoked runs are refused in every mode; grant expiry is by the
node's clock in every mode; a node that knows it is behind (lagging) is stale.

`Replica::decide(op, now)` returns `Allow(Reach | Grant)`, `NeedsGrant`, `Forbidden` or
`Refused { mode }`. `Replica::escalate` answers whether the node may issue a lease, start a spawn or
sign an approval (fresh only).

## Defaults and bounds

TTL 30 s, refresh 5 s, narrow window 120 s (`DEFAULT_*`; `PublisherConfig` overrides them, within the
certificate's caps). Statements issued up to 2 s in the future (node clock) are accepted.

- Revocation of grants, leases and runs: when the delta applies (about 1 ms with push); at worst 30 s
  after it is committed if the node hears nothing.
- Removing a reach rule, for plain reads on a partitioned node: at worst 150 s.
- A partitioned node refuses everything 150 s after the last statement it received was issued.

Both bounds also include clock skew up to the 2 s tolerance.

## Changes from the prototype (RESULTS.md §7)

1. **Statements are monotonic against the last statement** (`issued_at` strictly rising, epoch not
   falling under the same version). One naming an epoch the node already holds is accepted only if
   its head matches the node's recorded head at that epoch (a ring of 4,096); a different head is a
   `fork`.
2. **Catch-up re-signs the statement.** The prototype re-signed only when its cached statement was
   behind; this one signs one for every catch-up, which also never hands a node a statement it
   already holds (it would be refused as a replay).
3. **The delta log is fsynced before a delta is returned for publishing**; a torn last line (a crash
   mid-append, never published) is dropped on open.
4. **Re-genesis.** Every snapshot, delta and statement carries the certificate `version`. A
   root-signed certificate with a higher version lets nodes accept a snapshot under it at any
   epoch, and from then on refuse every artifact of older versions (`wrong_version`), so the
   discarded history can't be replayed. Recovery from a restore: get the root to sign a certificate
   with `version + 1` and call `Publisher::rotate`. Key rotation is the same operation.
5. **The node persists what it verified** (`cert.jws`, `snapshot.jws`, `deltas.jsonl`,
   `statements.json` with receipt times and the `issued_at` floor, `uses.log`), each write fsynced
   before the update is applied. `Replica::open` re-verifies everything and resumes in whatever mode
   the signed deadlines allow; any file that doesn't verify fails the load, and `Replica::reset`
   starts closed (keeping use counts) until a live statement arrives.
6. **Clock-skew guard.** Effective deadline = min(signed deadline, receipt + (deadline − `issued_at`)),
   capped at the certificate's `not_after`; `issued_at` may be at most 2 s ahead of the node's clock.
7. **Batching**: a delta carries a list of changes; `Publisher::stage` and `flush` batch them.

Also: zone policy is compiled once when an update is applied (#74's `CompiledZone`); a zone whose
globs don't compile can't be committed by the publisher, and if one arrives anyway it forbids
everything rather than being refused (refusing a signed delta would desynchronise the chain).

## Decisions

- **One generation per certificate version.** A version bump always means a fresh snapshot; the
  node is closed between accepting the new certificate and its snapshot, which catch-up sends right
  after it. Renewing a certificate (same version and key, later `not_after`) is routine.
- **Uses of counted grants are appended to `uses.log` and fsynced before the op is allowed.** Counts
  are per node, so a counted grant must name its box: one box lives on one node. The publisher refuses a
  counted grant without a box, and a node never honours one.
- **Use counts survive `Replica::reset`**: they are local and only ever restrictive.
- **The publisher trusts its own log's signatures** (it checks the chain, feed and versions on open,
  not the signatures, which older versions' keys made).
- **Approvals stay central** (implementation plan, 2026-11-11): `escalate(Approval)` only says
  whether the node is fresh enough to ask for or honour one.

## Not done here

- The transport and the subscriber loop (push over the ssh node channel, polling as fallback).
- Rotating the root key itself.
- After `Publisher::rotate`, a push subscriber needs a fresh `catch_up` (key, snapshot, statement):
  the subscriber loop should re-serve every connected node.
- Compacting the publisher's delta log; nodes compact theirs when sent a snapshot at their own
  epoch (`Publisher::snapshot`).
- A `cargo fuzz` target: the parser is covered by a deterministic mutation loop in the unit tests.
- Mode uses the wall clock, so a node clock stepping backwards after a statement arrives extends
  that statement on the node; run NTP with slewing.
- Snapshots are JSON; compress or move to a binary encoding before nodes carry about 10k grants
  (2.25 MB).

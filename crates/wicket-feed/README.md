# wicket-feed

The signed policy feed that lets a node decide locally while the control host is unreachable, for
exactly as long as the tokens and grants it holds are valid (#57, #153, research 18 §5.1, architecture A). It ports the
`experiments/freshness-feed` prototype (experiment #60) and adds the changes its `RESULTS.md` §7
asks for.

It is a library: no sockets, no threads, no timers. Every call that depends on time takes `now`
(Unix ms) from the caller. The transport (ssh, in a later PR) carries `Frame`s, one JSON line each:
`{"t": "key|snap|delta|fresh", "jws": "…"}`.

## Pieces

| | where | what |
|---|---|---|
| format | `src/format.rs`, `src/jws.rs` | `KeyCert`, `Snapshot`, `Delta`, `Fresh`, `Frame`; compact JWS (Ed25519), `typ` per kind |
| state | `src/state.rs` | policy entries behind the `Policy` trait, compiled once when applied; grants, revocations, epoch and head |
| tokens | `src/token.rs` | `BoxAuthority`: one box's authority as a Biscuit token chain (`wicket-authz`), what nodes decide with; `Issuer`: the control plane's side |
| node | `src/replica.rs` | `Replica`: verify, persist, apply, refuse; `mode`; `decide`; `escalate` |
| control plane | `src/publisher.rs` | `Publisher`: durable delta log, batching, snapshots, statements, catch-up, re-genesis |

## Format

- A pinned **root key** (offline) signs a `KeyCert` for each node feed's online **feed key**:
  `kid, x, version, not_after, max_ttl_ms` (an older certificate's `max_narrow_ms` is accepted and ignored).
- The feed key signs, for one node (`feed` = node id) and one certificate `version`:
  - a **snapshot**: zones, grants, revocations at an epoch, with the chain head;
  - **deltas**: epoch n−1 → n, a batch of changes, with `prev` = head(n−1); head(n) = sha256(delta JWS);
  - **freshness statements**: epoch, head, `issued_at`, `fresh_until` (an older statement's `narrow_until` is accepted and ignored).
- **Grants** are bound to `Op::digest` (tenant, zone, method, host, path), with `not_after` (node
  clock), an optional use count (counted on the node) and an optional box (run id).
- **Revocations** name a grant, run or token id, with `until` (the revoked thing's own expiry):
  snapshots drop entries past it, so the set stays bounded.

## Payloads

The feed is generic over its entries (`Policy`):

- **`BoxAuthority`** (what `wicket node serve` runs on, #76 design A), keyed by run id:
  - the box's whole token: block 0 minted by the control plane's authority root key with the
    zone's ceiling, a spawn block per link below it, and a third-party block per live grant;
  - the box's path and epoch (the token's `box` and `epoch` facts);
  - the zone block 0 was minted from, used only where it can't widen authority: the pre-TLS host
    verdict, which hosts are forwarded, and limits;
  - each grant's id, request and use cap.

  A node loads each token once, when its delta applies: signatures against the pinned authority
  root (`authz-root.pub`, installed at enrolment), every block's revocation id against the feed's
  revocation list, the strict structural check, then the compiled evaluator under its step budget.
  Requests are decided by `wicket_authz` (Allow / NeedsGrant / Forbidden), mapped onto the modes
  below. A `NeedsGrant` tries the record's grants for that exact request one at a time (the token's
  grant rule needs a `uses_left` fact, which the node supplies from its own count), so the node
  knows which grant to count, and a grant without a block in the token never fires.
- **`ZoneSpec`**, the original payload: zone policies compiled into `CompiledZone`, with the feed's own
  grant records. Kept as the differential oracle (`tests/tokens.rs` checks token decisions match it
  on every example and subset-test zone, fresh and offline).

**Revocation by block id.** `Revoke { kind: Token, id }` names a block's revocation id (hex) and
refuses every token containing that block. Revoking a spawn block therefore revokes the box it
started and every box below it. Held revocations are checked at load; one that arrives later
invalidates loaded tokens when its delta applies. `Revoke { kind: Grant }` stops one grant.

**Grant blocks are appended on the control host, and the whole token is shipped.** Biscuit can't
parse a lone third-party block (`wicket_authz::SignedGrant` has no `from_bytes`). The control host
holds the approver key, so it has no need to send one. It rebuilds the token from its unchanged base
with the live grants whenever they change. Dead grants then drop out, the chain stays under the
structural block cap (at most `token::MAX_GRANTS` = 10 live grants per box), and the base's
revocation ids stay stable. The alternative, a parser in the vendored fork, is only needed once
approvals are signed somewhere else (an approval service, or a parent box's grantor on another
node).

## Modes

| mode | when | allowed |
|---|---|---|
| fresh | a statement names an epoch the node holds, before its effective `fresh_until` | the token and its live grants; leases, spawns, approvals |
| offline | verified state that a statement once vouched for, and no live statement | the token and its live grants, each until its own expiry; no leases, spawns or approvals |
| lagging | a live statement names an epoch the node doesn't hold | nothing, until the deltas arrive |
| closed | no state, a feed key past its certificate, or nothing ever vouched for the state | nothing |

`Forbidden` stays forbidden and revoked runs are refused in every mode; token and grant expiry is by the
node's clock in every mode. There is no separate offline window (#153): a node works alone for as long
as what it holds is valid, and `Replica::authority_until(run)` says when a box's token stops allowing
anything (the earliest expiry of its first-party blocks), so the node can stop the box then.

`Replica::decide(op, now)` returns `Allow(Reach | Ceiling | Grant)`, `NeedsGrant` (the caller raises it,
or queues it offline), `Forbidden` or `Refused { mode }`. `Replica::escalate` answers whether the node
may issue a lease, start a spawn or sign an approval (fresh only).

## Defaults and bounds

TTL 30 s, refresh 5 s (`DEFAULT_*`; `PublisherConfig` overrides them, within the certificate's cap).
Statements issued up to 2 s in the future (node clock) are accepted.

- Revocation of grants, tokens and runs: when the delta applies (about 1 ms with push). A node that
  hears nothing keeps what it holds until it expires: the revoked thing's remaining lifetime.
- The feed key's certificate caps everything a node holds.

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

- Child boxes on a node. `Issuer::child` appends spawn blocks, and the tests cover subtree
  revocation on the node, but `wicket run --node` mints every run's token from block 0. A run
  started under a parent run doesn't yet get its parent's chain plus a spawn block.
- Spawn, model and message decisions through the token on the node. Those stay on the control
  host for now; the node decides egress.

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

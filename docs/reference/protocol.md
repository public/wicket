# Protocol and version skew

## Responses to the box

Every refusal is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) `application/problem+json`
response with an `x-wicket: <kind>` header, and a status line that says what happened, since many
tools show only that (`403 Blocked by wicket sandbox: needs human approval (r-1a2b3c4d)`). The body:

```json
{
  "type": "https://wicket.dev/e/pending-approval",
  "title": "Blocked by wicket sandbox: needs human approval",
  "status": 403,
  "detail": "…",
  "request_id": "r-1a2b3c4d",
  "retry_after": 30,
  "hint": "Call the wicket MCP tool await_grant with request_id r-1a2b3c4d to wait for a human's decision, then retry this same request once. …"
}
```

`request_id`, `retry_after` and `hint` are there only when there is a request to wait on, which also
adds the headers `x-wicket-request-id` and `retry-after: 30`.

| kind | status | title (or meaning) |
|---|---|---|
| `pending-approval` | 403 | Blocked by wicket sandbox: needs human approval. A pending request exists; retries deduplicate onto it. |
| `queued` | 403 | Needs human approval (queued offline): a node raised it while the control host was away; the id is node-local, `q-…`. |
| `denied` | 403 | Denied by a human. |
| `forbidden` | 403 | Never allowed (a `forbid` rule, a metadata endpoint, a non-public address), or a malformed request. |
| `unavailable` | 403 | Control plane unreachable: a node can't decide this without the control host. |
| `misdirected` | 421 | Wrong host for this connection: an HTTP/3 connection serves one host only. |
| `budget` | 429 | The model budget, or a node's slice of it, is spent. |
| `stale-generation` | 409 | This activation of a long-lived agent was superseded. |
| `unknown-host` | 502 | The name doesn't resolve upstream. |
| `upstream` | 502 | The upstream failed. |
| `audit-unavailable` | 503 | The audit record a grant-allowed request depends on couldn't be committed, so the request wasn't sent. |
| `credential` | 503 | The model credential isn't cached on this node and the control host is unreachable. |
| `bad-request`, `route`, `no-model` | 400, 404 | Not a proxy request, not a model route, or no model configured. |
| `error` | 500 | A ledger error. |

## The node control channel

Between a control-host process (a `wicket run`, or a link relay) and a node's `wicket node serve`:
one multiplexed, length-prefixed byte stream, over ssh (`ssh <node> wicket node attach`, which joins
the session to `serve`'s unix socket), or over that socket directly for this host's own node. The
code is `crates/wicket-cli/src/chan.rs`.

- **Frames.** A 4-byte big-endian length, then one kind byte and the body: `1` a JSON control
  message, `2` data (stream id and byte offset, each a big-endian u64, then the bytes: a box's stdio
  or a tunnel's), `3` a feed frame (control host to node only). A bad frame drops the connection.
- **Authentication.** ssh checks the node's pinned host key. On top of it, before anything else, the
  node proves its node key and shows its identity certificate, and the control host proves the
  issuer key (`Hello`'s nonce, `Challenge`, `Prove`). The handshake doesn't depend on ssh.
- **Integrity of policy** comes from the feed's own signatures, not the channel: a tampered,
  replayed or rolled-back feed frame is refused by the node's replica.
- **Streams** carry byte offsets, so after a reconnect each side says where to resume and drops
  duplicates. Tunnels (a forwarded CONNECT, or a connection to the run's model or MCP socket) are
  numbered by the node with the top bit set, and die with the connection.
- **Scopes.** Each connection names what it is for (a run, or a link relay's `links:<run>`); a newer
  connection for the same scope replaces the older one, and no other.

## Versions and skew

The control channel is versioned. `Hello` and `Welcome` carry the protocol version each end speaks;
two ends talk if the versions are **at most one apart**, at the lower one. So:

- a control host at N talks to nodes at N−1 and N (the rollout: control host first);
- a node at N talks to a control host at N−1 (the control host rolled back) and N+1.

`wicket self update` refuses a build more than one protocol version from the running one. A message
added in version N is sent only on a connection that negotiated N or later, since an older peer
drops a connection on a message it can't parse; a field added with a default needs no new version.
Support for N−1 is removed only after a release that spoke N everywhere. The build (sha256) is still
exchanged, for the logs and for the health gate.

| version | adds |
|---|---|
| 1 | Versions (#162). |
| 2 | Box tokens minted by a certified authority issuing key, carrying its certificate (#154). Needed once the roots are offline: `wicket keys roots-offline` refuses while a node talks 1, and a run on such a node is refused after. |
| 3 | Budget slices (`Lease`), secrets fetched by a node on first use (`SecretFetch`, `SecretFetched`, `SecretRevoke`) and the node's model spend (`Spent`) (#152, #153). With an older peer a node relays model calls and forwards injected hosts to the control host, as before. |
| 4 | Block 0 may carry an org layer compiled from the org policy (#51), which an older node's structural check refuses: such tokens go only to nodes talking 4, and `wicket policy apply` refuses while one doesn't. |
| 5 | Decisions at the edge (#164): `BoxStart.edge` (what the node decides gateway tools and spawns from: the identity's stable claims, the box's manifest, base token, grant keys, time and slots), `Spawned` and `Adopted` (a child the node started, and its takeover), `Ask.prefix`, and `Listen.dial` (a link the node carries between its own boxes). With an older peer a node relays every gateway tool call, as before. |

| 6 | Images pinned by digest (#192): `BoxStart.image_pin`, which the node checks against the image it starts (then started by its id), and the digest it started in `Started` and `Spawned`. A pinned box goes only to a node talking 6. |

wicket speaks version 6.

## Ledger schema

The ledger (and each node's `audit.db`, which is the same store) records its **schema version**
(the newest that has opened it) and its **floor** (the oldest that may open it) in `schema_meta`.
wicket 0.0.1 is at schema 1, floor 1.

- **Expand** steps (a new table, a new column with a default, a new index) bump the version and leave
  the floor: older builds ignore what they don't know, so a rollback across them is safe.
- **Contract** steps (dropping or rewriting anything an older build reads) raise the floor. A build
  below the floor refuses to open the ledger, and `wicket self rollback` refuses to switch to it. A
  contract step ships only in a release after the one whose expand step stopped anything reading the
  old shape.

## Audit records and checkpoints

The exported record and checkpoint formats, and the hash versions, are in [audit](audit.md).

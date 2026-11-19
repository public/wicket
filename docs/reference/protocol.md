# Protocol and version skew

## Responses to the box

Every refusal is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) `application/problem+json`
response with an `x-wicket: <kind>` header, and a status line that says what happened, since many
tools show only that (`403 Blocked by wicket box: needs approval (r-1a2b3c4d)`). The body:

```json
{
  "type": "https://wicket.dev/e/pending-approval",
  "title": "Blocked by wicket box: needs approval",
  "status": 403,
  "detail": "…",
  "request_id": "r-1a2b3c4d",
  "retry_after": 30,
  "hint": "Call the wicket MCP tool await_grant with request_id r-1a2b3c4d to wait for the decision, then retry this same request once. …"
}
```

`request_id`, `retry_after` and `hint` are there only when there is a request to wait on, which also
adds the headers `x-wicket-request-id` and `retry-after: 30`.

| kind | status | title (or meaning) |
|---|---|---|
| `pending-approval` | 403 | Blocked by wicket box: needs approval. A pending request exists, for an operator (or an agent above the box) to decide; retries deduplicate onto it. |
| `queued` | 403 | Needs approval (queued offline): a node raised it while the control host was away; the id is node-local, `q-…`. |
| `denied` | 403 | Denied, by an operator or an agent above the box. |
| `forbidden` | 403 | Never allowed (a `forbid` rule, a metadata endpoint, a non-public address), or a malformed request. |
| `unavailable` | 503 | Control host unreachable: a node can't decide this right now (catching up with its feed, no valid policy, or the control host is unreachable). Temporary, so it carries `retry-after: 5` and `retry_after`, and clients retry it; a model call is held up to 3 s first, in case the node catches up. |
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
code is `crates/wicket-chan/src/chan.rs`.

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

`wicket self update` takes a build more than one protocol version from the running one only as a
jump that switches the control host and every active enrolled node together, and refuses it while
any is left out, naming them ([updates](../explanation/updates.md#protocol-versions-and-skew)). A message
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
| 7 | Images delivered over the channel (#191): `ImageHave` (does the node have this digest), and `PutImage`, an OCI image layout archive on a control-host stream whose data frames the node acknowledges (`Ack`) as it takes them, ended by `Close` and answered by `ImagePut` once the node has verified and imported it, or refused it. With an older node, the image must be there already. |
| 8 | Images pulled by the node from an allowlisted registry, host-side (#191): `PullImage` (the digest, the registry and repository, the hosts the pull may reach and the name of the registry's secret, which the node fetches for the run) and `ImagePulled`. With a node talking 7, the image is sent instead. |
| 9 | A run's budget slice is `BudgetSlice` (it was `Lease`, #256: "lease" names only a grant of capacity). No alias: a node talking 8 is sent no slice, and a box with a model budget doesn't start on it. |
| 10 | Credential swaps on the node (#257): `BoxStart.swaps`, each fetched with `SecretFetch` on first use and swapped by the node's own egress proxy, which then decides the swapped hosts from the feed. A box with swaps went only to a node talking 10. |
| 11 | No forwarded egress (#257): a node terminates what its CA covers and decides it, splices a host its CA can't cover if the box's token allows it wholesale, and refuses it otherwise. The control host no longer serves the `egress` tunnel target, and `BoxStart.swap_hosts` is gone. |
| 12 | Node health (#377): a node reports its disk, inodes, memory, feed freshness and failures as `Health`, sent only on connections talking 12. |
| 13 | One gateway, on the node (#257 slice 4b): the tools a box's node doesn't answer itself reach the control host as `Call` (one of `ControlTool`, the control host's tools by name, with the box's arguments), answered with `Called`, instead of JSON-RPC relayed through a `gateway` tunnel (gone, with the run's `ctl/gateway.sock`). A box starts only on a node talking 13. |
| 14 | Node CA renewal over the channel (#416): `CaRenew` (make a new CA key), `CaCsr` (its signing request, or why not), `NodeCa` (its certificate) and `NodeCaInstalled` (installed for every box, or why not), sent at half the CA's life. A node talking 13 is renewed with `wicket node renew-ca` over ssh, as before. Node health reports carry the CA's validity (`ca_not_before`, `ca_not_after`, defaulted fields). |
| 15 | Messages in flight until the box has had them (#445): `MessageRead` (node to control host) once a message the control host's `await_message` gave reaches the box, or is pushed to its session. Until then the message is in flight, and a supervisor that takes the run over gives it again; the node drops one its box has had. With a node talking 14, the control host counts a message read as it hands it over, as before. |
| 16 | Path-prefix grants on nodes (#257 4a): a prefix grant ("every path under `/repos/acme/app/`") goes in a box's token as the prefix it is, a block `approved(gid, host, method, $p) <- path($p), $p.starts_with(prefix), …` the node's structural check admits only with a canonical prefix ending in `/`, so it covers the directory and every path under it, whole segments only, as the ledger does. To a node talking 15 the control host sends it for its own path exactly, as before (that node's check would refuse the whole token). |
| 17 | Standing reach (#572): `AskStanding` (node to control host), a box's `request_access` with scope `standing`, answered with `Asked` (which also carries `hint`, for an agent asking for the same thing again: an optional field, which an older node ignores). The control host publishes an approved standing rule to a node at 17 as a block of the box's token. A node at 15 or 16 neither asks for nor honours one: the box is told its control host or node must be updated, and asks as before. |

wicket speaks version 17 with a skew of 2 (#572 followed #568's 16 within a release, so a control host can go from 15 to 17 while its nodes still talk 15): it talks only to peers at 15, 16 and 17. What the rows above say happens
with an older peer (a node relaying every gateway tool before 5, a box refused by a node before 6,
9, 10 or 11, an image not sent to a node before 7, a box on a node before 13) is history: no
connection can negotiate below 15. Every connection has 12's health reports, 13's one gateway and
14's CA renewal. A check for a version's feature matters only while a peer below it can connect:
15's message reads, 16's prefix grants and 17's standing reach keep theirs while a node at 15 or 16
can. `BoxStart`'s `ca_pem` and
`workspace_tar` are always empty and no node reads them; they are defaulted, and go once no peer
from before that can connect.

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

# One decision path: only the node decides

Plan for [#257](https://github.com/public/wicket/issues/257), part of
[#253](https://github.com/public/wicket/issues/253). It covers where the control host still decides
per request today, and the order in which that moves to the node.

## Rules every slice keeps

- Decisions are made at the edge, on the box's node, from the box's token in the node's verified
  feed replica.
- A message from a peer (a node, another box) never grants anything. It can only ask, and a human
  or a principal with grant rights decides.
- Every grant has a lifetime.
- Egress log lines and audit records stay the same. A slice that changes one says so in its
  changelog fragment.

## Where the control host decides per request today

Every box runs on a node (#146): an enrolled one, or the host's own built-in node (`localnode.rs`,
`node.json`'s `shares_host`). `wicket run` (`run.rs`) also starts the run's own proxies on
`<run>/ctl/*.sock`. The node reaches them through `Node::open_tunnel` (`nodesrv.rs`), using the socket itself
on the built-in node or a `TunnelOpen` over the run's channel elsewhere (`noderun.rs` accepts the
targets `egress` and `gateway`).

| where | what it decides | still needed because |
|---|---|---|
| `run.rs` → `Egress::new` on `ctl/egress.sock`, deciding through `decide::Central` (compiled zone + ledger: `consume_grant`, `denied_recently`, `pending_for`) | every request to a host the node forwards instead of terminating (`decide::route_sealed`) | credential swaps (remote and wrapped sessions, #169/#112) are made only on the control host; hosts outside the node CA's name constraints, or a node with no CA or an expired one |
| the same egress's model gate (`Egress::set_model_gate`) | budget and filter for model calls made through egress (wrapped sessions) | it sits on the forwarded swap path above |
| `run.rs` → `Gateway::new` on `ctl/gateway.sock` (`wicket-proxy/src/gateway.rs`) | every gateway tool the node relays: `decide`, `expose`/`connect`/`link`/`unlink`/`links`, `finish`, `hibernate`; `send_message`, `request_capacity`, `request_update` while connected; spawns the node doesn't start itself; the control-host side of `await_grant`/`pending_requests`; `tools/list` and `initialize` | these tools need the ledger, the other boxes' records or the placement backend, and the node relays them as raw JSON-RPC |
| `run.rs` → `Llm::new` on `ctl/llm.sock` | nothing: since #152 the node's model proxy holds the credential (fetched with `SecretFetch`) and calls the model itself; `Llm::relayed`'s relay runs only when the vault isn't sourced, which never happens on a node | **removed in slice 1** |
| `noderun::ask` / `check_node_ask` / `check_node_op` | raises a pending request for a node's ask, after checking the op belongs to the run's own tenant, run and zone | this is issuance, not a decision: it stays (a peer message only asks) |
| `noderun::sync_grants` | turns ledger grants into Biscuit grant blocks (`LiveGrant`) on the feed, and renewals into re-minted blocks | the ledger is still where a grant is recorded *and* consumed for the forwarded egress path above |
| `nodesrv.rs` `shares_host` branches | transport only: where the box is laid out, the run's sockets reached directly, host directories mounted, the CA loaded unconstrained (`NodeCa::load_any`) | the built-in node shares the host's filesystem; none of these is a decision |

The node side, for comparison: `NodeDecider` (egress, from the replica), `nodegw.rs` (`whoami`,
`request_access`, `await_grant`, `pending_requests`, `spawn`/`spawn_agent`, `send_message` and
`await_message` while cut off, `request_capacity`/`request_update` queued while cut off) and the
node's own `Llm`.

## Staged plan

1. **Slice 1 (this branch): the model proxy runs only on the node.** `run.rs` stops listening on
   `ctl/llm.sock`. Its `Llm` stays as the run's budget counter (the node's `Spent` reports are
   merged into it, slices are leased from it, and the egress model gate uses it). `Llm::relayed`,
   `LlmRelay` and the `llm` tunnel target go. No protocol bump: every node within
   `PROTOCOL_SKEW` of protocol 8 is at protocol 3 or later (#152), so it fetches the credential and
   never opens that tunnel.
2. **Slice 2: credential swaps on the node.** `BoxStart` carries the swaps (placeholder, and the
   secret's name or a value), and the node fetches swapped secrets as it does injected ones
   (#152). Then `route_sealed` forwards only hosts the node's CA can't cover. Protocol 9: a box with
   swaps goes only to a node at 9 or later. Grant uses on swapped hosts are then counted on the
   node, from the feed.
3. **Slice 3: no forwarded egress.** A node whose CA can't cover a host refuses it (or splices it
   when its token allows the host wholesale) instead of forwarding it. The local node's CA is
   unconstrained already. `Central` and the `egress` tunnel target go, and the ledger stops
   consuming grants: it records issuance and `sync_grants` only publishes.
4. **Slice 4: one gateway, on the node.** `tools/list`, `initialize` and every tool are answered by
   `nodegw.rs`. Tools that need the control host (link tools, `decide`, `finish`/`hibernate`,
   capacity, update, messages to boxes on other nodes) go as typed channel messages that ask
   (`Msg::Ask`'s pattern), not as relayed JSON-RPC. `wicket-proxy/src/gateway.rs`'s tool bodies
   and spawn's `--parent-run` re-exec path go. This is protocol 10, behind #241's jumps.
5. **Slice 5: `run.rs` starts no proxies.** With nothing left on `ctl/*.sock`, the run supervisor
   keeps the vault, the ledger, approvals and the feed. The control host is forward-only: it relays
   secrets and asks, and decides nothing per request.

Each slice has to pass the node e2e flow (`ci/node-e2e.sh`, also run by `ci/acceptance.sh --nodes local`) and the acceptance
suite unchanged.

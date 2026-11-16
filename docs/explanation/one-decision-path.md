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
`node.json`'s `shares_host`). `wicket run` (`run.rs`) also starts the run's own gateway on
`<run>/ctl/gateway.sock`. The node reaches it through `Node::open_tunnel` (`nodesrv.rs`), using the socket itself
on the built-in node or a `TunnelOpen` over the run's channel elsewhere (`noderun.rs` accepts the
target `gateway`; `egress` went with slice 3, `llm` with slice 1).

| where | what it decides | still needed because |
|---|---|---|
| `run.rs` → `Egress::new` on `ctl/egress.sock`, deciding through `decide::Central` (compiled zone + ledger: `consume_grant`, `denied_recently`, `pending_for`) | every request to a host the node forwarded instead of terminating | **removed in slice 3**: a host the node CA can't cover is spliced (if the box's token allows it wholesale) or refused on the node (`decide::route`, `Route::Uncovered`) |
| the same egress's model gate (`Egress::set_model_gate`) | budget and filter for model calls made through egress (wrapped sessions) | **removed in slice 3**, with the forwarded path; since slice 2 the node's egress takes its own model proxy as its gate |
| `run.rs` → `Gateway::new` on `ctl/gateway.sock` (`wicket-proxy/src/gateway.rs`) | every gateway tool the node relays: `decide`, `expose`/`connect`/`link`/`unlink`/`links`, `finish`, `hibernate`; `send_message`, `request_capacity`, `request_update` while connected; spawns the node doesn't start itself; the control-host side of `await_grant`/`pending_requests`; `tools/list` and `initialize` | these tools need the ledger, the other boxes' records or the placement backend, and the node relays them as raw JSON-RPC |
| `run.rs` → `Llm::new` on `ctl/llm.sock` | nothing: since #152 the node's model proxy holds the credential (fetched with `SecretFetch`) and calls the model itself; `Llm::relayed`'s relay runs only when the vault isn't sourced, which never happens on a node | **removed in slice 1** |
| `noderun::ask` / `check_node_ask` / `check_node_op` | raises a pending request for a node's ask, after checking the op belongs to the run's own tenant, run and zone | this is issuance, not a decision: it stays (a peer message only asks) |
| `noderun::sync_grants` | turns ledger grants into Biscuit grant blocks (`LiveGrant`) on the feed, and renewals into re-minted blocks | publication, not a decision: since slice 3 it only publishes (every egress grant, whatever its host), and the ledger only records issuance. `Ledger::consume_grant` refuses an egress op; it still consumes wicket's own SPAWN and LINK grants for the control-host gateway (slice 4) |
| `nodesrv.rs` `shares_host` branches | transport only: where the box is laid out, the run's sockets reached directly, host directories mounted, the CA loaded unconstrained (`NodeCa::load_any`) | the built-in node shares the host's filesystem; none of these is a decision |

The node side, for comparison: `NodeDecider` (egress, from the replica), `nodegw.rs` (`whoami`,
`request_access`, `await_grant`, `pending_requests`, `spawn`/`spawn_agent`, `send_message` and
`await_message` while cut off, `request_capacity`/`request_update` queued while cut off) and the
node's own `Llm`.

## Staged plan

1. **Slice 1 (done, #317): the model proxy runs only on the node.** `run.rs` stops listening on
   `ctl/llm.sock`. Its `Llm` stays as the run's budget counter (the node's `Spent` reports are
   merged into it, slices are leased from it, and the egress model gate uses it). `Llm::relayed`,
   `LlmRelay` and the `llm` tunnel target go. No protocol bump: every node within
   `PROTOCOL_SKEW` of protocol 8 is at protocol 3 or later (#152), so it fetches the credential and
   never opens that tunnel.
2. **Slice 2 (done): credential swaps on the node.** `BoxStart::swaps` carries each swap: its
   host, its placeholder, and either the vault secret's name or, for a value the launcher handed
   the control host, a key it is fetched by (`swap.<n>`). It never carries the value, since the
   node keeps the start in its box record. The node fetches swapped secrets with `SecretFetch`, as
   it does injected ones (#152). `nodesecrets::release_run` releases them for the swap's hosts
   only. `route_sealed` forwards only hosts the node's CA can't cover, plus the `swap_hosts` of a
   box a control host at protocol 9 started. Protocol 10 (`chan::CREDENTIAL_SWAPS`; #316 took 9 for
   `BUDGET_SLICE`): a box with swaps goes only to a node at 10 or later. `sync_grants` hands grants
   on swapped hosts to the node, so their uses are counted there, from the feed. The node's
   egress takes its own model proxy as its model gate (`Egress::set_model_gate`), so a wrapped
   session's model calls, whose login is now swapped on the node, keep their budget and filter.
3. **Slice 3 (done): no forwarded egress.** A node whose CA can't cover a host (outside its name
   constraints, or no live CA) refuses it, or splices it when the box's token allows the host
   wholesale, instead of forwarding it (`decide::route` → `Route::Uncovered`; `Egress::refuse_uncovered`).
   The local node's CA is unconstrained already. `Central`, `forward_connect`, the `Relay` trait's
   tunnel and the `egress` tunnel target go, and so do `ctl/egress.sock` and `BoxStart::swap_hosts`.
   Plain `http://` needs no certificate, so the node decides it whatever its CA covers. The ledger
   stops consuming egress grants (`Ledger::consume_grant` refuses an egress op;
   `Ledger::grant_covering` looks one up without using it): it records issuance, and `sync_grants`
   only publishes, every egress grant included. A grant the node can't honour as approved (a risk
   bound a query could exceed, #119, or one its token can't load) is never published, so the box's
   request is asked again; one past `MAX_GRANTS` waits for room. Protocol 11
   (`chan::NO_FORWARDED_EGRESS`): a box that a node before 11 would forward a known host of (a reach,
   inject or swap host outside that node's CA, or any host without a live CA, `noderun::forwarded_host`)
   goes only to a node at 11 or later (`refuse_older_node`). Egress lines: a refused uncovered host
   is a `forbidden` line (`not served on this node (<why>)`), where it was a `forwarded` one; the
   control host's own `grant …; used by …` details (and their `WARNING: approved for …`) are gone
   with Central. Audit records are unchanged.
4. **Slice 4: one gateway, on the node.** `tools/list`, `initialize` and every tool are answered by
   `nodegw.rs`. Tools that need the control host (link tools, `decide`, `finish`/`hibernate`,
   capacity, update, messages to boxes on other nodes) go as typed channel messages that ask
   (`Msg::Ask`'s pattern), not as relayed JSON-RPC. `wicket-proxy/src/gateway.rs`'s tool bodies
   and spawn's `--parent-run` re-exec path go. This is protocol 12, behind #241's jumps.
5. **Slice 5: `run.rs` starts no proxies.** With nothing left on `ctl/*.sock`, the run supervisor
   keeps the vault, the ledger, approvals and the feed. The control host is forward-only: it relays
   secrets and asks, and decides nothing per request.

Each slice has to pass the node e2e flow (`ci/node-e2e.sh`, also run by `ci/acceptance.sh --nodes local`) and the acceptance
suite unchanged.

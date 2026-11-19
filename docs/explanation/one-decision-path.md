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
`node.json`'s `shares_host`). Since slice 4b the box's gateway is the node's (`nodesrv/gateway.rs`):
the tools only the control host can answer reach the run's `Gateway` (`run.rs`, in the supervisor's
process) as typed calls, `Msg::Call` over the run's channel, answered by `noderun`. No socket of the
run's is a tunnel target any more (`llm` went with slice 1, `egress` with slice 3, `gateway` with 4b).

| where | what it decides | still needed because |
|---|---|---|
| `run.rs` → `Egress::new` on `ctl/egress.sock`, deciding through `decide::Central` (compiled zone + ledger: `consume_grant`, `denied_recently`, `pending_for`) | every request to a host the node forwarded instead of terminating | **removed in slice 3**: a host the node CA can't cover is spliced (if the box's token allows it wholesale) or refused on the node (`decide::route`, `Route::Uncovered`) |
| the same egress's model gate (`Egress::set_model_gate`) | budget and filter for model calls made through egress (wrapped sessions) | **removed in slice 3**, with the forwarded path; since slice 2 the node's egress takes its own model proxy as its gate |
| `run.rs` → `Gateway::new`, answering the node's `Msg::Call` (`wicket-gateway/src/lib.rs`) | the `chan::ControlTool`s: `decide`, `expose`/`connect`/`link`/`unlink`/`links`, `finish`, `hibernate`; `send_message`, `await_message`, `request_capacity`, `request_update` while connected; spawns the node doesn't start itself; operator-held `await_grant`/`pending_requests`; `principals`, `receipts`, `delegations`, `continue_child` | these tools need the ledger, the other boxes' records, the placement backend or the run's supervisor; since 4b they are typed calls, not relayed JSON-RPC |
| `run.rs` → `Llm::new` on `ctl/llm.sock` | nothing: since #152 the node's model proxy holds the credential (fetched with `SecretFetch`) and calls the model itself; `Llm::relayed`'s relay runs only when the vault isn't sourced, which never happens on a node | **removed in slice 1** |
| `noderun::ask` / `check_node_ask` / `check_node_op` | raises a pending request for a node's ask, after checking the op belongs to the run's own tenant, run and zone | this is issuance, not a decision: it stays (a peer message only asks) |
| `noderun::sync_grants` | turns ledger grants into Biscuit grant blocks (`LiveGrant`) on the feed, and renewals into re-minted blocks | publication, not a decision: since slice 3 it only publishes (every egress grant, whatever its host), and the ledger only records issuance. `Ledger::consume_grant` refuses an egress op. wicket's own SPAWN and LINK grants are used where the spawn or link is made, on the control host, by `Ledger::use_effect_grant` with #369's binding to the call's arguments (`spawn.rs`, `wicket-gateway/src/link.rs`) |
| `run.rs` → `control::Supervised`, `wicket-home/src/control.rs` `Prompts` (#363) | a driven harness's tool-permission prompts: `Ledger::consume_grant` on `TOOL wicket.internal /tools/<tool>/<digest>`, `denied_recently`, then `pending_for` | **per tool call, on the control host**: the last per-request decision there, and `consume_grant`'s last caller outside tests. While the control host is unreachable a prompt waits. Step 4 below |
| `wicket-gateway` `send_message` (connected) and `nodegw::send_local` (cut off) | who may message whom: parent or child, the receiver's `accept_from`, its org layer | **decided twice**, by the control host from identities and records, and by the node from both boxes' tokens. Step 3 below |
| `run.rs` → `Llm::with_quota` | the run's model budget: its total, its children's carve-outs, the slices it leases its node, the node's `Spent` merged in | quota issuance, not a per-call decision; but it builds the whole model proxy (`wicket_proxy::llm::Llm`) to use its counter. Step 2 below |
| `nodesrv.rs` `shares_host` branches | transport only: where the box is laid out, the run's sockets reached directly, host directories mounted, the CA loaded unconstrained (`NodeCa::load_any`) | the built-in node shares the host's filesystem; none of these is a decision |

The node side, for comparison: `NodeDecider` (egress, from the replica), `nodegw.rs` (`whoami`,
`request_access`, `await_grant`, `pending_requests`, `spawn`, `send_message` and
`await_message` while cut off, `request_capacity`/`request_update` queued while cut off) and the
node's own `Llm`.

## Staged plan

1. **Slice 1 (done, #317): the model proxy runs only on the node.** `run.rs` stops listening on
   `ctl/llm.sock`. Its `Llm` stays as the run's budget counter (the node's `Spent` reports are
   merged into it, slices are sent from it, and the egress model gate uses it). `Llm::relayed`,
   `LlmRelay` and the `llm` tunnel target go. No protocol bump: every node within
   `PROTOCOL_SKEW` of protocol 8 is at protocol 3 or later (#152), so it fetches the credential and
   never opens that tunnel.
2. **Slice 2 (done): credential swaps on the node.** `BoxStart::swaps` carries each swap: its
   host, its placeholder, and either the vault secret's name or, for a value the launcher handed
   the control host, a key it is fetched by (`swap.<n>`). It never carries the value, since the
   node keeps the start in its box record. The node fetches swapped secrets with `SecretFetch`, as
   it does injected ones (#152). `nodesecrets::release_run` releases them for the swap's hosts
   only. `route_sealed` forwards only hosts the node's CA can't cover, plus the `swap_hosts` of a
   box a control host at protocol 9 started. Protocol 10 (#316 took 9 for the budget slice): a box
   with swaps went only to a node at 10 or later, a check gone since no peer talks below 11. `sync_grants` hands grants
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
   request is asked again; one past `MAX_GRANTS` waits for room. Protocol 11:
   a box that a node before 11 would have forwarded a known host of went only to a node at 11 or
   later; with protocol 12 no peer talks below 11, and that check is gone. Egress lines: a refused uncovered host
   is a `forbidden` line (`not served on this node (<why>)`), where it was a `forwarded` one; the
   control host's own `grant …; used by …` details (and their `WARNING: approved for …`) are gone
   with Central. Audit records are unchanged.
4. **Slice 4: one gateway, on the node.** `tools/list`, `initialize` and every tool are answered by
   `nodegw.rs`. Tools that need the control host (link tools, `decide`, `finish`/`hibernate`,
   capacity, update, messages to boxes on other nodes) go as typed channel messages that ask
   (`Msg::Ask`'s pattern), not as relayed JSON-RPC. `wicket-proxy/src/gateway.rs`'s tool bodies
   and spawn's `--parent-run` re-exec path go. This is protocol 13 (12 is node health's, #377),
   behind #241's jumps.
   - **4a (done): what was already the node's.** The node answers MCP's own methods (`initialize`,
     `ping`, `tools/list`, notifications) itself, with the one implementation
     (`wicket_proxy::gateway::handshake`), connected or not: they are never relayed. The control
     host's copies of `whoami` and `request_access`, which the node always answered, are gone,
     and so are the branches for peers before protocol 5 (`EDGE_DECISIONS`), which
     `PROTOCOL_SKEW` no longer lets connect. No protocol change.
   - **4b (done): typed calls, no relay.** Protocol 13. The tools only the
     control host answers are a closed set, `chan::ControlTool`. The node asks them as
     `Msg::Call { id, run, tool, args }` over the run's channel and gets `Msg::Called { id, text,
     is_error }`; `noderun` answers with the run's `Gateway::call_tool` in the supervisor's
     process. A name outside the set never leaves the node. A call waits as long as its tool may
     (`await_grant`, `await_message`) and fails at once if the run's connection drops. Gone:
     `relay_rpc`, `relay_or_offline`, `gateway_offline`, the gateway's HTTP server
     (`Gateway::serve*`), `ctl/gateway.sock`, the `gateway` tunnel target (`TUNNEL_TARGETS`,
     `Node::open_tunnel`, `noderun`'s tunnel handler), and `refuse_older_node`'s per-feature
     floors and `forwarded_host`, all below 13. A box went only to nodes at 13 or later; with
     protocol 15 no peer talks below 14, and that check (`refuse_older_node`) is gone too.
   - **4c (done): a child's supervisor in its parent's process.** A spawn the node doesn't start
     (placement on another node, an org layer not alike, a renewed authority, beyond the zone) is a
     `ControlTool::Spawn` call that `noderun` answers itself with `spawn::tool`, and a child the
     node started is adopted as before; either way the child's supervisor (`run::run`) runs on a
     thread of the parent's process with its own runtime, printing to `children/<run>.log`, and
     its parent stops it through a `Notify` instead of a SIGINT. A thread can't be killed, so a
     supervisor that hasn't ended 30 s after its stop (`spawn::stop_children`, #409) is recorded
     as stuck: a line in the parent's log, `run.child_stuck`, and `runs.stuck_at` (schema 14),
     which the reconciler reports and `wicket top` shows until a new supervisor takes the run. Gone: `launch_as`'s
     `wicket run --parent-run` re-exec, `Cmd::Run`'s `--parent-run`, `--lease` and `--adopt` and
     their daemon guards, `RunCtx.spawner`, the `Spawner` type and `Gateway::spawn`. A run's owner
     in the ledger is its process, so a parent and its children share one; if it dies the
     reconciler re-attaches each (`wicket attach`), as their own processes.
   - **The tool bodies (done, after #434).** The control host's tool bodies, the answerers of
     `ControlTool`s, are in the `wicket-gateway` crate (with the link tools in
     `link.rs` and the delegation tools in `delegate.rs`), which `noderun`
     asks: what needs the ledger is answered where the ledger is. wicket-proxy's
     gateway module keeps MCP's handshake, the tool list and a spawn's arguments, which the node
     reads. The deterministic simulation (`wicket-sim`) calls the bodies through
     `Gateway::call_tool` from the wicket-gateway library, without the rest of the control host.
5. **Slice 5 (done): `run.rs` starts no proxies.** (Its gateway socket went with 4b.) With nothing
   left on `ctl/*.sock`, the run supervisor keeps the vault, the ledger, approvals and the feed. The
   control host is forward-only: it relays secrets and asks, and decides nothing per request. Its
   own node's `shares_host` is transport only (where a box's files are laid out, what may be
   mounted, which boxes are its to reap); no branch on it decides. The run's own CA went too: the
   control host terminates no TLS, so a box trusts the installation root alone (`BoxStart.ca_pem`
   is sent empty, for nodes at 13 that read it).

## What's left (2026-11-19)

Slices 1-5 removed every per-request path #257 named. Read again on main, the control host still:

- **decides a driven harness's tool prompts** per call (`wicket-home`'s `Prompts`, #363);
- **decides message delivery twice**, once on the control host while the box's node is connected,
  once on the node while cut off;
- **builds the model proxy for a budget counter**: the run's `Llm` counts, carves, leases slices
  and merges `Spent`, and calls no model since slice 1.

What stays on the control host is issuance and lifecycle, as #253 keeps them: spawns it places
(and its check of a node-started child it adopts), links (both boxes' records, made there), an
agent's `decide`, capacity and update requests (the money check, #256), `finish` and
`hibernate`, the ledger reads (`principals`, `receipts`, `delegations`, a human's decision for
`await_grant` and `pending_requests`), and the model budget's total. The `shares_host` branches
are transport. The steps:

6. **The run's budget without the model proxy.** `run.rs` keeps the counter, carve-outs, slices
   and `Spent` merges in a budget type of their own, and no longer builds `Llm`. No protocol.
7. **One message decision, at the receiver's node.** It decides delivery from the receiver's
   token (its `accept_from`, its org layer) and the sender's principal as the control host routes
   it; the control host stores, routes and gives receipts. A protocol bump.
8. **Tool prompts on the node.** TOOL grants published by `sync_grants` like egress ones; the node
   answers a prompt from its replica and asks by `Msg::Ask`, queued while cut off. `run.rs`'s
   `Supervised` keeps interrupts and mode changes, which are commands. Then `consume_grant` and
   `denied_recently` have no production caller. A protocol bump, and a design point first: how the
   node reads the harness's control lines.

Each slice has to pass the node e2e flow (`ci/node-e2e.sh`, also run by `ci/acceptance.sh --nodes local`) and the acceptance
suite unchanged.

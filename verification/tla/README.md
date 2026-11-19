# GrantsOnNodes: grants and budget slices on nodes

Model 1 of [#321](https://github.com/public/wicket/issues/321). It covers the control host, which
issues, renews and revokes grants and leases budget slices. It covers one node, which replicates
grants through the feed, decides at the edge, and may be cut off or crash. And it covers the box,
which makes requests and model calls, and spawns children. The peers that may message them are in
it too. TLC checks it at small, explicit bounds.

Run it with `ci/tla.sh`, or `ci/tla.sh verification/tla/<cfg>` for one configuration. A model
that should pass and doesn't prints TLC's counterexample; `ci/tla.sh --traces` prints each `fail_*`
variant's too, the trace to file with a finding. The script
downloads a Temurin 21 JRE and `tla2tools.jar` (TLC 2.19, release v1.7.4), pinned by URL and
sha256. CI's `tla` job runs it when the models or `ci/tla.sh` change (`ci/determinator/suites.toml`), and
on every push to `main` and nightly. TLC reads only the models, so a change to the code they model
doesn't run it: review such a change against the tables below.

## What it checks

Safety (invariants):

| property | meaning |
|---|---|
| `NoAllowPastLifetime` | no allow at or past a grant's end, by the ledger's rule (below), even while the node is cut off |
| `NoAllowAfterRevocation` | no allow with a grant whose revocation the decider has: the ledger for Central, the replica for the node |
| `SpendWithinBudget` | what the provider billed for the box, plus every child's carve-out (each assumed spent in full), stays within the run's budget, across slices, crashes and reconnections |
| `PeerNeverGrants` | every grant in the ledger was decided by a human, and every grant the node holds came from the publisher's feed |
| `LedgerNeverDecides` | from #257's slice 3 the ledger records grants and never decides a request by one (`CentralAllow` never fires): one decision path, the node's |

Liveness, under weak fairness for the plumbing only: the node restarts and reconnects, the feed
is delivered, spend is written and reported, a call in flight lands, a child is adopted, and an
ended box is released. Faults are bounded by `MaxFaults`.

| property | meaning |
|---|---|
| `NodeConverges` | the node ends up connected, at the feed's head, holding every handed grant with the ledger's end and revocation |
| `SliceReturns` | once the box stops, its final spend is reported and no slice is held against the budget |

Without the fairness on `Deliver` and `Release`, TLC finds liveness violations, so these
properties aren't vacuous.

### Revocation while cut off

A cut-off node can't learn of a revocation. Offline it decides as fresh (#153), so it honours a
revoked grant until it reconnects, or until the grant's end, whichever is first. The model states
"not after revocation" as no allow after the revocation reaches the decider. `NoAllowPastLifetime`
bounds the rest.

### The grant-expiry boundary (decided)

**A grant is live while `now < expires_at`, a half-open interval: its end is exclusive, in
milliseconds.** This is the ledger's rule (`live_grant`: `g.expires_at > now`), and the one
`TokenLive` uses with `Boundary = "ledger"`.

Today the node decides by the token's check, `check if time($t), $t <= not_after`. That check uses
whole seconds (`token::request`: `now_ms.div_euclid(1000)`) and is inclusive, with `not_after =
expires_at` (`noderun::live_grant`, `renew_live`). So a node honours a grant for up to 999 ms past
the ledger's end. #333's simulation noted this, and `fail_token_boundary` shows it in two steps.

Two ways to make the node match:
- publish `not_after = expires_at - 1` (the inclusive whole-second check then ends exactly at
  `expires_at`);
- check `$t < not_after`.

The box authority's end (`Replica::authority_until`, which adds the second) is a separate rule, and
is not modelled here.

## The #257 switch

`Stacks` selects which decision paths exist:

| value | what decides | model actions |
|---|---|---|
| `"today"` | slices 1 and 2 done. Central decides forwarded hosts from the ledger, the control host's egress model gate makes model calls, and the gateway on the control host spawns | `CentralAllow`, `ChCall`, `ChSpawn`, and every node action |
| `"slice3"` | no forwarded egress (done, #257 slice 3): Central and the model gate gone; `Hand` publishes every grant, `FwdGrants` (on hosts the node's CA can't cover) included, and `NodeAllow` never uses one, since such a host is spliced or refused; the gateway still spawns on the control host | `ChSpawn`, and the node's |
| `"end"` | slices 4–5: only the node decides, and spawns | the node's only |

Each #257 slice PR should update this table and the switch, and keep every `pass_*.cfg` passing.

## Design switches, and what TLC found

The other switches are protocol choices. A `pass_*.cfg` uses the decided design: every switch on,
`Boundary = "ledger"`. Each `fail_*.cfg` turns one switch back to today's code, and `ci/tla.sh`
requires TLC to refuse it with the invariant listed. `fail_today` has every switch as on main.

| switch (decided value) | today | fails | counterexample (TLC trace, shortest) |
|---|---|---|---|
| `Boundary = "ledger"` | `"token"` | `fail_token_boundary`: `NoAllowPastLifetime` | approved at 0.5 s for 1 s (`expires_at` 1); handed and delivered; the node allows at 1.0 s |
| `Journal` | on with #333, off on main | `fail_no_journal`: `SpendWithinBudget` | 2 calls billed and reported, slice 4; the node crashes before its 1 s write, restarts from 0, and calls again: the bug #333's simulation found |
| `SeparateCounters` | off: `merge_spent` is a `fetch_max` into the counter the control host's own calls (egress model gate) also count in | `fail_merged_counters`: `SpendWithinBudget` | the control host's own calls use the budget the node was already leased; the node, counting from its own base, spends its slice too |
| `SliceReserved` | off: `remaining()` doesn't subtract what a node was leased | `fail_slice_unreserved`: `SpendWithinBudget` | slice 4 of 4 leased at 2 spent; the node spends a third; before its report, the control host's gateway carves two children of 1 from `remaining()` = 2 |
| `EdgeCarveKept` | off: the next `BudgetSlice` replaces the slice `nodegw` lowered for an edge child | `fail_edge_carve`: `SpendWithinBudget` | slice 4; two edge children of 1 lower it to 2; one is adopted; `slice_due` sends 3 (it knows one child), which replaces 2 while the other child still holds its 1 |
| `SliceAtStart` | off: no slice until the first `BudgetSlice`, the node bounded only by the zone | `fail_no_first_slice`: `SpendWithinBudget` | the control host spends (or carves) the budget while the node, with no slice yet, spends it again |
| `NodeSkew = 0` | (an assumption) | `fail_node_skew`: `NoAllowPastLifetime` | a node clock one tick behind honours a grant past its end in real time |

What each decided switch means for the code:
- `SeparateCounters`: the control host counts its own model calls apart from the node's reports.
  Slices are in the node's base.
- `SliceReserved`: a leased slice's unspent part is held against the budget (`remaining()`, spawn
  carve-outs, the control host's own calls) until the box's final spend returns it (`Release`).
- `EdgeCarveKept`: a node keeps an edge child's carve-out against its parent's zone budget, and
  subtracts carve-outs not yet adopted from any slice it is sent.
- `SliceAtStart`: the box start carries its first slice, so a node never spends without one.

After #257's slice 3, `SeparateCounters` and the control host's own calls are moot. After slices
4–5, so is `SliceReserved`: `pass_budget_end` also passes with it off. `EdgeCarveKept`,
`SliceAtStart` and `Journal` stay needed.

## Actions and the code

| action | code (file, function) |
|---|---|
| `Tick` | clocks: `wicket_store::now`, `wicket_feed::now_ms` |
| `PeerAsk` | `noderun.rs` `ask`, `check_node_ask` (a node's `Msg::Ask`); `nodegw.rs` `request_access` and the queue while cut off; the gateway's `request_access` |
| `PeerForge` | `wicket-feed/src/replica.rs` `Replica::accept` → `plan`, `verify`: only frames the publisher signed are applied |
| `Approve` | `wicket-control/src/grant.rs` `decide` → `approve`; `wicket-store` `Ledger::approve` |
| `Hand` | `noderun.rs` `sync_grants` (today: `route_sealed` = Terminate; since slice 3 every egress grant) → `wicket-store/src/node.rs` `hand_grant_to_node`, `live_grant`, `Publisher::commit` (`Change::PutZone`) |
| `Renew` | `grant.rs` `renew`; `node.rs` `renew_grant`; `noderun.rs` `renew_live`, `sync_grants` |
| `Revoke` | `node.rs` `revoke_grant`; `noderun.rs` `sync_grants` (`Change::Revoke`) |
| `Deliver` | `nodesrv/conn.rs` (feed frames from the channel) → `Replica::accept`; it resumes from the node's epoch on reconnect (`Replica::hello`) |
| `NodeAllow` | `wicket-proxy/src/decide.rs` `route` (only a host the node's CA covers; else `egress/connect.rs` splices or `refuse_uncovered`), then `NodeDecider` → `wicket-feed/src/token.rs` `Replica::<BoxAuthority>::decide` (`request`: whole seconds) |
| `CentralAllow` | today only (removed in slice 3): `decide.rs` `Central` → `wicket-store/src/lib.rs` `Ledger::consume_grant`, which since slice 3 refuses an egress op |
| `NodeAdmit` | `wicket-proxy/src/llm.rs` `Llm::admit` (slice, then zone), `filter`, `reserve_output`; with #333, `Llm::journal` |
| `NodeUpstream` | `llm.rs` `Llm::handle`: the call sent upstream |
| `NodePersist` | `nodesrv.rs` `serve_box`'s spend task (`SPEND_FILE`; with #333, `write_spend`) |
| `Report` | `nodesrv.rs` `serve_box` (`Msg::Spent`) → `noderun.rs` (`Msg::Spent`) → `Llm::merge_spent` |
| `SliceDue` | `noderun.rs` `slice_due` (with #333, `Slice::renewed`), `Llm::next_slice` → `nodesrv/conn.rs` `Msg::BudgetSlice` → `Slices::put`, `Llm::set_slice` |
| `ChCall` | `wicket-proxy/src/egress/mod.rs` (model gate) → `llm.rs` `Llm::through_egress` |
| `ChSpawn` | `wicket-control/src/spawn.rs` (the gateway's spawn): `remaining()`, `reserved_*` |
| `EdgeSpawn` | `wicket-node/src/nodegw.rs` spawn: `llm_left` within the slice; the parent's slice lowered, the child's own `Slices::put` |
| `Adopt` | `noderun.rs` (`Msg::Spawned`) → `spawn.rs` `adopt` (`reserved_*`) |
| `BoxDone`, `Release` | the box's end: `nodesrv.rs`'s last `Msg::Spent`, `Slices::drop_run`. No slice is returned today, since none is held (`SliceReserved`) |
| `Cut`, `Reconnect` | the channel (`chan.rs`); `noderun.rs`'s connection loop (`Progress::slice_sent` starts again; `p.slice` from the holdings) |
| `Crash`, `Restart` | `nodesrv.rs` `serve_box` on restart: `SPEND_FILE` merged, `Slices::get`, the replica and its uses from disk |

## Abstractions and assumptions

- One run on one node. Model budget is counted in requests, one unit per call. Output and input
  tokens follow the same rules: absolute slice totals, and a call whose end wasn't seen charged its
  whole reservation.
- At most one call is in flight. A crash before a call goes upstream loses it unbilled, and one
  after has billed it.
- Channel messages (spend, slices, adoption) are delivered whole, or lost on a cut or a crash, as
  separate steps that interleave with everything else. The feed resumes from the node's epoch.
- A revocation or renewal is published in the same step as the ledger change (`sync_grants` runs
  within seconds). Delivery is still a separate step.
- The node's clock is the control host's, less `NodeSkew` ticks. The properties hold only with no
  skew: a node whose clock is behind honours grants past their end (`fail_node_skew`).
- Not modelled yet: a control-host restart and `spent_base` (#333's second observation, the slice's
  base after a restart), grants with counted uses, `MAX_GRANTS`, lagging and closed replica modes,
  more than one node or box, and the box authority's end, which is what bounds a slice's offline
  spend when a node never comes back (here faults are finite).

## Bounds

The `.cfg` files state them, and `ci/tla.sh` runs them all in about 5 minutes on two cores, with
a 1 GiB heap:

| cfg | half | states (distinct) | time |
|---|---|---|---|
| `GrantsOnNodes.cfg` | both, end state: 1 grant, 4 ticks, budget 2, 1 spawn, 2 faults | 101,762 | 26 s |
| `pass_grants_end`, `pass_grants_slice3`, `pass_grants_today` | grants: 2 grants (one on a host the node's CA can't cover), 5 ticks at 2 per second, 1 renewal, 2 faults | 424,704 (today) | 90 s each |
| `pass_budget_end`, `_slice3`, `_today` | budget: budget 4, step 2, 2 spawns of 1, 3 faults | 5,591 to 14,803 | under 10 s |
| `fail_*` | as their half | (stops at the violation) | under 10 s |

The halves share only the node's up/connected state and its faults, so checking them apart
loses no interleaving that matters to either property, and keeps the state space in the
hundreds of thousands. The whole model at the halves' bounds had over 10M states.

# ApprovalEffect: approvals bound to their effect

[#369](https://github.com/public/wicket/issues/369), on top of model 1. A parent principal and the
child it spawned (one delegation hop) ask for one effect, each request with arguments. A human, or
an agent with grant rights, decides each request on its effect descriptor: who asks, the effect,
the grant's terms, and the hash of the arguments. An action runs under a grant: the egress proxy
sends the request, or wicket spawns, links, leases or updates. The box may present an action
again (a retry, a replay), change its arguments after the approval, or hold it until its grant is
near its end. `ci/tla.sh` runs `ApprovalEffect.cfg` and its `fail_effect_*` variants, which name
the model on a `\* model: ApprovalEffect` line (`GrantsOnNodes`'s variants name theirs).

| property | meaning |
|---|---|
| `HoldUntilDecided` | no action runs for a principal's effect while a request for that effect, from a sibling branch or the same one, waits for a decision |
| `ExactlyOnceOnReplay` | an approved action runs once, however often it is presented again |
| `NoActionAfterExpiry` | no action runs at or after its grant's end, however long it waited |
| `IdentityKeptAcrossHops` | a request keeps its originator's identity across the delegation hop, and an action runs only under a grant to its originator |
| `ArgumentsBound` | an action runs only with the arguments its grant was decided on |

| switch (decided value) | the bug it stands for | fails |
|---|---|---|
| `Hold = TRUE` | a related request is filed and decided apart from the pending one, or a granted action runs while another request for its effect is pending (2607.14166) | `fail_effect_no_hold`: `HoldUntilDecided` |
| `ConsumeOnce = TRUE` | the grant's use isn't recorded with the action, so a replay runs it again | `fail_effect_replay`: `ExactlyOnceOnReplay` |
| `CheckAtRun = TRUE` | the grant's lifetime is checked when it is decided, not when the action runs | `fail_effect_check_at_decision`: `NoActionAfterExpiry` |
| `KeepIdentity = TRUE` | the parent relays its child's request as its own, so the child acts under the parent's grants | `fail_effect_relay_as_self`: `IdentityKeptAcrossHops` |
| `BindArgs = TRUE` | a grant matches only the target, so changed arguments run under it (2610.21063) | `fail_effect_unbound_args`: `ArgumentsBound` |

| action | code (file, function) |
|---|---|
| `Ask` | `wicket-store/src/effect.rs` `Ledger::file_request` (`held_by`: `Filed::Held`); `pending_for` for egress, spawn, link, capacity and update asks |
| `Approve` | `wicket-control/src/grant.rs` `decide` (the shown descriptor, `effect::SHOWN_EFFECT`) → `approve` → `Ledger::approve` (`args_sha256` copied to the grant) and `bind_grant_effect` |
| `Deny` | `wicket-control/src/grant.rs` `decide` → `deny` |
| `Run` | `wicket-store/src/effect.rs` `Ledger::use_effect_grant` (exact target, arguments, one use, `expires_at > now`, held while pending) from `wicket-control/src/spawn.rs` `spawn` and `wicket-proxy/src/link.rs` `open`; `wicket-cli/src/reconcile.rs` `lease_unbound` for capacity; `Ledger::consume_grant` (in its transaction) for egress, where the hold is at `Ask`: an egress op is asked for only when no grant covers it, so no request for its exact effect is pending while a grant for it is used |
| `Via` | the identity a request is filed under: the asking run's (`Op::run`), never a relaying parent's; `Effect::run` and `requested_by` in the descriptor |

Bounds: two request ids, one effect, two argument values, `Lifetime = 1`, `MaxTime = 2`
(`ApprovalEffect.cfg`).

Each invariant is the safety property its switch's guard is there for, so the model checks that
the guards together keep every property in every interleaving of asks, decisions, replays, ticks
and hops, and that dropping any one guard breaks its property. Not modelled: zone-wide grants,
prefix asks, and the ledger's transactions themselves (each action is one atomic step, as
`file_request`, `approve_shown` and `use_effect_grant` are one transaction each).

# RunLifecycle: an agent's activations across control-host restarts

Model 2 of [#321](https://github.com/public/wicket/issues/321). It covers one long-lived agent
(`#70`, `#249`) and the activations (runs) that hold it. A wake claims the agent and starts a box.
The box's supervisor runs on the control host: it renews the claim and the box's authority, hands
the agent its messages, and closes its session when the agent asks to finish. A control-host crash
stops every supervisor, never a box; the box's node keeps it running until its authority ends. The
reconciler gives a box whose supervisor is gone a new one (re-attach, `#151`). A wake may take
over an agent whose holder let its claim lapse. Messages are a peer's (`#250`) or an operator's
(`#198`); one held while no run holds the agent goes to its next run.

| property | meaning |
|---|---|
| `OneHarness` | a wake never starts a second harness of the agent while another runs |
| `NoMessageLost` | no message is counted as delivered without the agent ever having it |
| `NoMessageStuck` | a message in flight on a live supervisor's open link was taken on that link: one taken on a link that dropped is given again, not left in flight until a later supervisor |
| `NoMessageTwice` | no box is given a message twice |
| `FinishKnown` | a live supervisor of an agent that asked to finish, whose session is still open, knows it: a finished run's harness never keeps running |
| `ActiveHasRun` | an `active` agent has a live run (a supervisor, or one the reconciler can still adopt or end) or a claim that hasn't lapsed: never `active` with nothing behind it |

`TRUE` is the pass design, and the code. Each `fail_lifecycle_*` variant is the code before one
fix, which TLC refuses:

| switch (pass value) | the code without it | fails |
|---|---|---|
| `FinishInLedger = TRUE` (the code, #444) | before #444, the agent's `finish` reached only its supervisor (`run.rs`: `finish_asked`, from `want_rx`). A control-host restart between the call and the end of its turn lost it; the re-attached supervisor never closed the session, and the harness ran until its timeout. Now the gateway records it (`Ledger::record_run_want`, `runs.want`) before the tool answers, and a re-attached supervisor reads it (`run.rs` `asked_of`) | `fail_lifecycle_finish_lost`: `FinishKnown` |
| `AckAfterHand = TRUE` (done, #445) | before #445, a message was marked delivered when it was taken (`Ledger::take_message`, and for prompts what is now `take_prompts`), before the box had it. If the control host stopped in between, the only copy was the dead supervisor's. Now a message is in flight (`take_message_in_flight`, `messages.taken_at`) until the box's node says the box has had it (`Msg::MessageRead`, protocol 15); a prompt is recorded by where it is in the box's stdin (`stdin_start`, `stdin_end`). A supervisor that takes the run over gives again what never arrived (`requeue_in_flight`, and `requeue_prompts` against the node's `stdin_received`), and the node drops a message its box has had (`Node::had_message`) | `fail_lifecycle_message_lost`: `NoMessageLost` |
| `WakeAfterAuthority = TRUE` (done, #446) | before #446, `Ledger::claim_wake` took over an `active` agent whose claim lapsed (`CLAIM_SECS`, 30 s). A control-host outage longer than that left its box running on its node, so a wake then started a second box until the first's re-attached supervisor found it superseded. Now `claim_wake` takes over a lapsed agent only once no run of it is recorded running with authority left (its box's authority end, recorded in the ledger at its start and each renewal, plus 30 s): its node stops the box then, or the reconciler ends the run once its node says the box is gone | `fail_lifecycle_twin_wake`: `OneHarness` |
| `RequeueOnReconnect = TRUE` (done, #453) | after #451 (and before #453), a supervisor gave again its in-flight messages only on its first resume of a run it took over. If the link to the box's node dropped after `await_message` answered and before `MessageRead` arrived, while the supervisor lived on, the message stayed in flight, neither waiting nor read, until a later supervisor. Now every reconnect gives again what was given on the link that dropped (`noderun.rs` `requeue_on_resume`), and an answer that can't be sent gives its message back (`Ledger::requeue_message`); the node drops a repeat its box has had | `fail_lifecycle_reconnect_stuck`: `NoMessageStuck` |
| `EndAgentOnLost = TRUE` (done, #474) | before #474, the reconciler ended a run as `lost` (its supervisor gone, its node with no box for it: a box that never started, say, `BoxFails`) but left its agent `active`, its claim lapsed, with nothing to renew it or read its messages. Now `Ledger::run_lost` ends the run and, if it was the agent's current activation, the agent: back to `hibernated` (restorable from its last head) if it has one, else `ended` | `fail_lifecycle_agent_left_active`: `ActiveHasRun` |

Every switch is now the code (#444, #445, #446, #453, #474), so `RunLifecycle.cfg` is main, and each
`fail_lifecycle_*` variant is the code before one fix. `NoMessageTwice` holds in every variant: with
`AckAfterHand` a message is queued again after a crash, and the box's record of what it has had
keeps the repeat out.

| action | code (file, function) |
|---|---|
| `Wake` | `wicket-control/src/hibernate.rs` `wake` → `wicket-store/src/agents.rs` `Ledger::claim_wake` (moves undelivered and held messages, and operator messages, to the new run; `WakeAfterAuthority`: `FENCING_RUNS`, `Ledger::agent_fenced_until`) |
| `Renew`, `Supersede` | `wicket-control/src/run.rs`, the heartbeat: `Ledger::renew_agent_claim`, and `superseded` when it fails |
| `Crash`, `Restart` | the control host's processes stopping (`ci/acceptance.sh`, `restart_flow`). wicketd stopping or moving to a new build is no step of the model (#455): its runs' supervisors are processes of their own, which a restart (`KillMode=process`) or a re-exec (the daemon's handoff) leaves running (`ci/acceptance.sh`, `daemon_flow`) |
| `Adopt`, `Lost` | `wicket-cli/src/reconcile.rs`: `run_adopted` (a new `wicket run --attach`), `run_lost` (`Ledger::run_lost`, which ends the agent's activation with the run, #474; also `run.rs` `attach_failed`) |
| `BoxFails` | a box that never starts on its node, or stops at once, its supervisor gone with it (#474: the node then reports no box for the run) |
| `AskFinish`, `CloseSession`, `HarnessExits` | the gateway's `finish` tool (`wicket_proxy::Want::Finish`) → `run.rs` `finish_asked` → the session's close (`stdin = None`, `StdinClose`, recorded by the node) and `Linger::Finish` (#293) |
| `Send` | `send_message` (the gateway), and `wicket session`'s and the console's `add_prompt` (an operator's prompt, a row of the same `messages` inbox since #253) |
| `Take`, `Hand`, `Ack` | `Ledger::take_message_in_flight` (`await_message`) and `take_prompts` (`run.rs`), then the tool's reply or the stdin write; `Ack` is `Msg::MessageRead`, or for a prompt the node's `stdin_received` at a takeover |
| `LinkDrop`, `LinkUp` | the link between a live supervisor and its box's node dropping and coming back (`noderun.rs` `session`, reconnecting; `requeue_on_resume`, #453) |
| `Tick` | time; a node stops a box whose authority has ended |

Bounds: two activations, one message, `ClaimTtl = 1`, `AuthTtl = 3`, `MaxTime = 5`, one crash
and one link drop (`RunLifecycle.cfg`; the older `fail_lifecycle_*` variants allow no link drop). Not modelled: hibernation's push (`commit_agent_push` checks the pusher's
generation, so a stale twin can't commit), the wake's restore, budgets, and spawned children.

# Placement: placed nodes and the runs on them

Model 3 of [#321](https://github.com/public/wicket/issues/321). A node is created with a lease. A
run is placed on a node with lease left, and carries the node's lease end as its start-by time
(`#395`). The node admits a box into the memory its running boxes leave (`#300`), counting a box's
limit until its container ends (`#430`). A box's container ends, its exit is recorded, and its
files are fetched, or kept on the node when the fetch fails (`#324`). The reconciler releases a
node past its lease once nothing on it holds it (`#294`).

| property | meaning |
|---|---|
| `NoStartPastLease` | no box starts at or past its node's lease end |
| `NoOvercommit` | no node runs more boxes than its memory holds |
| `NoReleaseWithWork` | no node is released with a run's work on it: running, not yet collected, or kept |

Here `TRUE` is the code on main, and each `fail_placement_*` variant is a bug it fixed:

| switch (main) | the bug | fails |
|---|---|---|
| `StartByCheck = TRUE` | a placed node started a box that reached it past its lease (#395) | `fail_placement_no_start_by`: `NoStartPastLease` |
| `Admission = TRUE` | two runs on one node beyond its memory (#300) | `fail_placement_no_admission`: `NoOvercommit` |
| `ReleaseHolds = TRUE` | a node released at its lease end with a run, or a run's files, on it (#294, #324) | `fail_placement_release_running`: `NoReleaseWithWork` |
| `FreeAtContainerEnd = TRUE` | before #430 a box's limit counted until its exit was recorded, refusing a box the memory had room for; `pass_placement_before430` checks the old rule was safe too, and `Placement.cfg` that #430's is | (none: both pass) |

A box that started before its node's lease end may run past it: the reconciler keeps the node,
billing, until the run ends (`placed_held`). The spend that costs is outside this model.

| action | code (file, function) |
|---|---|
| `Create` | `wicket-control/src/nodecreate.rs` (`wicket node create`) |
| `Place` | `wicket-control/src/run.rs`: the placed node and `start_by` (its lease end) in the `BoxStart` |
| `Start`, `Refuse` | `wicket-node/src/nodesrv.rs` `start_box` (the `start_by` check) and `Node::admit` (`holds_limits`) |
| `ContainerEnds`, `Exit` | `nodesrv.rs`: `Node::box_ended` (#430), then `finish` once the output is read |
| `Fetch`, `FetchFails`, `FetchLater` | `run.rs`'s fetch of the box's files, `Ledger::set_run_uncollected`, and a later `wicket fetch` |
| `Release` | `wicket-cli/src/reconcile.rs` `placed_pass` (`running_runs_on_node`, `uncollected_runs_on_node`) |

Bounds: one node, two runs, `Cap = 1`, `Lease = 2`, `MaxTime = 4` (`Placement.cfg`). Not
modelled: the spend envelope and capacity approvals, the provider's own lease, several nodes'
choice of placement, and a node's crash.

# Update: the control host moving to a new build under long-lived runs

Model 4 of [#321](https://github.com/public/wicket/issues/321). A new build arrives two ways:

- An install (`deploy/install.sh`) restarts wicketd. `KillMode=process` leaves the runs'
  supervisors running as orphans, on the build they started on (#468), and wicketd's child too:
  this host's own node's `serve` (#529).
- `wicket self update` re-executes the local serve, stops the runs' old supervisors itself, then
  sends wicketd SIGHUP. The daemon drains: it refuses new commands and writes the handoff of its
  running ones, then re-executes as the new build (#455).

The new build writes operators' prompts in its schema. A supervisor still on the old build reads
them. A run's box on the local node (`LocalRuns`) is served by the local serve. When a new build's
supervisor re-attached to an old build's serve, the box was lost (#529).

| property | meaning |
|---|---|
| `NoPromptLost` | no operator's prompt is lost across an update |
| `OldBuildBounded` | after an update, no supervisor runs the old build for longer than the handover's bound |
| `DaemonTakesCommands` | the daemon refuses commands for no longer than its drain's bound: it always takes them again |
| `BoxesKept` | an update keeps every run's box: a re-attach never ends the box it means to keep |

The bounds are what the code's timeouts keep. They are written as obligations on time: time
doesn't pass a handover's bound while the handover can still act, nor a drain's while the drain
can still return. A bug that stops either from acting lets time pass, and breaks its property.

| switch (pass value) | the code without it | fails |
|---|---|---|
| `ExpandSafe = TRUE` and `HandOverOnStart = TRUE` | #475: schema 17 wasn't expand-safe for older readers. After an install's restart (#468), the old-build supervisors' `await_message` took the new build's prompts as peers' messages and dropped them | `fail_update_old_supervisor_drops_prompts`: `NoPromptLost` |
| `HandOverOnStart = TRUE` (#477) | an install's restart left every run on its old supervisor for as long as the run lived | `fail_update_old_build_lingers`: `OldBuildBounded` |
| `DrainReturns = TRUE` (#489) | #487: the SIGHUP drain asked the registry it held how many commands it handed over, deadlocked, and the daemon refused every command until it was restarted | `fail_update_drain_hangs`: `DaemonTakesCommands` |
| `ServeFirstOnStart = TRUE` (#529) | `deploy/install.sh`'s restart of wicketd left the local serve on the old build. The new wicketd handed the local run over, and its new-build supervisor, re-attached to the old serve, lost the box ("stopped by wicket: its control host stopped it") | `fail_update_local_serve_left_old`: `BoxesKept` |
| `ServeFirstOnUpdate = TRUE` (#529) | `wicket self update`'s `handover` stopped the old supervisors before it re-executed the serve. The reconciler service could re-attach a local run in between, to the old serve | `fail_update_serve_after_stop`: `BoxesKept` |
| `ExpandSafe = TRUE` alone | the handover narrows #475's window but doesn't close it. A prompt sent in the seconds before an old supervisor is stopped is still dropped if the schema step isn't expand-safe. The expand rule, which the store's `previous_build` test checks (#477), is what closes it | `fail_update_handover_without_expand`: `NoPromptLost` |

| action | code (file, function) |
|---|---|
| `Install`, `DaemonStart` | `deploy/install.sh` (`systemctl restart wicketd`); `wicket-cli/src/daemon/mod.rs` `serve`, which hands over on a thread (`hand_over_runs`) while it takes commands |
| `ServeReexec` | `update.rs` `reexec_local_node`: SIGHUP to the local serve, which re-executes as the current build with the same pid and adopts its boxes; the caller waits for it. First in `hand_over_runs` and in `handover` |
| `HandOver`, `Reattach` | `wicket-cli/src/update.rs` `stop_stale_supervisors` (SIGKILL, the box left running), then a reconciler's `run_adopted` (`wicket attach` on the new build): the handover's own pass (`adopt_handed`) or the reconciler service's, whichever comes first |
| `SelfUpdate`, `DrainDone` | `update.rs` `handover`, then SIGHUP: `daemon/mod.rs` `drain` and `handoff::prepare`, held across the exec (#489) |
| `Send`, `Take` | `Ledger::add_prompt` (#463), and a supervisor's `take_prompts` or `await_message` on its build |

Bounds: two runs, one of them on the local node, two prompts, `MaxTime = 4`, `HandoverMax = 1`,
`DrainMax = 1` (`Update.cfg`).

Not modelled:
- a supervisor stopped holding a prompt in flight (RunLifecycle covers that: it is given again on the re-attach, #445);
- several updates in a row;
- a rollback;
- nodes' own builds (a remote node's serve moves by `wicket self update --nodes`);
- why an old serve under a new supervisor loses the box. The model takes #529's outcome as given;
- the reconciler service's own restart: `wicket-reconcile.service` has `KillMode=process`, so its
  restart leaves the supervisors its passes started running (#529).

## Update: trails of real updates

`UpdateTrace.tla` checks the model against what happened (trace validation, #321 and #324, as
#421 does for the ledger). A trail is the control host's audited steps during a real update.
`ci/tla-trail.py` makes it from an audit export: each run's `reconcile.run_adopted` and
`run.attach` is `Reattach(r)`, with its box left `stopped` when the run ended "stopped by wicket"
within seconds, and `running` otherwise.

The steps the audit doesn't record may happen between the trail's: wicketd's restart, the local
serve's re-exec, the old supervisors being stopped, ticks and prompts. They are any of the model's
own actions except the other way of updating.

A `trail_*.cfg` checks `TrailUnmatched`. TLC refuses it exactly when some behaviour of the model
takes every step of the trail, which makes the trail a behaviour of the model.

The trails are 2026-11-18's, scrubbed, in `trails/update-2026-11-18.txt`:

| config | trail | switches | result |
|---|---|---|---|
| `trail_1848_merged_matched` | the 18:48 install, with #531: both runs re-attached, both boxes kept | the design as merged (`Update.cfg`) | matched: a behaviour of the spec |
| `trail_1759_merged_unmatched` | the 17:58 install: the local run re-attached and its box stopped 2 s later (#529) | the design as merged | unmatched: no behaviour of the spec |
| `trail_1759_serve_left_old_matched` | the same | `fail_update_local_serve_left_old`'s (`ServeFirstOnStart = FALSE`) | matched: a behaviour of #529's fail variant |

The 10:04 self update that hung (#487) has no trail: the export starts at 11:00:06. Between the
updates, the only records are each run's identity rotations. A drain that never returns shows as the
CLI's commands refused, and this export holds no record of a refused command or of the drain. A trail
for such an incident would need the daemon's own log (`wicketd: handing N running command(s)`,
`waiting for N command(s)`) as well.

To check a new update: export the audit records around it, run
`python3 -I ci/tla-trail.py <export>`, and paste its `TrailHHMM` into `UpdateTrace.tla`. Then
add a `trail_<HHMM>_<switches>_matched.cfg` (or `_unmatched`) for the switches it should and
shouldn't match. Check the printed records against the public-repository rules before
committing: the script drops owners, trust domains and node names, but not every field an audit
record could hold.


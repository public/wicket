--------------------------- MODULE GrantsOnNodes ---------------------------
(***************************************************************************)
(* #321, model 1: grants and budget slices on nodes.                       *)
(*                                                                         *)
(* One run, its box on one node, the control host (ledger, feed publisher, *)
(* budget counter) and the peers that may message them. The README maps   *)
(* every action to the code (file, function).                              *)
(*                                                                         *)
(* Time is counted in ticks, TicksPerSec to a second, so that the token's  *)
(* whole-second check and the ledger's `expires_at <= now` can disagree    *)
(* inside one second, as they do in the code (milliseconds).               *)
(*                                                                         *)
(* Model budget is counted in model requests: every call is one unit. The  *)
(* output-token and input-token counters follow the same rules (absolute   *)
(* slice totals, a reservation charged in full when not settled), so one   *)
(* counter shows the protocol.                                             *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Grants,          \* grant ids the human may issue
    FwdGrants,       \* of those, grants on hosts the node's CA can't cover: forwarded to Central
                     \* today; since slice 3 published, and never used (spliced or refused)
    Lifetime,        \* a grant's lifetime, and a renewal's, in whole seconds
    MaxRenew,        \* renewals per grant
    TicksPerSec,     \* ticks per second (>= 2 to see the sub-second boundary)
    MaxTime,         \* last tick
    NodeSkew,        \* how far the node's clock is behind the control host's, in ticks
    Budget,          \* the run's model budget (requests)
    Part,            \* a slice's step: ceil(budget * slice_fraction)
    Carve,           \* a child's model budget, carved out of the run's
    MaxSpawns,       \* children the box may start
    MaxFaults,       \* cut-offs plus node crashes
    Stacks,          \* "today" (two stacks: Central and the node), "slice3" (no forwarded egress),
                     \* "end" (#257: only the node decides; spawns on the node)
    Boundary,        \* "token": a grant is live while now_s <= not_after (inclusive, whole seconds);
                     \* "ledger": live while now < expires_at (half-open). See the README.
    Journal,         \* the node journals spend before a call goes upstream (#324, PR #333)
    SeparateCounters,\* the control host keeps its own calls apart from the node's reports
    SliceReserved,   \* a leased slice is held against the budget until returned
    EdgeCarveKept,   \* a node keeps an edge child's carve-out against its parent
    SliceAtStart     \* the box start carries its first slice: no spend before a slice

ASSUME Stacks \in {"today", "slice3", "end"}
ASSUME Boundary \in {"token", "ledger"}
ASSUME FwdGrants \subseteq Grants
ASSUME TicksPerSec >= 1 /\ Lifetime >= 1 /\ Budget >= 1 /\ Part >= 1 /\ Carve >= 1

NoSlice == -1                \* no slice leased yet (`Llm::slice()` is None)

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b
Sub(a, b) == IF a > b THEN a - b ELSE 0   \* saturating_sub

VARIABLES
    now,         \* the control host's clock, in ticks
    \* ---- grants: the ledger, the feed, the node's replica ----
    ledger,      \* [Grants -> [st, exp (s), handed, renews]]
    asks,        \* grants a peer (box, node) has asked for: pending requests
    decided,     \* grants a human decided (the only issuer)
    forged,      \* grant frames a peer sent the node directly (unsigned by the publisher)
    feed,        \* the publisher's committed changes, in order
    epoch,       \* how many of them the node's replica applied (persisted before applied)
    rep,         \* the node's replica: [Grants -> [has, exp, rev]]
    \* ---- the node ----
    up, conn,    \* node `serve` running; its channel to the control host open
    faults,
    \* ---- budget ----
    billed,      \* model calls the provider billed for the run's own box (node and Central)
    carved,      \* model budget given to children (each assumed to spend all of it)
    chCount,     \* the control host's `Llm` counter (requests), what `remaining` and `next_slice` read
    chOwn,       \* of it, the control host's own calls (egress model gate)
    chNode,      \* the highest count the node reported (`Msg::Spent`)
    chReserved,  \* reserved_requests: children's carve-outs
    chSlice,     \* the last slice sent (`Progress::slice`, kept in the holdings)
    sliceSent,   \* sent on this connection (`Progress::slice_sent`)
    nCount,      \* the node's `Llm` counter in memory
    nJournal,    \* node-spend.json
    nSlice,      \* the node's slice (`Slices`, on disk)
    nInflight,   \* a call admitted on the node, not yet sent upstream
    nCarved,     \* edge carve-outs the node keeps against the parent (EdgeCarveKept)
    unadopted,   \* edge children the control host hasn't adopted yet (the node's queue, on disk)
    spawns,
    boxDone,     \* the box makes no more calls
    released,    \* its final spend reported and its slice returned
    \* ---- history, for the safety properties ----
    pastLife,    \* some allow came at or past the grant's lifetime (the ledger's)
    pastRevoke,  \* some allow used a grant whose revocation the decider had
    ledgerUsed   \* the ledger decided a request by a grant (Central's consume_grant)

grantVars == <<ledger, asks, decided, forged, feed, epoch, rep>>
nodeVars == <<up, conn, faults>>
budgetVars == <<billed, carved, chCount, chOwn, chNode, chReserved, chSlice, sliceSent,
                nCount, nJournal, nSlice, nInflight, nCarved, unadopted, spawns, boxDone, released>>
histVars == <<pastLife, pastRevoke, ledgerUsed>>
vars == <<now, grantVars, nodeVars, budgetVars, histVars>>

-----------------------------------------------------------------------------
(* Clocks and liveness of a grant *)

Sec(t) == t \div TicksPerSec
NodeNow == Sub(now, NodeSkew)

\* The ledger's rule (`live_grant`: expires_at > now): live strictly before expires_at.
LedgerLive(g, t) == ledger[g].st = "live" /\ t < ledger[g].exp * TicksPerSec

\* What the deciding node does with a grant block's end at time t (its own clock).
TokenLive(exp, t) ==
    IF Boundary = "token"
    THEN Sec(t) <= exp                      \* `check if time($t), $t <= not_after`, time in whole s
    ELSE t < exp * TicksPerSec              \* the same end as the ledger's

\* A revocation the node has applied.
RevokedAt(g) == {i \in 1..Len(feed) : feed[i].kind = "revoke" /\ feed[i].g = g}
RevDelivered(g) == \E i \in RevokedAt(g) : i <= epoch

\* What the control host may still hand out or spend itself. The node's base (SeparateCounters)
\* or the merged counter.
Base == IF SeparateCounters THEN chNode ELSE chCount
Held == IF SliceReserved /\ chSlice # NoSlice /\ ~released THEN Sub(chSlice, Base) ELSE 0
Left == Sub(Budget, chCount + chReserved)

-----------------------------------------------------------------------------
Init ==
    /\ now = 0
    /\ ledger = [g \in Grants |-> [st |-> "none", exp |-> 0, handed |-> FALSE, renews |-> 0]]
    /\ asks = {} /\ decided = {} /\ forged = {}
    /\ feed = << >> /\ epoch = 0
    /\ rep = [g \in Grants |-> [has |-> FALSE, exp |-> 0, rev |-> FALSE]]
    /\ up = TRUE /\ conn = TRUE /\ faults = 0
    /\ billed = 0 /\ carved = 0
    /\ chCount = 0 /\ chOwn = 0 /\ chNode = 0 /\ chReserved = 0
    /\ chSlice = (IF SliceAtStart THEN Min(Budget, Part) ELSE NoSlice)
    /\ sliceSent = SliceAtStart
    /\ nCount = 0 /\ nJournal = 0 /\ nInflight = 0
    /\ nSlice = (IF SliceAtStart THEN Min(Budget, Part) ELSE NoSlice)
    /\ nCarved = 0 /\ unadopted = 0 /\ spawns = 0
    /\ boxDone = FALSE /\ released = FALSE
    /\ pastLife = FALSE /\ pastRevoke = FALSE /\ ledgerUsed = FALSE

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<grantVars, nodeVars, budgetVars, histVars>>

-----------------------------------------------------------------------------
(* Peers: a box or a node may ask; it never grants. *)

PeerAsk(g) ==
    /\ g \notin asks
    /\ asks' = asks \cup {g}
    /\ UNCHANGED <<now, ledger, decided, forged, feed, epoch, rep, nodeVars, budgetVars, histVars>>

\* A peer (another box, a node) sends the node a grant of its own making. The replica accepts
\* only frames signed by the publisher (`Replica::accept`), so nothing changes but the record.
PeerForge(g) ==
    /\ g \notin forged
    /\ forged' = forged \cup {g}
    /\ UNCHANGED <<now, ledger, asks, decided, feed, epoch, rep, nodeVars, budgetVars, histVars>>

(* The control host: a human decides; the ledger records; sync_grants publishes. *)

Approve(g) ==
    /\ g \in asks
    /\ ledger[g].st = "none"
    /\ decided' = decided \cup {g}
    /\ ledger' = [ledger EXCEPT ![g].st = "live", ![g].exp = Sec(now) + Lifetime]
    /\ UNCHANGED <<now, asks, forged, feed, epoch, rep, nodeVars, budgetVars, histVars>>

\* sync_grants hands a live grant to the node: ledger.node set, a PutZone on the feed. Today only a
\* grant on a host the node terminates; since slice 3 it only publishes, every grant included.
Hand(g) ==
    /\ (Stacks = "today" => g \notin FwdGrants)
    /\ LedgerLive(g, now)
    /\ ~ledger[g].handed
    /\ ledger' = [ledger EXCEPT ![g].handed = TRUE]
    /\ feed' = Append(feed, [kind |-> "put", g |-> g, exp |-> ledger[g].exp])
    /\ UNCHANGED <<now, asks, decided, forged, epoch, rep, nodeVars, budgetVars, histVars>>

\* `wicket grant renew`, then renew_live re-publishes the block with its new end.
Renew(g) ==
    /\ LedgerLive(g, now)
    /\ ledger[g].renews < MaxRenew
    /\ Sec(now) + Lifetime > ledger[g].exp
    /\ ledger' = [ledger EXCEPT ![g].exp = Sec(now) + Lifetime, ![g].renews = @ + 1]
    /\ feed' = IF ledger[g].handed
               THEN Append(feed, [kind |-> "put", g |-> g, exp |-> Sec(now) + Lifetime])
               ELSE feed
    /\ UNCHANGED <<now, asks, decided, forged, epoch, rep, nodeVars, budgetVars, histVars>>

\* Revoked in the ledger; a handed grant's revocation published (Change::Revoke).
Revoke(g) ==
    /\ ledger[g].st = "live"
    /\ ledger' = [ledger EXCEPT ![g].st = "revoked"]
    /\ feed' = IF ledger[g].handed
               THEN Append(feed, [kind |-> "revoke", g |-> g, exp |-> ledger[g].exp])
               ELSE feed
    /\ UNCHANGED <<now, asks, decided, forged, epoch, rep, nodeVars, budgetVars, histVars>>

(* The node's replica follows the feed while connected. *)

Deliver ==
    /\ up /\ conn
    /\ epoch < Len(feed)
    /\ LET e == feed[epoch + 1] IN
         rep' = IF e.kind = "put"
                THEN [rep EXCEPT ![e.g].has = TRUE, ![e.g].exp = e.exp]
                ELSE [rep EXCEPT ![e.g].rev = TRUE]
    /\ epoch' = epoch + 1
    /\ UNCHANGED <<now, ledger, asks, decided, forged, feed, nodeVars, budgetVars, histVars>>

(* Decisions. *)

\* The node decides at the edge, fresh or offline, on its own clock (`Replica::decide`). Never a
\* host its CA can't cover (`decide::route`): today it forwards those; since slice 3 it splices one
\* the box's token allows wholesale (which uses no grant) and refuses the rest.
NodeAllow(g) ==
    /\ up
    /\ g \notin FwdGrants
    /\ rep[g].has /\ ~rep[g].rev
    /\ TokenLive(rep[g].exp, NodeNow)
    /\ pastLife' = (pastLife \/ ~(now < ledger[g].exp * TicksPerSec))
    /\ pastRevoke' = (pastRevoke \/ RevDelivered(g))
    /\ UNCHANGED <<now, grantVars, nodeVars, budgetVars, ledgerUsed>>

\* Today only: Central decides a forwarded request from the ledger (`consume_grant`), reached
\* through the node's tunnel. Gone with slice 3 (no forwarded egress).
CentralAllow(g) ==
    /\ Stacks = "today"
    /\ up /\ conn
    /\ g \in FwdGrants
    /\ ~ledger[g].handed
    /\ LedgerLive(g, now)
    /\ pastLife' = (pastLife \/ ~(now < ledger[g].exp * TicksPerSec))
    /\ pastRevoke' = (pastRevoke \/ ledger[g].st = "revoked")
    /\ ledgerUsed' = TRUE
    /\ UNCHANGED <<now, grantVars, nodeVars, budgetVars>>

-----------------------------------------------------------------------------
(* Budget: the node's model proxy. *)

\* `Llm::admit` and `filter` on the node: the slice first, then the zone's budget (on a node,
\* its token's zone: the whole budget). Offline too. With the journal, spend is written before
\* the call goes upstream.
NodeAdmit ==
    /\ up /\ ~boxDone
    /\ nInflight = 0
    /\ nSlice = NoSlice \/ nCount < nSlice
    /\ nCount + 1 + nCarved <= Budget
    /\ nCount' = nCount + 1
    /\ nInflight' = 1
    /\ nJournal' = IF Journal THEN nCount + 1 ELSE nJournal
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, carved, chCount, chOwn, chNode,
                   chReserved, chSlice, sliceSent, nSlice, nCarved, unadopted, spawns, boxDone, released>>

\* The call reaches the provider, which bills it.
NodeUpstream ==
    /\ up /\ nInflight = 1
    /\ nInflight' = 0
    /\ billed' = billed + 1
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, carved, chCount, chOwn, chNode, chReserved,
                   chSlice, sliceSent, nCount, nJournal, nSlice, nCarved, unadopted, spawns, boxDone, released>>

\* serve_box's 1 s task writes node-spend.json when the count moved.
NodePersist ==
    /\ up /\ nJournal # nCount
    /\ nJournal' = nCount
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, carved, chCount, chOwn, chNode,
                   chReserved, chSlice, sliceSent, nCount, nSlice, nInflight, nCarved, unadopted,
                   spawns, boxDone, released>>

\* Msg::Spent: the node's count merged into the control host's (`merge_spent`: fetch_max).
Report ==
    /\ up /\ conn
    /\ nCount > chNode
    /\ chNode' = nCount
    /\ chCount' = IF SeparateCounters THEN chOwn + nCount ELSE Max(chCount, nCount)
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, carved, chOwn, chReserved, chSlice,
                   sliceSent, nCount, nJournal, nSlice, nInflight, nCarved, unadopted, spawns,
                   boxDone, released>>

\* noderun::slice_due with Llm::next_slice: the slice is spent + min(left, part), kept while
\* more than half of it is left and it isn't above the next one. The node sets it
\* (`Llm::set_slice`), replacing what it had.
Low(cap, nxt, used) == Sub(cap, used) * 2 < Sub(nxt, used)
SliceDue ==
    /\ up /\ conn /\ ~released
    /\ LET next == Base + Min(Left, Part)
           new == IF chSlice # NoSlice /\ ~Low(chSlice, next, Base) /\ chSlice <= next
                  THEN chSlice ELSE next
       IN /\ (~sliceSent \/ new # chSlice)
          /\ chSlice' = new
          /\ sliceSent' = TRUE
          /\ nSlice' = IF EdgeCarveKept THEN Sub(new, unadopted * Carve) ELSE new
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, carved, chCount, chOwn, chNode,
                   chReserved, nCount, nJournal, nInflight, nCarved, unadopted, spawns, boxDone, released>>

\* Today only: a model call through the control host's egress (its model gate), counted in the
\* same counter the node's reports are merged into.
ChCall ==
    /\ Stacks = "today"
    /\ up /\ conn /\ ~boxDone
    /\ chCount + 1 + chReserved + Held <= Budget
    /\ chCount' = chCount + 1
    /\ chOwn' = chOwn + 1
    /\ billed' = billed + 1
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, carved, chNode, chReserved, chSlice, sliceSent,
                   nCount, nJournal, nSlice, nInflight, nCarved, unadopted, spawns, boxDone, released>>

\* A spawn the control host's gateway decides (spawn.rs): carved from `remaining()`.
ChSpawn ==
    /\ Stacks \in {"today", "slice3"}
    /\ up /\ conn /\ ~boxDone
    /\ spawns < MaxSpawns
    /\ Carve + chCount + chReserved + Held <= Budget
    /\ chReserved' = chReserved + Carve
    /\ carved' = carved + Carve
    /\ spawns' = spawns + 1
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, chCount, chOwn, chNode, chSlice,
                   sliceSent, nCount, nJournal, nSlice, nInflight, nCarved, unadopted, boxDone, released>>

\* A spawn the node decides (nodegw.rs, fresh only): carved from what the node was leased,
\* lowering its parent's slice if it has one.
EdgeSpawn ==
    /\ up /\ conn /\ epoch = Len(feed) /\ ~boxDone
    /\ spawns < MaxSpawns
    /\ Min(Sub(Budget, nCount + nCarved), IF nSlice = NoSlice THEN Budget ELSE Sub(nSlice, nCount)) >= Carve
    /\ nSlice' = IF nSlice = NoSlice THEN NoSlice ELSE nSlice - Carve
    /\ nCarved' = IF EdgeCarveKept THEN nCarved + Carve ELSE nCarved
    /\ carved' = carved + Carve
    /\ unadopted' = unadopted + 1
    /\ spawns' = spawns + 1
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, chCount, chOwn, chNode, chReserved,
                   chSlice, sliceSent, nCount, nJournal, nInflight, boxDone, released>>

\* Msg::Spawned, then spawn::adopt reserves the child's budget.
Adopt ==
    /\ up /\ conn /\ unadopted > 0
    /\ unadopted' = unadopted - 1
    /\ chReserved' = chReserved + Carve
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, carved, chCount, chOwn, chNode,
                   chSlice, sliceSent, nCount, nJournal, nSlice, nInflight, nCarved, spawns, boxDone, released>>

BoxDone ==
    /\ ~boxDone
    /\ boxDone' = TRUE
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, carved, chCount, chOwn, chNode,
                   chReserved, chSlice, sliceSent, nCount, nJournal, nSlice, nInflight, nCarved,
                   unadopted, spawns, released>>

\* The box has ended: its final spend is reported and its slice comes back.
Release ==
    /\ up /\ conn /\ boxDone /\ nInflight = 0 /\ unadopted = 0 /\ ~released
    /\ chNode' = Max(chNode, nCount)
    /\ chCount' = IF SeparateCounters THEN chOwn + Max(chNode, nCount) ELSE Max(chCount, nCount)
    /\ chSlice' = IF SeparateCounters THEN Max(chNode, nCount) ELSE Max(chCount, nCount)
    /\ nSlice' = nCount
    /\ released' = TRUE
    /\ UNCHANGED <<now, grantVars, nodeVars, histVars, billed, carved, chOwn, chReserved, sliceSent,
                   nCount, nJournal, nInflight, nCarved, unadopted, spawns, boxDone>>

-----------------------------------------------------------------------------
(* Faults. A cut-off node keeps deciding (offline); a crashed one restarts from disk: its
   replica, its slice, its unadopted children, and its spend as last written. *)

Cut ==
    /\ up /\ conn /\ faults < MaxFaults
    /\ conn' = FALSE
    /\ faults' = faults + 1
    /\ UNCHANGED <<now, grantVars, up, budgetVars, histVars>>

Crash ==
    /\ up /\ faults < MaxFaults
    /\ up' = FALSE /\ conn' = FALSE
    /\ faults' = faults + 1
    /\ nCount' = nJournal
    /\ nInflight' = 0
    /\ UNCHANGED <<now, grantVars, histVars, billed, carved, chCount, chOwn, chNode, chReserved,
                   chSlice, sliceSent, nJournal, nSlice, nCarved, unadopted, spawns, boxDone, released>>

Restart ==
    /\ ~up
    /\ up' = TRUE
    /\ UNCHANGED <<now, grantVars, conn, faults, budgetVars, histVars>>

\* A new connection: the feed resumes from the node's epoch; slice_sent starts again.
Reconnect ==
    /\ up /\ ~conn
    /\ conn' = TRUE
    /\ sliceSent' = FALSE
    /\ UNCHANGED <<now, grantVars, up, faults, histVars, billed, carved, chCount, chOwn, chNode,
                   chReserved, chSlice, nCount, nJournal, nSlice, nInflight, nCarved, unadopted,
                   spawns, boxDone, released>>

-----------------------------------------------------------------------------
Next ==
    \/ Tick
    \/ \E g \in Grants : PeerAsk(g) \/ PeerForge(g) \/ Approve(g) \/ Hand(g) \/ Renew(g) \/ Revoke(g)
    \/ \E g \in Grants : NodeAllow(g) \/ CentralAllow(g)
    \/ Deliver
    \/ NodeAdmit \/ NodeUpstream \/ NodePersist \/ Report \/ SliceDue
    \/ ChCall \/ ChSpawn \/ EdgeSpawn \/ Adopt \/ BoxDone \/ Release
    \/ Cut \/ Crash \/ Restart \/ Reconnect

\* Only the plumbing is fair: the node restarts and reconnects, the feed is delivered, spend is
\* reported and written, a call in flight lands, an ended box is released. Faults are bounded.
Fairness ==
    /\ WF_vars(Restart) /\ WF_vars(Reconnect) /\ WF_vars(Deliver)
    /\ WF_vars(NodeUpstream) /\ WF_vars(NodePersist) /\ WF_vars(Report)
    /\ WF_vars(Adopt) /\ WF_vars(Release)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ now \in 0..MaxTime
    /\ \A g \in Grants : ledger[g].st \in {"none", "live", "revoked"} /\ ledger[g].handed \in BOOLEAN
    /\ epoch \in 0..Len(feed)
    /\ up \in BOOLEAN /\ conn \in BOOLEAN /\ (conn => up)
    /\ billed \in Nat /\ carved \in Nat /\ nCount \in Nat /\ nInflight \in 0..1

\* No allow without a live grant: never past its lifetime (the ledger's end, half-open), even while
\* cut off, and never with a revocation the decider has. A cut-off node learns a revocation when it
\* reconnects; until then the grant's lifetime bounds it (#153).
NoAllowPastLifetime == ~pastLife
NoAllowAfterRevocation == ~pastRevoke

\* Total model spend (the box's billed calls plus every child's carve-out, which it may spend in
\* full) stays within the run's budget, across slices, crashes and reconnections.
SpendWithinBudget == billed + carved <= Budget

\* A peer message never grants: every grant in the ledger was decided by a human, and every grant
\* the node holds came from the publisher's feed, so from the ledger.
PeerNeverGrants ==
    /\ \A g \in Grants : ledger[g].st # "none" => g \in decided
    /\ \A g \in Grants : rep[g].has => ledger[g].handed

\* One decision path (#257): from slice 3 the ledger records grants and never decides a request
\* by one; only the node does, from its replica.
LedgerNeverDecides == Stacks # "today" => ~ledgerUsed

Safety == NoAllowPastLifetime /\ NoAllowAfterRevocation /\ SpendWithinBudget /\ PeerNeverGrants /\ LedgerNeverDecides

\* A reconnecting node converges to the control host's grants.
Converged ==
    /\ up /\ conn /\ epoch = Len(feed)
    /\ \A g \in Grants : ledger[g].handed =>
           /\ rep[g].has /\ rep[g].exp = ledger[g].exp
           /\ rep[g].rev = (ledger[g].st = "revoked")
NodeConverges == <>[]Converged

\* An unused slice returns to the budget once the box stops.
SliceReturns == boxDone ~> (released /\ Held = 0)

=============================================================================

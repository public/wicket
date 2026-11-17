------------------------------ MODULE Placement ------------------------------
(***************************************************************************)
(* Model 3 of #321: placed nodes and the runs on them. A node is created   *)
(* with a lease; a run is placed on a node with lease left and carries the *)
(* node's lease end as its start-by time (#395); the node admits a box     *)
(* into the memory its running boxes leave (#430); a box's container ends, *)
(* its exit is recorded, and its files are fetched (or kept on the node    *)
(* when the fetch fails, #324); the reconciler releases a node past its    *)
(* lease once nothing on it holds it (#294, #300). See README.md for the   *)
(* code each action restates.                                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nodes,              \* e.g. {"n1"}
    Runs,               \* e.g. {"r1", "r2"}
    Cap,                \* boxes a node's memory holds at once
    Lease,              \* a node's lease, in ticks
    MaxTime,
    \* Design switches: TRUE is the code on main, FALSE the bug it fixed.
    StartByCheck,       \* a placed node refuses a box start at or past its lease end (#395)
    Admission,          \* a node admits a box only into memory its running boxes leave (#300)
    FreeAtContainerEnd, \* a box's limit stops counting when its container ends, not at its recorded exit (#430)
    ReleaseHolds        \* the reconciler keeps a node a run still runs on or keeps files on (#300, #324)

NONE == "none"

VARIABLES
    now,
    node,       \* n -> "none" | "active" | "released"
    leaseUntil, \* n -> its lease end
    run,        \* r -> "new" | "placed" | "running" | "ended" | "exited" | "kept" | "collected" | "refused"
    at,         \* r -> the node it is placed on, or NONE
    startBy,    \* r -> its BoxStart's start_by: its node's lease end when it was placed
    started,    \* r -> its box started
    startedAt   \* r -> when

vars == <<now, node, leaseUntil, run, at, startBy, started, startedAt>>

RunStates == {"new", "placed", "running", "ended", "exited", "kept", "collected", "refused"}

TypeOK ==
    /\ now \in 0..MaxTime
    /\ node \in [Nodes -> {"none", "active", "released"}]
    /\ run \in [Runs -> RunStates]
    /\ at \in [Runs -> Nodes \cup {NONE}]
    /\ started \in [Runs -> BOOLEAN]

Init ==
    /\ now = 0
    /\ node = [n \in Nodes |-> "none"]
    /\ leaseUntil = [n \in Nodes |-> 0]
    /\ run = [r \in Runs |-> "new"]
    /\ at = [r \in Runs |-> NONE]
    /\ startBy = [r \in Runs |-> 0]
    /\ started = [r \in Runs |-> FALSE]
    /\ startedAt = [r \in Runs |-> 0]

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<node, leaseUntil, run, at, startBy, started, startedAt>>

(* nodecreate.rs (wicket node create): a node, its lease from now. *)
Create(n) ==
    /\ node[n] = "none"
    /\ node' = [node EXCEPT ![n] = "active"]
    /\ leaseUntil' = [leaseUntil EXCEPT ![n] = now + Lease]
    /\ UNCHANGED <<now, run, at, startBy, started, startedAt>>

(* run.rs: a run placed on an active node with lease left; its start carries the node's lease   *)
(* end (`BoxStart::start_by`).                                                                  *)
Place(r, n) ==
    /\ run[r] = "new" /\ node[n] = "active" /\ now < leaseUntil[n]
    /\ run' = [run EXCEPT ![r] = "placed"]
    /\ at' = [at EXCEPT ![r] = n]
    /\ startBy' = [startBy EXCEPT ![r] = leaseUntil[n]]
    /\ UNCHANGED <<now, node, leaseUntil, started, startedAt>>

(* What a node counts as committed (`Node::holds_limits`). *)
Committed(n) ==
    Cardinality({q \in Runs : at[q] = n /\ (run[q] = "running" \/ (~FreeAtContainerEnd /\ run[q] = "ended"))})

(* nodesrv.rs, start_box: a start past its start-by time is refused (#395); one that doesn't fit   *)
(* is refused (Node::admit).                                                                       *)
Start(r) ==
    /\ run[r] = "placed" /\ node[at[r]] = "active"
    /\ StartByCheck => now < startBy[r]
    /\ Admission => Committed(at[r]) + 1 <= Cap
    /\ run' = [run EXCEPT ![r] = "running"]
    /\ started' = [started EXCEPT ![r] = TRUE]
    /\ startedAt' = [startedAt EXCEPT ![r] = now]
    /\ UNCHANGED <<now, node, leaseUntil, at, startBy>>

Refuse(r) ==
    /\ run[r] = "placed"
    /\ StartByCheck /\ now >= startBy[r]
    /\ run' = [run EXCEPT ![r] = "refused"]
    /\ UNCHANGED <<now, node, leaseUntil, at, startBy, started, startedAt>>

(* The box's container ends (Docker's wait; Node::box_ended, #430). *)
ContainerEnds(r) ==
    /\ run[r] = "running"
    /\ run' = [run EXCEPT ![r] = "ended"]
    /\ UNCHANGED <<now, node, leaseUntil, at, startBy, started, startedAt>>

(* Its output is read and its exit recorded (`finish`). *)
Exit(r) ==
    /\ run[r] = "ended"
    /\ run' = [run EXCEPT ![r] = "exited"]
    /\ UNCHANGED <<now, node, leaseUntil, at, startBy, started, startedAt>>

(* run.rs: its files fetched, or kept on the node when the fetch fails (set_run_uncollected). *)
Fetch(r) ==
    /\ run[r] = "exited"
    /\ run' = [run EXCEPT ![r] = "collected"]
    /\ UNCHANGED <<now, node, leaseUntil, at, startBy, started, startedAt>>

FetchFails(r) ==
    /\ run[r] = "exited"
    /\ run' = [run EXCEPT ![r] = "kept"]
    /\ UNCHANGED <<now, node, leaseUntil, at, startBy, started, startedAt>>

(* A kept run's files fetched later (`wicket fetch`). *)
FetchLater(r) ==
    /\ run[r] = "kept" /\ node[at[r]] = "active"
    /\ run' = [run EXCEPT ![r] = "collected"]
    /\ UNCHANGED <<now, node, leaseUntil, at, startBy, started, startedAt>>

(* reconcile.rs, placed_pass: a node past its lease is released unless a run runs on it or keeps *)
(* its files there (running_runs_on_node, uncollected_runs_on_node).                              *)
Holds(n) == \E q \in Runs : at[q] = n /\ run[q] \in {"placed", "running", "ended", "exited", "kept"}

Release(n) ==
    /\ node[n] = "active" /\ now >= leaseUntil[n]
    /\ ReleaseHolds => ~Holds(n)
    /\ node' = [node EXCEPT ![n] = "released"]
    /\ UNCHANGED <<now, leaseUntil, run, at, startBy, started, startedAt>>

Next ==
    \/ Tick
    \/ \E n \in Nodes : Create(n) \/ Release(n)
    \/ \E r \in Runs : Start(r) \/ Refuse(r) \/ ContainerEnds(r) \/ Exit(r) \/ Fetch(r) \/ FetchFails(r)
                       \/ FetchLater(r) \/ \E n \in Nodes : Place(r, n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety.                                                                 *)
(***************************************************************************)

(* No box starts at or past its node's lease end. *)
NoStartPastLease == \A r \in Runs : started[r] => startedAt[r] < leaseUntil[at[r]]

(* No node runs more boxes than its memory holds. *)
NoOvercommit == \A n \in Nodes : Cardinality({q \in Runs : at[q] = n /\ run[q] = "running"}) <= Cap

(* No node is released with a run's work on it: running, not yet collected, or kept. *)
NoReleaseWithWork ==
    \A r \in Runs : (at[r] # NONE /\ node[at[r]] = "released") => run[r] \in {"collected", "refused"}

=============================================================================

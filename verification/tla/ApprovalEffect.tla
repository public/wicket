--------------------------- MODULE ApprovalEffect ---------------------------
(***************************************************************************)
(* #369 (on #321's model 1): approvals bound to their effect.              *)
(*                                                                         *)
(* A parent principal and the child it delegated to (a spawn: one hop)     *)
(* make requests for one effect (method, host, path or prefix; or a kind   *)
(* and its target), each with arguments. A human decides each request on   *)
(* its effect descriptor, which names who asks, the effect, the terms and  *)
(* a hash of the arguments. A grant is the approved descriptor. An action  *)
(* runs under a grant: the egress proxy sends the request, or wicket       *)
(* spawns, links, updates or leases.                                       *)
(*                                                                         *)
(* Each switch is the decided design when TRUE; a `fail_*` cfg turns one  *)
(* off and TLC must find the invariant it protects broken. The README maps *)
(* every action to the code (file, function).                              *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Ids,          \* request ids
    Parent,       \* the principal that spawned Child
    Child,        \* a principal one delegation hop below Parent
    Effects,      \* effect keys: (method, host, path) or (kind, target)
    Args,         \* argument values; the descriptor carries their hash
    Lifetime,     \* a grant's lifetime, in ticks
    MaxTime,      \* last tick
    \* ---- the design (TRUE) or the bug each fail_* cfg shows (FALSE) ----
    Hold,         \* a related request or action waits while one for its effect is pending
    ConsumeOnce,  \* a grant's use is recorded with the action, so a replay finds it spent
    CheckAtRun,   \* a grant's lifetime is checked when the action runs, not when it was decided
    KeepIdentity, \* a delegated request keeps its originator's identity across the hop
    BindArgs      \* a grant matches the arguments' hash it was decided on

Principals == {Parent, Child}
NoGrant == [p |-> Parent, e |-> CHOOSE x \in Effects : TRUE, a |-> CHOOSE x \in Args : TRUE,
            exp |-> -1, live |-> FALSE]

VARIABLES
    now,
    reqs,       \* [Ids -> request]: st "none", "pending", "approved" or "denied"
    grants,     \* [Ids -> grant]: what approving request i issued (NoGrant before)
    spent,      \* grants whose one use an action recorded
    \* ---- history, for the safety properties ----
    ranWhilePending,  \* an action ran while a request for its principal and effect was pending
    ranTwice,         \* a grant's one use ran twice (a replay)
    ranPastExpiry,    \* an action ran at or past its grant's end
    ranAsOther,       \* an action ran under a grant issued to someone other than its originator
    ranUnbound        \* an action ran with arguments other than those its grant was decided on

hist == <<ranWhilePending, ranTwice, ranPastExpiry, ranAsOther, ranUnbound>>
vars == <<now, reqs, grants, spent, hist>>

None == [st |-> "none", origin |-> Parent, via |-> Parent, e |-> CHOOSE x \in Effects : TRUE,
         a |-> CHOOSE x \in Args : TRUE]

\* A request for principal p's effect e is waiting for a decision.
PendingFor(p, e) == \E j \in Ids : reqs[j].st = "pending" /\ reqs[j].origin = p /\ reqs[j].e = e

\* A request other than grant g's own, for the same originator and effect as request i, is pending:
\* a sibling's (or the same branch's) decision that i's action must wait for.
SiblingPending(i, g) ==
    \E j \in Ids : (j # g) /\ (reqs[j].st = "pending") /\ (reqs[j].origin = reqs[i].origin) /\ (reqs[j].e = reqs[i].e)

\* The identity the decider sees on a request p makes: its own (one record across the hop), or,
\* without KeepIdentity, the hop's (the parent relays the child's request as itself).
Via(p) == IF ~KeepIdentity /\ p = Child THEN Parent ELSE p

Init ==
    /\ now = 0
    /\ reqs = [i \in Ids |-> None]
    /\ grants = [i \in Ids |-> NoGrant]
    /\ spent = {}
    /\ ranWhilePending = FALSE /\ ranTwice = FALSE /\ ranPastExpiry = FALSE
    /\ ranAsOther = FALSE /\ ranUnbound = FALSE

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<reqs, grants, spent, hist>>

\* Principal p asks for effect e with arguments a (`Ledger::file_request`). With Hold a
\* second ask for an effect already pending for p files nothing: it waits on the pending one.
Ask(i, p, e, a) ==
    /\ reqs[i].st = "none"
    /\ Hold => ~PendingFor(p, e)
    /\ reqs' = [reqs EXCEPT ![i] = [st |-> "pending", origin |-> p, via |-> Via(p), e |-> e, a |-> a]]
    /\ UNCHANGED <<now, grants, spent, hist>>

\* A human (or an agent with grant rights) approves request i's descriptor: the grant is issued to
\* the identity the descriptor names, for its effect and its arguments' hash (`grant::decide`).
Approve(i) ==
    /\ reqs[i].st = "pending"
    /\ reqs' = [reqs EXCEPT ![i].st = "approved"]
    /\ grants' = [grants EXCEPT ![i] = [p |-> reqs[i].via, e |-> reqs[i].e, a |-> reqs[i].a,
                                        exp |-> now + Lifetime, live |-> TRUE]]
    /\ UNCHANGED <<now, spent, hist>>

Deny(i) ==
    /\ reqs[i].st = "pending"
    /\ reqs' = [reqs EXCEPT ![i].st = "denied"]
    /\ UNCHANGED <<now, grants, spent, hist>>

\* Request i's action runs under grant g with arguments a (the proxy sends it, or spawn, link,
\* update or capacity executes): the box may change the arguments after approval, may present the
\* request again (a retry, a replay), and may hold it until the grant is near its end.
Run(i, g, a) ==
    /\ reqs[i].st \in {"pending", "approved"}
    /\ grants[g].live
    /\ grants[g].e = reqs[i].e
    /\ grants[g].p = reqs[i].via               \* the decider matches the identity it is shown
    /\ BindArgs => grants[g].a = a
    /\ ConsumeOnce => g \notin spent
    /\ CheckAtRun => now < grants[g].exp
    /\ Hold => ~SiblingPending(i, g)
    /\ spent' = spent \cup {g}
    /\ ranWhilePending' = (ranWhilePending \/ SiblingPending(i, g))
    /\ ranTwice' = (ranTwice \/ g \in spent)
    /\ ranPastExpiry' = (ranPastExpiry \/ now >= grants[g].exp)
    /\ ranAsOther' = (ranAsOther \/ grants[g].p # reqs[i].origin)
    /\ ranUnbound' = (ranUnbound \/ grants[g].a # a)
    /\ UNCHANGED <<now, reqs, grants>>

Next ==
    \/ Tick
    \/ \E i \in Ids, p \in Principals, e \in Effects, a \in Args : Ask(i, p, e, a)
    \/ \E i \in Ids : Approve(i) \/ Deny(i)
    \/ \E i, g \in Ids, a \in Args : Run(i, g, a)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ now \in 0..MaxTime
    /\ \A i \in Ids : reqs[i].st \in {"none", "pending", "approved", "denied"}
    /\ spent \subseteq Ids

\* No action runs for a principal's effect while a request for that effect is waiting for a
\* decision, from a sibling branch or the same one (2607.14166).
HoldUntilDecided == ~ranWhilePending
\* An approved action runs once, however often it is presented again.
ExactlyOnceOnReplay == ~ranTwice
\* No action runs at or after its grant's end, however long it waited.
NoActionAfterExpiry == ~ranPastExpiry
\* An action runs only under a grant to its originator: a delegation hop neither lends the
\* parent's grants to the child nor hides the child behind the parent.
IdentityKeptAcrossHops ==
    /\ ~ranAsOther
    /\ \A i \in Ids : reqs[i].st # "none" => reqs[i].via = reqs[i].origin
\* An action runs only with the arguments its grant was decided on (2610.21063).
ArgumentsBound == ~ranUnbound

Safety == TypeOK /\ HoldUntilDecided /\ ExactlyOnceOnReplay /\ NoActionAfterExpiry
          /\ IdentityKeptAcrossHops /\ ArgumentsBound
=============================================================================

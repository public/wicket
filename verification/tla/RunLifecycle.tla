---------------------------- MODULE RunLifecycle ----------------------------
(***************************************************************************)
(* Model 2 of #321: one long-lived agent's activations (runs) across       *)
(* control-host restarts. A wake claims the agent and starts a box; the    *)
(* box's supervisor runs on the control host, renews the claim and the     *)
(* box's authority, hands the agent its messages, and closes its session   *)
(* when the agent asks to finish. A control-host crash kills every         *)
(* supervisor, never a box: its node keeps it running until its authority  *)
(* ends. The reconciler gives a box whose supervisor is gone a new one     *)
(* (re-attach). A wake may take over an agent whose holder let its claim   *)
(* lapse. See README.md for the code each action restates.                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Runs,               \* activation ids, e.g. {"r1", "r2"}
    Msgs,               \* messages for the agent (a peer's or an operator's), e.g. {"m1"}
    ClaimTtl,           \* CLAIM_SECS, in ticks
    AuthTtl,            \* how long a box's authority lasts past its last renewal, in ticks
    MaxTime,
    MaxCrashes,
    \* Design switches: TRUE is the pass design, FALSE the code without it (README.md says which are
    \* the code and which still open).
    FinishInLedger,     \* the agent's finish is recorded in the ledger, not only in its supervisor (#444)
    AckAfterHand,       \* a message is marked delivered once the box has it (and a box drops a repeat)
    WakeAfterAuthority  \* a lapsed holder's agent is woken only once every box of it has stopped

NONE == "none"

VARIABLES
    now, host, crashes,
    agent,      \* the ledger's agent row: [state, gen, holder, claimUntil]
    box,        \* r -> "none" | "running" | "stopped"   (the box, on its node)
    harness,    \* r -> "none" | "running" | "exited"    (the agent's process in it)
    sup,        \* r -> "none" | "alive" | "dead"        (its supervisor, on the control host)
    gen,        \* r -> the agent generation r was started with
    authUntil,  \* r -> when its box's authority ends (its node stops it then)
    asked,      \* r -> the agent in r called finish
    finLedger,  \* r -> its finish is in the ledger
    finSup,     \* r -> its supervisor knows of its finish
    stdinOpen,  \* r -> its session is open (the node records a close durably)
    msg,        \* m -> "unsent" | "queued" | "taken" | "handed" | "done" | "lost"
    msgTo,      \* m -> the run it is queued for, or NONE (held for the agent's principal)
    handedTo,   \* m -> r -> how many times r's harness was given m
    seen        \* r -> the messages r's box has had (its own record, outliving its supervisor)

vars == <<now, host, crashes, agent, box, harness, sup, gen, authUntil, asked, finLedger, finSup,
          stdinOpen, msg, msgTo, handedTo, seen>>

TypeOK ==
    /\ now \in 0..MaxTime
    /\ host \in {"up", "down"}
    /\ crashes \in 0..MaxCrashes
    /\ agent.state \in {"hibernated", "active"}
    /\ agent.holder \in Runs \cup {NONE}
    /\ box \in [Runs -> {"none", "running", "stopped"}]
    /\ harness \in [Runs -> {"none", "running", "exited"}]
    /\ sup \in [Runs -> {"none", "alive", "dead"}]
    /\ asked \in [Runs -> BOOLEAN]
    /\ finLedger \in [Runs -> BOOLEAN]
    /\ finSup \in [Runs -> BOOLEAN]
    /\ stdinOpen \in [Runs -> BOOLEAN]
    /\ msg \in [Msgs -> {"unsent", "queued", "taken", "handed", "done", "lost"}]
    /\ msgTo \in [Msgs -> Runs \cup {NONE}]
    /\ seen \in [Runs -> SUBSET Msgs]

Init ==
    /\ now = 0
    /\ host = "up"
    /\ crashes = 0
    /\ agent = [state |-> "hibernated", gen |-> 0, holder |-> NONE, claimUntil |-> 0]
    /\ box = [r \in Runs |-> "none"]
    /\ harness = [r \in Runs |-> "none"]
    /\ sup = [r \in Runs |-> "none"]
    /\ gen = [r \in Runs |-> 0]
    /\ authUntil = [r \in Runs |-> 0]
    /\ asked = [r \in Runs |-> FALSE]
    /\ finLedger = [r \in Runs |-> FALSE]
    /\ finSup = [r \in Runs |-> FALSE]
    /\ stdinOpen = [r \in Runs |-> FALSE]
    /\ msg = [m \in Msgs |-> "unsent"]
    /\ msgTo = [m \in Msgs |-> NONE]
    /\ handedTo = [m \in Msgs |-> [r \in Runs |-> 0]]
    /\ seen = [r \in Runs |-> {}]

(* Time passes. A node stops a box whose authority has ended (it can't renew it). *)
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ LET ends(r) == box[r] = "running" /\ authUntil[r] <= now + 1 IN
       /\ box' = [r \in Runs |-> IF ends(r) THEN "stopped" ELSE box[r]]
       /\ harness' = [r \in Runs |-> IF ends(r) THEN "exited" ELSE harness[r]]
    /\ UNCHANGED <<host, crashes, agent, sup, gen, authUntil, asked, finLedger, finSup, stdinOpen, msg,
                   msgTo, handedTo, seen>>

(* hibernate::wake and Ledger::claim_wake: a hibernated agent, or one whose holder's claim has *)
(* lapsed, becomes r's: a new generation, its claim, its box started; whatever was queued for  *)
(* an earlier activation, or held for its principal, is now r's.                               *)
Wake(r) ==
    /\ host = "up"
    /\ box[r] = "none" /\ sup[r] = "none"
    /\ \/ agent.state = "hibernated"
       \/ /\ agent.state = "active"
          /\ agent.claimUntil < now
          /\ WakeAfterAuthority => \A q \in Runs : box[q] = "running" => authUntil[q] <= now
    /\ agent' = [state |-> "active", gen |-> agent.gen + 1, holder |-> r, claimUntil |-> now + ClaimTtl]
    /\ box' = [box EXCEPT ![r] = "running"]
    /\ harness' = [harness EXCEPT ![r] = "running"]
    /\ sup' = [sup EXCEPT ![r] = "alive"]
    /\ gen' = [gen EXCEPT ![r] = agent.gen + 1]
    /\ authUntil' = [authUntil EXCEPT ![r] = now + AuthTtl]
    /\ stdinOpen' = [stdinOpen EXCEPT ![r] = TRUE]
    /\ msgTo' = [m \in Msgs |-> IF msg[m] = "queued" THEN r ELSE msgTo[m]]
    /\ UNCHANGED <<now, host, crashes, asked, finLedger, finSup, msg, handedTo, seen>>

(* run.rs's heartbeat: the holder renews its claim (and its box's authority). *)
Renew(r) ==
    /\ host = "up" /\ sup[r] = "alive" /\ box[r] = "running"
    /\ gen[r] = agent.gen
    /\ agent' = [agent EXCEPT !.claimUntil = now + ClaimTtl]
    /\ authUntil' = [authUntil EXCEPT ![r] = now + AuthTtl]
    /\ UNCHANGED <<now, host, crashes, box, harness, sup, gen, asked, finLedger, finSup, stdinOpen, msg,
                   msgTo, handedTo, seen>>

(* run.rs's heartbeat, superseded: a newer activation has the agent, so this box stops. *)
Supersede(r) ==
    /\ host = "up" /\ sup[r] = "alive" /\ box[r] = "running"
    /\ gen[r] # agent.gen
    /\ box' = [box EXCEPT ![r] = "stopped"]
    /\ harness' = [harness EXCEPT ![r] = "exited"]
    /\ sup' = [sup EXCEPT ![r] = "none"]
    /\ UNCHANGED <<now, host, crashes, agent, gen, authUntil, asked, finLedger, finSup, stdinOpen, msg,
                   msgTo, handedTo, seen>>

(* The control host stops: every supervisor with it, and what only they knew. Boxes run on. *)
Crash ==
    /\ host = "up" /\ crashes < MaxCrashes
    /\ host' = "down"
    /\ crashes' = crashes + 1
    /\ sup' = [r \in Runs |-> IF sup[r] = "alive" THEN "dead" ELSE sup[r]]
    /\ finSup' = [r \in Runs |-> FALSE]
    \* Taken and not yet acknowledged: queued again (the proposed design). Today a taken message is
    \* delivered as far as the ledger knows, and the only copy was the dead supervisor's: lost.
    /\ msg' = [m \in Msgs |-> IF msg[m] \in {"taken", "handed"} THEN (IF AckAfterHand THEN "queued" ELSE "lost")
                             ELSE msg[m]]
    /\ UNCHANGED <<now, agent, box, harness, gen, authUntil, asked, finLedger, stdinOpen, msgTo, handedTo, seen>>

Restart ==
    /\ host = "down"
    /\ host' = "up"
    /\ UNCHANGED <<now, crashes, agent, box, harness, sup, gen, authUntil, asked, finLedger, finSup,
                   stdinOpen, msg, msgTo, handedTo, seen>>

(* reconcile.rs (run_adopted): a box whose supervisor is gone gets a new one, which knows what *)
(* the ledger knows.                                                                           *)
Adopt(r) ==
    /\ host = "up" /\ sup[r] = "dead" /\ box[r] = "running"
    /\ sup' = [sup EXCEPT ![r] = "alive"]
    /\ finSup' = [finSup EXCEPT ![r] = FinishInLedger /\ finLedger[r]]
    /\ UNCHANGED <<now, host, crashes, agent, box, harness, gen, authUntil, asked, finLedger, stdinOpen,
                   msg, msgTo, handedTo, seen>>

(* reconcile.rs (run_lost): no box left, so the run ends. *)
Lost(r) ==
    /\ host = "up" /\ sup[r] = "dead" /\ box[r] # "running"
    /\ sup' = [sup EXCEPT ![r] = "none"]
    /\ UNCHANGED <<now, host, crashes, agent, box, harness, gen, authUntil, asked, finLedger, finSup,
                   stdinOpen, msg, msgTo, handedTo, seen>>

(* The agent calls wicket's finish tool: the ledger records it (gateway.rs `want` →          *)
(* Ledger::record_run_want, #444), and its supervisor is told (want_rx).                       *)
AskFinish(r) ==
    /\ host = "up" /\ sup[r] = "alive" /\ harness[r] = "running" /\ ~asked[r]
    /\ asked' = [asked EXCEPT ![r] = TRUE]
    /\ finSup' = [finSup EXCEPT ![r] = TRUE]
    /\ finLedger' = [finLedger EXCEPT ![r] = FinishInLedger]
    /\ UNCHANGED <<now, host, crashes, agent, box, harness, sup, gen, authUntil, stdinOpen, msg, msgTo,
                   handedTo, seen>>

(* run.rs: at the end of the turn, the session closes (StdinClose, which the node records). *)
CloseSession(r) ==
    /\ host = "up" /\ sup[r] = "alive" /\ finSup[r] /\ stdinOpen[r]
    /\ stdinOpen' = [stdinOpen EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<now, host, crashes, agent, box, harness, sup, gen, authUntil, asked, finLedger, finSup,
                   msg, msgTo, handedTo, seen>>

(* The harness exits at the end of its session (or is stopped after its grace, #293); its box *)
(* ends with it.                                                                               *)
HarnessExits(r) ==
    /\ harness[r] = "running" /\ ~stdinOpen[r]
    /\ harness' = [harness EXCEPT ![r] = "exited"]
    /\ box' = [box EXCEPT ![r] = "stopped"]
    /\ UNCHANGED <<now, host, crashes, agent, sup, gen, authUntil, asked, finLedger, finSup, stdinOpen,
                   msg, msgTo, handedTo, seen>>

(* send_message: to the agent's holder while it holds the agent, else held for its principal. *)
Send(m) ==
    /\ host = "up" /\ msg[m] = "unsent"
    /\ msg' = [msg EXCEPT ![m] = "queued"]
    /\ msgTo' = [msgTo EXCEPT ![m] = IF agent.state = "active" THEN agent.holder ELSE NONE]
    /\ UNCHANGED <<now, host, crashes, agent, box, harness, sup, gen, authUntil, asked, finLedger, finSup,
                   stdinOpen, handedTo, seen>>

(* Ledger::take_message (await_message) and take_operator_messages: the supervisor takes it,  *)
(* and today the ledger marks it delivered.                                                    *)
Take(m, r) ==
    /\ host = "up" /\ sup[r] = "alive" /\ box[r] = "running"
    /\ msg[m] = "queued" /\ msgTo[m] = r
    /\ msg' = [msg EXCEPT ![m] = "taken"]
    /\ UNCHANGED <<now, host, crashes, agent, box, harness, sup, gen, authUntil, asked, finLedger, finSup,
                   stdinOpen, msgTo, handedTo, seen>>

(* ...and gives it to the harness (the tool's reply, or stdin). A box that has had it drops it *)
(* in the proposed design.                                                                     *)
Hand(m, r) ==
    /\ host = "up" /\ sup[r] = "alive" /\ harness[r] = "running"
    /\ msg[m] = "taken" /\ msgTo[m] = r
    /\ handedTo' = [handedTo EXCEPT ![m][r] = IF AckAfterHand /\ m \in seen[r] THEN @ ELSE @ + 1]
    /\ seen' = [seen EXCEPT ![r] = @ \cup {m}]
    /\ msg' = [msg EXCEPT ![m] = IF AckAfterHand THEN "handed" ELSE "done"]
    /\ UNCHANGED <<now, host, crashes, agent, box, harness, sup, gen, authUntil, asked, finLedger, finSup,
                   stdinOpen, msgTo>>

(* The proposed design's acknowledgement: marked delivered once the box has it. *)
Ack(m) ==
    /\ host = "up" /\ msg[m] = "handed" /\ sup[msgTo[m]] = "alive"
    /\ msg' = [msg EXCEPT ![m] = "done"]
    /\ UNCHANGED <<now, host, crashes, agent, box, harness, sup, gen, authUntil, asked, finLedger, finSup,
                   stdinOpen, msgTo, handedTo, seen>>

Next ==
    \/ Tick \/ Crash \/ Restart
    \/ \E r \in Runs : Wake(r) \/ Renew(r) \/ Supersede(r) \/ Adopt(r) \/ Lost(r) \/ AskFinish(r)
                       \/ CloseSession(r) \/ HarnessExits(r)
    \/ \E m \in Msgs : Send(m) \/ Ack(m) \/ \E r \in Runs : Take(m, r) \/ Hand(m, r)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety.                                                                 *)
(***************************************************************************)

(* A wake never starts a second harness of the agent while another runs. *)
OneHarness == Cardinality({r \in Runs : harness[r] = "running"}) <= 1

(* No message is lost: none the ledger counts as delivered without the agent ever having it. *)
NoMessageLost == \A m \in Msgs : msg[m] # "lost"

(* No box is given a message twice. *)
NoMessageTwice == \A m \in Msgs, r \in Runs : handedTo[m][r] <= 1

(* A live supervisor of an agent that asked to finish, whose session is still open, knows it,   *)
(* so it closes the session: a finished run's harness never keeps running.                      *)
FinishKnown ==
    \A r \in Runs : (host = "up" /\ sup[r] = "alive" /\ asked[r] /\ stdinOpen[r] /\ harness[r] = "running") => finSup[r]

=============================================================================

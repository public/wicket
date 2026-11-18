------------------------------- MODULE Update -------------------------------
(***************************************************************************)
(* Model 4 of #321: the control host moving to a new build while long-     *)
(* lived runs go on (#455, #468, #475, #477, #487, #489, #529). Two ways a *)
(* new build arrives: an install (`deploy/install.sh`), which restarts     *)
(* wicketd (`systemctl restart`: its runs' supervisors, and this host's    *)
(* own node's serve, survive on the build they started on), and `wicket    *)
(* self update`, which re-executes the local serve, stops the runs' old    *)
(* supervisors (the new build's reconciler re-attaches them) and sends     *)
(* wicketd SIGHUP: it drains (refuses new commands, writes the handoff of  *)
(* its running ones) and re-executes as the new build. The new build       *)
(* writes prompts in its schema; a supervisor on the old build reads them. *)
(* A run's box on the local node is served by the local serve: a new       *)
(* build's supervisor re-attached to an old build's serve lost its box     *)
(* (#529). See README.md for the code each action restates.               *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Runs,               \* long-lived runs, each with one supervisor, e.g. {"r1", "r2"}
    LocalRuns,          \* the runs whose box is on this host's own node, a subset of Runs
    Prompts,            \* operators' prompts, e.g. {"p1", "p2"}
    MaxTime,
    HandoverMax,        \* how long a handover may take (the serve's re-exec, stop_stale_supervisors' wait, the reconcile)
    DrainMax,           \* how long the daemon may refuse commands while it moves to the new build
    \* Design switches: TRUE is the pass design and the code, FALSE the code before its fix.
    ExpandSafe,         \* an older build handles every row a newer one writes (the expand rule, #475)
    HandOverOnStart,    \* wicketd's start hands old-build supervisors to its own build (#477)
    DrainReturns,       \* the SIGHUP drain returns: it doesn't take the registry it holds (#489)
    ServeFirstOnStart,  \* wicketd's start re-executes the local serve as its build, before the handover (#529)
    ServeFirstOnUpdate  \* a self update re-executes the local serve before it stops the old supervisors (#529)

ASSUME LocalRuns \subseteq Runs

VARIABLES
    now,
    build,          \* the installed build: "old" | "new"
    installedAt,    \* when the new build was installed (or MaxTime + 1 before)
    daemon,         \* [state |-> "up" | "starting" | "draining", build |-> "old" | "new", since |-> time]
    serve,          \* the build this host's own node's serve runs: "old" | "new"
    serveDue,       \* the new daemon's re-exec of the local serve is to do (#529), before its handover
    handover,       \* the new daemon's handover of old-build supervisors is to do (#477)
    sup,            \* r -> "old" | "new" | "stopped" (its supervisor: on which build, or stopped for a re-attach)
    box,            \* r -> "running" | "stopped" (its box)
    prompt,         \* p -> "unsent" | "queued" | "read" | "lost"
    promptTo,       \* p -> the run it is for
    written         \* p -> the build whose schema wrote it

vars == <<now, build, installedAt, daemon, serve, serveDue, handover, sup, box, prompt, promptTo, written>>

Never == MaxTime + 1

TypeOK ==
    /\ now \in 0..MaxTime
    /\ build \in {"old", "new"}
    /\ daemon.state \in {"up", "starting", "draining"}
    /\ daemon.build \in {"old", "new"}
    /\ serve \in {"old", "new"}
    /\ serveDue \in BOOLEAN
    /\ handover \in BOOLEAN
    /\ sup \in [Runs -> {"old", "new", "stopped"}]
    /\ box \in [Runs -> {"running", "stopped"}]
    /\ prompt \in [Prompts -> {"unsent", "queued", "read", "lost"}]
    /\ promptTo \in [Prompts -> Runs]
    /\ written \in [Prompts -> {"old", "new"}]

Init ==
    /\ now = 0
    /\ build = "old"
    /\ installedAt = Never
    /\ daemon = [state |-> "up", build |-> "old", since |-> 0]
    /\ serve = "old"
    /\ serveDue = FALSE
    /\ handover = FALSE
    /\ sup = [r \in Runs |-> "old"]
    /\ box = [r \in Runs |-> "running"]
    /\ prompt = [p \in Prompts |-> "unsent"]
    /\ promptTo \in [Prompts -> Runs]
    /\ written = [p \in Prompts |-> "old"]

(* The bounds the code keeps (its timeouts), as obligations on time: time doesn't pass a     *)
(* handover's bound while it can still act, nor a drain's while it can still return.         *)
HandoverDue == (serveDue \/ (handover /\ \E r \in Runs : sup[r] = "old")) /\ now >= installedAt + HandoverMax
DrainDue == daemon.state = "draining" /\ DrainReturns /\ now >= daemon.since + DrainMax

Tick ==
    /\ now < MaxTime
    /\ ~HandoverDue /\ ~DrainDue
    \* A restarted daemon starts at once (systemd), within the tick it was restarted in.
    /\ daemon.state # "starting"
    /\ now' = now + 1
    /\ UNCHANGED <<build, installedAt, daemon, serve, serveDue, handover, sup, box, prompt, promptTo, written>>

(* An operator's prompt (`wicket session`, the console), through the daemon when it takes    *)
(* commands: written in its build's schema (#463: a row of `messages`, kind prompt).          *)
Send(p) ==
    /\ daemon.state = "up" /\ prompt[p] = "unsent"
    /\ prompt' = [prompt EXCEPT ![p] = "queued"]
    /\ written' = [written EXCEPT ![p] = daemon.build]
    /\ UNCHANGED <<now, build, installedAt, daemon, serve, serveDue, handover, sup, box, promptTo>>

(* A run's supervisor takes its prompts and gives them to the harness in its box. One on the  *)
(* old build, reading a row of the new schema: handled if the step was expand-safe, else      *)
(* dropped (#475: an old `await_message` took a prompt as a peer's message and dropped it).   *)
Take(p) ==
    LET r == promptTo[p] IN
    /\ prompt[p] = "queued" /\ sup[r] \in {"old", "new"} /\ box[r] = "running"
    /\ prompt' = [prompt EXCEPT ![p] = IF sup[r] = "old" /\ written[p] = "new" /\ ~ExpandSafe THEN "lost" ELSE "read"]
    /\ UNCHANGED <<now, build, installedAt, daemon, serve, serveDue, handover, sup, box, promptTo, written>>

(* `deploy/install.sh`: the new build is installed and wicketd restarted (systemctl restart,  *)
(* KillMode=process): the runs' supervisors survive on the old build (#468), and so does its  *)
(* child, this host's own node's serve (#529).                                                *)
Install ==
    /\ build = "old" /\ daemon.state = "up"
    /\ build' = "new"
    /\ installedAt' = now
    /\ daemon' = [state |-> "starting", build |-> "new", since |-> now]
    /\ UNCHANGED <<now, serve, serveDue, handover, sup, box, prompt, promptTo, written>>

(* The new wicketd starts: it takes commands at once, and on a thread of its own re-executes  *)
(* the local serve (#529), then hands its old-build supervisors over (#477). Before #477 that *)
(* thread didn't exist; before #529 it didn't move the serve.                                 *)
DaemonStart ==
    /\ daemon.state = "starting"
    /\ daemon' = [daemon EXCEPT !.state = "up", !.since = now]
    /\ serveDue' = (HandOverOnStart /\ ServeFirstOnStart /\ serve # build)
    /\ handover' = HandOverOnStart
    /\ UNCHANGED <<now, build, installedAt, serve, sup, box, prompt, promptTo, written>>

(* `reexec_local_node`: SIGHUP, and the serve re-executes as the current build, same pid, its *)
(* boxes adopted (they keep running). The handover waits for it.                             *)
ServeReexec ==
    /\ serveDue
    /\ serve' = build
    /\ serveDue' = FALSE
    /\ UNCHANGED <<now, build, installedAt, daemon, handover, sup, box, prompt, promptTo, written>>

(* `stop_stale_supervisors`: an old-build supervisor is stopped (SIGKILL), its box left        *)
(* running. After the serve's re-exec, when there is one to do.                               *)
HandOver(r) ==
    /\ handover /\ ~serveDue /\ sup[r] = "old"
    /\ sup' = [sup EXCEPT ![r] = "stopped"]
    /\ handover' = (\E q \in Runs \ {r} : sup[q] = "old")
    /\ UNCHANGED <<now, build, installedAt, daemon, serve, serveDue, box, prompt, promptTo, written>>

(* A reconciler (the handover's own pass, or the reconciler service's, whichever comes first) *)
(* re-attaches a run whose supervisor is gone (`wicket attach`, on the current build). A new  *)
(* build's supervisor re-attached to a box on the local node whose serve is on another build  *)
(* ended that box (#529: "stopped by wicket: its control host stopped it", 2 s after).        *)
Reattach(r) ==
    /\ sup[r] = "stopped" /\ box[r] = "running"
    /\ sup' = [sup EXCEPT ![r] = build]
    /\ box' = [box EXCEPT ![r] = IF r \in LocalRuns /\ serve # build THEN "stopped" ELSE "running"]
    /\ UNCHANGED <<now, build, installedAt, daemon, serve, serveDue, handover, prompt, promptTo, written>>

(* `wicket self update`: it switches the build, re-executes the local serve and waits for it, *)
(* stops the old supervisors (its `handover`, in that order), and sends wicketd SIGHUP: the   *)
(* daemon drains. Before #529's fix the serve's re-exec came after the stop, and a reconciler  *)
(* could re-attach a stopped run in between.                                                  *)
SelfUpdate ==
    /\ build = "old" /\ daemon.state = "up"
    /\ build' = "new"
    /\ installedAt' = now
    /\ serve' = IF ServeFirstOnUpdate THEN "new" ELSE serve
    /\ serveDue' = ~ServeFirstOnUpdate
    /\ sup' = [r \in Runs |-> IF sup[r] = "old" THEN "stopped" ELSE sup[r]]
    /\ daemon' = [daemon EXCEPT !.state = "draining", !.since = now]
    /\ UNCHANGED <<now, handover, box, prompt, promptTo, written>>

(* The drain returns and the daemon re-executes as the new build, taking commands again       *)
(* (#489). Before #489 it took the registry lock it held, and never returned (#487).          *)
DrainDone ==
    /\ daemon.state = "draining" /\ DrainReturns
    /\ daemon' = [state |-> "up", build |-> build, since |-> now]
    /\ UNCHANGED <<now, build, installedAt, serve, serveDue, handover, sup, box, prompt, promptTo, written>>

Next ==
    \/ Tick \/ Install \/ DaemonStart \/ ServeReexec \/ SelfUpdate \/ DrainDone
    \/ \E r \in Runs : HandOver(r) \/ Reattach(r)
    \/ \E p \in Prompts : Send(p) \/ Take(p)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety.                                                                 *)
(***************************************************************************)

(* No operator's prompt is lost across an update. *)
NoPromptLost == \A p \in Prompts : prompt[p] # "lost"

(* After an update, no supervisor runs the old build for longer than the handover. *)
OldBuildBounded == build = "new" => \A r \in Runs : sup[r] = "old" => now <= installedAt + HandoverMax

(* The daemon always takes commands again: it refuses them for no longer than its drain. *)
DaemonTakesCommands == daemon.state = "draining" => now <= daemon.since + DrainMax

(* An update keeps every run's box: a re-attach never ends the box it means to keep (#529). *)
BoxesKept == \A r \in Runs : box[r] = "running"

=============================================================================

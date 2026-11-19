---------------------------- MODULE UpdateTrace ----------------------------
(***************************************************************************)
(* Trace validation for Update.tla (#321, #324): is what the control host  *)
(* audited during a real update a behaviour of the model? A trail is the   *)
(* sequence of audited steps (`ci/tla-trail.py` makes it from an audit     *)
(* export): each `reconcile.run_adopted` and `run.attach` of a run is      *)
(* `Reattach(r)`, with the box's state after it (`stopped` when the run    *)
(* ended "stopped by wicket" within seconds). What isn't audited (wicketd  *)
(* restarting, the local serve's re-exec, the old supervisors being        *)
(* stopped, ticks, prompts; and wicketd's start where it isn't audited)   *)
(* may happen between the trail's steps, as any                            *)
(* of the model's own actions. A `trail_*.cfg` checks `TrailUnmatched`:    *)
(* TLC refuses it exactly when some behaviour of the model takes every     *)
(* step of the trail, which is then a behaviour of the model.              *)
(***************************************************************************)
EXTENDS Update, Sequences

CONSTANTS
    Trail,          \* the audited steps, e.g. Trail1848 below
    ViaInstall,     \* the update was an install (TRUE) or a self update (FALSE)
    DaemonAudited   \* wicketd audits its start (`daemon.started`), so it isn't a hidden step

VARIABLE i          \* how many of the trail's steps have been taken

(* What the audit doesn't record: any of the model's actions but the trail's own and the other  *)
(* way of updating.                                                                             *)
Hidden ==
    \/ Tick \/ ServeReexec
    \/ (~DaemonAudited /\ (DaemonStart \/ DrainDone))
    \/ (ViaInstall /\ Install)
    \/ (~ViaInstall /\ SelfUpdate)
    \/ \E r \in Runs : HandOver(r)
    \/ \E p \in Prompts : Send(p) \/ Take(p)

(* The trail's next step: a re-attach of its run, leaving its box as audited (`run.attach`); the   *)
(* build switched (`self.switched`); wicketd started (`daemon.started`), after a restart or, after *)
(* a SIGHUP, as the drain's end; or time passing (a drain bound's worth, with no `daemon.started`  *)
(* after `daemon.sighup`).                                                                       *)
Observed ==
    /\ i < Len(Trail)
    /\ LET e == Trail[i + 1] IN
        \/ e.action = "Reattach" /\ Reattach(e.run) /\ box'[e.run] = e.box
        \/ e.action = "SelfUpdate" /\ SelfUpdate
        \/ e.action = "DrainDone" /\ DrainDone
        \/ e.action = "DaemonStart" /\ DaemonStart
        \/ e.action = "Tick" /\ Tick
    /\ i' = i + 1

TraceInit == Init /\ i = 0

TraceNext == (Hidden /\ UNCHANGED i) \/ Observed

TraceSpec == TraceInit /\ [][TraceNext]_<<vars, i>>

(* Refused exactly when a behaviour of the model takes the whole trail. *)
TrailUnmatched == i < Len(Trail)

(***************************************************************************)
(* The trails of 2026-11-18's installs, as `ci/tla-trail.py` printed them  *)
(* from the control host's audit export (verification/tla/trails/):       *)
(* r1 is the run on this host's own node, r2 the one on a remote node.     *)
(***************************************************************************)

\* The 17:58 install (#529): both runs re-attached at 17:59:02; r1's box was stopped 2 s later.
Trail1759 == << [action |-> "Reattach", run |-> "r1", box |-> "stopped"], [action |-> "Reattach", run |-> "r2", box |-> "running"] >>

\* The 18:48 install, with #531: both runs re-attached, both boxes kept.
Trail1848 == << [action |-> "Reattach", run |-> "r2", box |-> "running"], [action |-> "Reattach", run |-> "r1", box |-> "running"] >>

(***************************************************************************)
(* A self update's trail, constructed (not audited: the export of         *)
(* 2026-11-18 doesn't reach the 10:04 update, #487, and no build then     *)
(* audited the drain). As its records read with `daemon.sighup` and       *)
(* `daemon.started` audited: the switch, the two re-attaches, then the     *)
(* SIGHUP and two drain bounds with no `daemon.started`.                   *)
(***************************************************************************)
TrailHungDrain == << [action |-> "SelfUpdate", run |-> "none", box |-> "none"],
                     [action |-> "Reattach", run |-> "r1", box |-> "running"],
                     [action |-> "Reattach", run |-> "r2", box |-> "running"],
                     [action |-> "Tick", run |-> "none", box |-> "none"],
                     [action |-> "Tick", run |-> "none", box |-> "none"] >>

\* The same self update, its drain returning: `daemon.started` after the SIGHUP.
TrailSelfUpdate == << [action |-> "SelfUpdate", run |-> "none", box |-> "none"],
                      [action |-> "Reattach", run |-> "r1", box |-> "running"],
                      [action |-> "Reattach", run |-> "r2", box |-> "running"],
                      [action |-> "DrainDone", run |-> "none", box |-> "none"] >>

=============================================================================

//! The update scenario (#324): the control host moves to a new build while long-lived runs go on,
//! one with its box on this host's own node and one on a remote node. Either way a build arrives:
//!
//! - **An install** (`deploy/install.sh`). wicketd is restarted (`KillMode=process`), and the
//!   runs' supervisors and its child, the local node's serve, survive on the old build (#468).
//!   The new wicketd takes commands at once. On a thread (`hand_over_runs`), it re-executes the
//!   local serve (#529, `update::reexec_local_node`), stops the old-build supervisors
//!   (`stop_stale_supervisors`, #477), and runs its reconcile, which re-attaches each run on the
//!   new build. install.sh then restarts `wicket-reconcile.service`.
//! - **`wicket self update`.** Its `handover` re-executes the local serve, stops the old
//!   supervisors and adopts their runs. Then it sends wicketd SIGHUP: the daemon drains (it refuses
//!   new commands while it writes the handoff) and re-executes as the new build (#455, #489).
//!
//! Meanwhile the reconciler service's own passes re-attach any run whose supervisor is gone,
//! whichever comes first. An operator's CLI sends prompts through the daemon, retrying while it
//! refuses; each is written in the daemon's build's schema, and the run's supervisor takes it.
//!
//! These are processes, signals and `exec`, which turmoil's hosts don't model. So this scenario is
//! a discrete-event simulation of them, seeded: the plan (which update, when, and how long each
//! step takes) and every interleaving come from the seed. Its stand-ins follow the code named
//! above, as `verification/tla/Update.tla` restates it.
//!
//! The oracle checks three things:
//! - **No box is stopped.** A re-attach never ends the box it means to keep, and neither does a
//!   restart.
//! - **No prompt is lost.** Each is read by the run's harness by the end.
//! - **The CLI is answered within [`CLI_BOUND_MS`].** The daemon refuses commands only for its
//!   start and its drain.
//!
//! Each fix has a switch in [`Options`], and each switch has a seed that breaks the invariant it
//! protects once the fix is turned off (`tests/scenario.rs`, `update_without_*`):
//!
//! | switch | the code without it |
//! |---|---|
//! | `expand_safe` and `hand_over_on_start` | #475: an old supervisor drops a new-schema prompt, and an install leaves old supervisors on (no #477) |
//! | `drain_returns` | #487: the SIGHUP drain never returns, so the CLI is never answered |
//! | `serve_first_on_start` | #529: the new wicketd hands runs over while the local serve is still the old build |
//! | `serve_first_on_update` | #529, in a self update: the stop came before the serve's re-exec, and a reconcile pass can re-attach in between |
//! | `reconcile_keeps_children` | #529: without `KillMode=process`, restarting the reconciler unit SIGTERMs the supervisors its passes started |
//!
//! What a new build's supervisor attached to an old build's local serve does is taken as it was
//! seen (#529: the box was stopped, "its control host stopped it"); why is not modelled. A remote
//! node's serve is within the protocol's skew, and is moved by `wicket self update --nodes`, not
//! here. A rollback, several updates in a row and nodes' own updates are not modelled either.

use crate::rng::Rng;
use crate::trace::{Report, Trace};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt;

/// How long a CLI call may go unanswered (ms): the daemon's start and drain take far less.
pub const CLI_BOUND_MS: i64 = 10_000;
/// When the scenario ends (ms): long after the update, so every prompt has been taken.
const END_MS: i64 = 60_000;
/// How often the CLI tries again while the daemon refuses (ms).
const RETRY_MS: i64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Build {
    Old,
    New,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeKind {
    Local,
    Remote,
}

/// Which process started a supervisor: what a restart of it does to the supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Parent {
    /// wicketd, or the update's own reconcile it runs: `KillMode=process` leaves it.
    Daemon,
    /// A pass of `wicket-reconcile.service`.
    Reconciler,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Daemon {
    Up,
    /// Restarted by systemd: not taking commands yet.
    Starting,
    /// On SIGHUP: refusing new commands until the drain returns.
    Draining,
}

/// How the new build arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Update {
    Install,
    SelfUpdate,
}

struct Run {
    node: NodeKind,
    sup_build: Build,
    sup_parent: Parent,
    sup_alive: bool,
    box_running: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PromptState {
    Queued,
    Read,
    Lost,
}

struct Prompt {
    run: usize,
    schema: Build,
    state: PromptState,
}

struct Call {
    run: usize,
    first: i64,
    answered: bool,
    late: bool,
}

/// What a seed decides.
pub struct Plan {
    pub seed: u64,
    pub update: Update,
    /// When the update starts (ms).
    pub at: i64,
    /// How long wicketd takes to start again after an install's restart.
    daemon_down: i64,
    /// How long the local serve's re-exec takes (`reexec_serve` waits for it).
    serve_reexec: i64,
    /// From stopping the old supervisors to the update's reconcile re-attaching them.
    adopt_after: i64,
    /// From wicketd's start to install.sh's restart of the reconciler unit.
    reconcile_restart_after: i64,
    /// The reconciler service's passes: every `period`, the first at `phase`.
    period: i64,
    phase: i64,
    /// How long the drain takes, when it returns.
    drain: i64,
    /// How often a supervisor takes its prompts.
    poll: i64,
    /// The CLI's prompts: (when, which run).
    prompts: Vec<(i64, usize)>,
}

impl Plan {
    pub fn new(seed: u64) -> Plan {
        let mut r = Rng::new(seed ^ 0x0BAD_C0DE_0000_0477);
        let update = if r.chance(0.5) { Update::Install } else { Update::SelfUpdate };
        let at = r.range_i(5_000, 20_000);
        let mut prompts: Vec<(i64, usize)> = (0..r.range(6, 12)).map(|_| (r.range_i(0, 40_000), r.range(0, 1) as usize)).collect();
        prompts.sort_unstable();
        Plan {
            seed,
            update,
            at,
            daemon_down: r.range_i(200, 1_500),
            serve_reexec: r.range_i(50, 500),
            adopt_after: r.range_i(100, 2_000),
            reconcile_restart_after: r.range_i(0, 2_000),
            period: r.range_i(1_000, 5_000),
            phase: r.range_i(0, 1_000),
            drain: r.range_i(0, 300),
            poll: r.range_i(150, 400),
            prompts,
        }
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "update seed {}: {:?} at {} ms", self.seed, self.update, self.at)?;
        writeln!(
            f,
            "  daemon down {} ms, serve re-exec {} ms, adopt after {} ms, reconciler restart after {} ms, its passes every {} ms from {} ms, drain {} ms, supervisors poll every {} ms",
            self.daemon_down, self.serve_reexec, self.adopt_after, self.reconcile_restart_after, self.period, self.phase, self.drain, self.poll
        )?;
        let p: Vec<String> = self.prompts.iter().map(|(t, r)| format!("{t}:r{r}")).collect();
        writeln!(f, "  prompts {}", p.join(" "))
    }
}

/// The fixes, each switchable off to find its bug again. All on is today's code.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub keep_trace: bool,
    /// An older build handles every row a newer one writes (the expand rule, #475).
    pub expand_safe: bool,
    /// wicketd's start hands old-build supervisors to its own build (#477).
    pub hand_over_on_start: bool,
    /// The SIGHUP drain returns (#489; before it, #487).
    pub drain_returns: bool,
    /// wicketd's start re-executes the local serve before it hands runs over (#529).
    pub serve_first_on_start: bool,
    /// A self update re-executes the local serve before it stops the old supervisors (#529).
    pub serve_first_on_update: bool,
    /// `wicket-reconcile.service` has `KillMode=process` (#529).
    pub reconcile_keeps_children: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            keep_trace: false,
            expand_safe: true,
            hand_over_on_start: true,
            drain_returns: true,
            serve_first_on_start: true,
            serve_first_on_update: true,
            reconcile_keeps_children: true,
        }
    }
}

/// What happens next. Ordered by time, then by when it was scheduled, so a seed replays exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    /// The CLI tries call `n` (again).
    Try(usize),
    /// Run `n`'s supervisor takes its queued prompts.
    Poll(usize),
    UpdateStarts,
    /// wicketd is up again after an install's restart.
    DaemonStarted,
    /// The local serve is the new build; then `Then`.
    ServeReexecuted(Then),
    /// `stop_stale_supervisors`; then `Then`.
    StopStale(Then),
    /// The update's own reconcile re-attaches the handed runs.
    Adopt,
    /// A pass of the reconciler service.
    ReconcilePass,
    /// install.sh restarts the reconciler unit.
    ReconcileRestart,
    /// `wicket self update` sends wicketd SIGHUP.
    Sighup,
    DrainReturns,
}

/// What a step of a handover does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Then {
    /// Stop the old supervisors (the serve went first).
    Stop,
    /// Re-execute the serve (the stop went first: the old order).
    Serve,
    /// Adopt.
    Adopt,
}

struct Sim {
    plan: Plan,
    o: Options,
    trace: Trace,
    now: i64,
    seq: u64,
    queue: BinaryHeap<Reverse<(i64, u64, Ev)>>,
    build: Build,
    daemon: Daemon,
    daemon_build: Build,
    serve: Build,
    runs: Vec<Run>,
    prompts: Vec<Prompt>,
    calls: Vec<Call>,
    stopped: usize,
    longest_wait: i64,
}

impl Sim {
    fn at(&mut self, t: i64, e: Ev) {
        self.seq += 1;
        self.queue.push(Reverse((t, self.seq, e)));
    }

    fn note(&mut self, line: impl Into<String>) {
        self.trace.note(self.now, line);
    }

    /// A supervisor of the current build re-attaches run `r` (`wicket attach`).
    fn attach(&mut self, r: usize, parent: Parent) {
        let build = self.build;
        let run = &mut self.runs[r];
        run.sup_build = build;
        run.sup_parent = parent;
        run.sup_alive = true;
        let node = run.node;
        self.note(format!("r{r}: re-attached by {parent:?} on the {build:?} build"));
        // #529, as it was seen: a new build's supervisor on an old build's local serve lost the box.
        if node == NodeKind::Local && self.serve != build {
            self.stop_box(r, "a supervisor of the new build re-attached to the local node's serve on the old build");
        }
    }

    fn stop_box(&mut self, r: usize, why: &str) {
        if !self.runs[r].box_running {
            return;
        }
        self.runs[r].box_running = false;
        self.runs[r].sup_alive = false;
        self.stopped += 1;
        let node = self.runs[r].node;
        self.trace.violate(self.now, format!("r{r}'s box on the {node:?} node was stopped: {why}"));
    }

    /// `stop_stale_supervisors`: SIGKILL, so each box goes on.
    fn stop_stale(&mut self) {
        for r in 0..self.runs.len() {
            if self.runs[r].sup_alive && self.runs[r].sup_build != self.build {
                self.runs[r].sup_alive = false;
                self.note(format!("r{r}: its old-build supervisor stopped, its box left running"));
            }
        }
    }

    /// A reconcile (the update's own, or a pass of the service): re-attaches each run whose box
    /// runs and whose supervisor is gone.
    fn reconcile(&mut self, parent: Parent) {
        for r in 0..self.runs.len() {
            if self.runs[r].box_running && !self.runs[r].sup_alive {
                self.attach(r, parent);
            }
        }
    }

    fn step(&mut self, e: Ev) {
        let p = &self.plan;
        let (serve_reexec, adopt_after, poll, period, drain) = (p.serve_reexec, p.adopt_after, p.poll, p.period, p.drain);
        match e {
            Ev::Try(n) => {
                if self.calls[n].answered {
                    return;
                }
                let waited = self.now - self.calls[n].first;
                if self.daemon == Daemon::Up {
                    let (run, schema) = (self.calls[n].run, self.daemon_build);
                    self.calls[n].answered = true;
                    self.longest_wait = self.longest_wait.max(waited);
                    self.prompts.push(Prompt { run, schema, state: PromptState::Queued });
                    self.note(format!("call {n}: prompt for r{run} accepted, written in the {schema:?} schema, after {waited} ms"));
                    return;
                }
                if waited > CLI_BOUND_MS && !self.calls[n].late {
                    self.calls[n].late = true;
                    let state = self.daemon;
                    self.trace
                        .violate(self.now, format!("call {n}: the CLI got no answer within {CLI_BOUND_MS} ms (the daemon is {state:?})"));
                }
                self.at(self.now + RETRY_MS, Ev::Try(n));
            }
            Ev::Poll(r) => {
                let run = &self.runs[r];
                if run.sup_alive && run.box_running {
                    let old = run.sup_build == Build::Old;
                    for i in 0..self.prompts.len() {
                        if self.prompts[i].run != r || self.prompts[i].state != PromptState::Queued {
                            continue;
                        }
                        // #475: an older build's reader took a newer build's row as something else.
                        if old && self.prompts[i].schema == Build::New && !self.o.expand_safe {
                            self.prompts[i].state = PromptState::Lost;
                            self.trace.violate(
                                self.now,
                                format!("prompt {i} for r{r} was lost: an old build's supervisor dropped a new-schema prompt"),
                            );
                        } else {
                            self.prompts[i].state = PromptState::Read;
                            self.note(format!("prompt {i}: read by r{r}"));
                        }
                    }
                }
                self.at(self.now + poll, Ev::Poll(r));
            }
            Ev::UpdateStarts => {
                // The new version is made current: what every process started from now runs.
                self.build = Build::New;
                match self.plan.update {
                    Update::Install => {
                        self.note("install: wicketd restarted; its runs' supervisors and the local serve go on, on the old build");
                        self.daemon = Daemon::Starting;
                        let t = self.now + self.plan.daemon_down;
                        self.at(t, Ev::DaemonStarted);
                        self.at(t + self.plan.reconcile_restart_after, Ev::ReconcileRestart);
                    }
                    Update::SelfUpdate => {
                        self.note("self update: its handover starts");
                        if self.o.serve_first_on_update {
                            self.at(self.now + serve_reexec, Ev::ServeReexecuted(Then::Stop));
                        } else {
                            self.at(self.now, Ev::StopStale(Then::Serve));
                        }
                    }
                }
            }
            Ev::DaemonStarted => {
                self.daemon = Daemon::Up;
                self.daemon_build = Build::New;
                self.note("wicketd is up on the new build");
                if self.o.hand_over_on_start {
                    if self.o.serve_first_on_start && self.serve != self.build {
                        self.at(self.now + serve_reexec, Ev::ServeReexecuted(Then::Stop));
                    } else {
                        self.at(self.now, Ev::StopStale(Then::Adopt));
                    }
                }
            }
            Ev::ServeReexecuted(then) => {
                self.serve = self.build;
                self.note("the local serve re-executed as the new build, its boxes adopted");
                match then {
                    Then::Stop => self.at(self.now, Ev::StopStale(Then::Adopt)),
                    _ => self.at(self.now + adopt_after, Ev::Adopt),
                }
            }
            Ev::StopStale(then) => {
                self.stop_stale();
                match then {
                    Then::Serve => self.at(self.now + serve_reexec, Ev::ServeReexecuted(Then::Adopt)),
                    _ => self.at(self.now + adopt_after, Ev::Adopt),
                }
            }
            Ev::Adopt => {
                self.reconcile(Parent::Daemon);
                if self.plan.update == Update::SelfUpdate {
                    self.at(self.now, Ev::Sighup);
                }
            }
            Ev::ReconcilePass => {
                self.reconcile(Parent::Reconciler);
                self.at(self.now + period, Ev::ReconcilePass);
            }
            Ev::ReconcileRestart => {
                self.note("install: the reconciler unit restarted");
                if !self.o.reconcile_keeps_children {
                    for r in 0..self.runs.len() {
                        if self.runs[r].sup_alive && self.runs[r].sup_parent == Parent::Reconciler {
                            // A supervisor ends its box on SIGTERM.
                            self.stop_box(r, "its supervisor, a child of the reconciler unit, was SIGTERMed by the unit's restart");
                        }
                    }
                }
            }
            Ev::Sighup => {
                self.daemon = Daemon::Draining;
                self.note("wicketd: SIGHUP, draining");
                if self.o.drain_returns {
                    self.at(self.now + drain, Ev::DrainReturns);
                }
            }
            Ev::DrainReturns => {
                self.daemon = Daemon::Up;
                self.daemon_build = Build::New;
                self.note("wicketd re-executed as the new build");
            }
        }
    }
}

/// Runs the update scenario for `seed`. `_dir` is unused (no files): the other scenarios' signature.
pub fn run(seed: u64, _dir: &std::path::Path, o: Options) -> Report {
    let plan = Plan::new(seed);
    let plan_text = plan.to_string();
    let runs = vec![
        Run { node: NodeKind::Local, sup_build: Build::Old, sup_parent: Parent::Daemon, sup_alive: true, box_running: true },
        Run { node: NodeKind::Remote, sup_build: Build::Old, sup_parent: Parent::Daemon, sup_alive: true, box_running: true },
    ];
    let mut s = Sim {
        trace: Trace::new(0, o.keep_trace),
        o,
        now: 0,
        seq: 0,
        queue: BinaryHeap::new(),
        build: Build::Old,
        daemon: Daemon::Up,
        daemon_build: Build::Old,
        serve: Build::Old,
        runs,
        prompts: vec![],
        calls: vec![],
        stopped: 0,
        longest_wait: 0,
        plan,
    };
    for (n, &(t, run)) in s.plan.prompts.clone().iter().enumerate() {
        s.calls.push(Call { run, first: t, answered: false, late: false });
        s.at(t, Ev::Try(n));
    }
    for r in 0..s.runs.len() {
        let first = s.plan.poll / 2 + r as i64 * 37;
        s.at(first, Ev::Poll(r));
    }
    let (at, phase) = (s.plan.at, s.plan.phase);
    s.at(at, Ev::UpdateStarts);
    s.at(phase, Ev::ReconcilePass);
    while let Some(Reverse((t, _, e))) = s.queue.pop() {
        if t > END_MS {
            break;
        }
        s.now = t;
        s.step(e);
    }
    s.now = END_MS;
    for i in 0..s.prompts.len() {
        if s.prompts[i].state == PromptState::Queued && s.runs[s.prompts[i].run].box_running {
            let r = s.prompts[i].run;
            s.trace.violate(END_MS, format!("prompt {i} for r{r} was never read"));
        }
    }
    for n in 0..s.calls.len() {
        if !s.calls[n].answered && !s.calls[n].late && END_MS - s.calls[n].first > CLI_BOUND_MS {
            s.trace.violate(END_MS, format!("call {n}: the CLI got no answer within {CLI_BOUND_MS} ms"));
        }
    }
    let read = s.prompts.iter().filter(|p| p.state == PromptState::Read).count();
    let kept = s.runs.iter().filter(|r| r.box_running).count();
    let stats = format!(
        "{:?} at {} ms; {} of {} prompts read, {} calls, longest wait {} ms; {} of {} boxes kept",
        s.plan.update,
        s.plan.at,
        read,
        s.prompts.len(),
        s.calls.len(),
        s.longest_wait,
        kept,
        s.runs.len()
    );
    Report {
        scenario: "update",
        seed,
        plan: plan_text,
        violations: s.trace.violations.clone(),
        known: vec![],
        hash: s.trace.hash(),
        stats,
        trace: s.trace.lines().to_vec(),
    }
}

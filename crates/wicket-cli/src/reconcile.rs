//! The reconciler (#38, which includes the box half of #21): one pass makes what exists agree with the
//! ledger, and `wicket reconcile --every <interval>` runs passes for ever.
//!
//! **What it compares.**
//! - *Runs*: a run recorded as `running` whose supervising process (its owner in the ledger,
//!   `<machine>:<pid>:<start>`) is gone on this machine is asked about on its node (#151). If the node
//!   still has its box, the run is **adopted**: a new supervisor (`wicket attach <run>`) takes it over,
//!   its box untouched. If the node says the box is gone, the run is ended as `lost`; if the node
//!   can't be reached, the run is left for the next pass. A run with no node recorded (its process
//!   died before it reached one) is ended as `lost`. A run supervised on another machine is left alone: only that machine can
//!   tell. A run whose owner is alive but whose supervisor is stuck (a child's, in its parent's
//!   process, that didn't end when its parent stopped it, #409) is reported as `run_stuck` each pass
//!   and taken over once that process ends.
//! - *Leases* (`wicket_store::LeaseRow`): a pending lease whose request a human granted becomes
//!   `approved`, one denied or withdrawn ends. An approved or active lease ends when its holder run has
//!   ended or (active) when `not_after` has passed; runs placed on it are stopped first.
//! - *Machines*: the provider's instances carrying this installation's owner tag, against the approved
//!   and active leases (`wicket_placement::reconcile`, matching by each lease's idempotency tag). A node
//!   no live lease asks for is destroyed, or with `warm_pool` kept until minute 50 of its paid hour; a
//!   duplicate is destroyed; one created less than ten minutes ago that nothing records yet is left
//!   for its creator to record (`wicket node create` records its node once the provider answers,
//!   #324); a node that matches a lease the ledger has no node for (a crash between
//!   create and record) is adopted; an approved lease with no node gets one (acquire, enrol with the
//!   host key pinned at creation, `wicket node install`). Untagged instances are never listed, so never
//!   touched; protected ones are reported and left. **Ownership is checked again right before every
//!   destroy** (`Placer::release` reads the instance and refuses one without the owner tag or with
//!   `wicket-protected`), so a tag changed between list and destroy saves the machine.
//! - *Placed nodes* (`wicket_store::PlacedNodeRow`, #294): nodes `wicket node create` made, which
//!   no capacity lease asks for, are held to their own lease ([`placed_pass`]). At its end (minute 50
//!   of its last paid hour) a node no running run is placed on is released (`Placer::release`, which
//!   checks the owner tag and `wicket-protected` first) and its enrolment revoked, with an audit record
//!   saying why; one a run still holds is kept, audited once per change of holders, and flagged in
//!   `wicket node list` and the console (asking for a renewal decision is #56; until then it is a
//!   warning). A run whose files a fetch didn't bring back (`runs.uncollected`) holds its node the
//!   same way, so they aren't destroyed with it (#300, #324); so does a capacity lease's run. The machine half above leaves recorded placed nodes to this step.
//! - *Boxes*: Docker's `wicket=1` containers, here and on every active enrolled node (over its pinned
//!   ssh), by their `wicket.run` label. A box whose run has ended is stopped; a running run's box is
//!   left to its run (above). **A box whose run this ledger doesn't know is left alone**: Docker may
//!   be shared.
//!
//! - *Stores*: once an hour ([`crate::storegc::EVERY_SECS`]), the content-addressed stores'
//!   collection (#258, `wicket state gc`): the local store and the state store's, then the local
//!   store's cache cap. Audited as `store.gc` and `store.deleted`, not `reconcile.*`.
//! - *Triggers* (#578): each pass fires the schedules' minutes and the timers that came due since
//!   the last one (at most `wicket_control::triggers::CATCH_UP_SECS` back), once each: waking or
//!   messaging the agent a trigger names, or queueing the run it starts. Audited as `trigger.*`.
//!
//! **Order.** Runs, then leases, then machines, then boxes, so killing every control-plane process
//! mid-run and restarting leaves nothing behind after one pass: the lost runs end, their leases end,
//! their machines go, and their boxes stop.
//!
//! **Records.** Every change is an audit record `reconcile.<what>` (the console's activity shows them).
//! Reports of things left alone (protected, unknown, warm) are printed, not recorded.
//!
//! **One pass at a time** per installation: a pass holds an exclusive lock on
//! `<data dir>/reconcile.lock`. `wicket approve` of a capacity request runs a pass at once; run
//! `wicket reconcile --every 30s` (e.g. as a systemd user service beside `wicket serve`) for everything
//! else, including lease ends and approvals given on the console.
//!
//! **Dry run** reports what the pass would do from the current state, changing nothing; what a change
//! would set off later in the same pass (a lease approved now and created next) shows on the next pass.
//!
//! **Not yet:** the daily money reconcile against the provider's own charges (design §8.5); a lease
//! records what its node billed under the provider's billing model when it ends.

use crate::capacity::{self, lease_key, LeaseApprover, PlacementConfig};
use crate::owner::LOST;
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use wicket_core::{RunId, TenantId};
use wicket_placement::billing::PoolRules;
use wicket_placement::model::Boot;
use wicket_placement::reconcile as plan;
use wicket_placement::*;
use wicket_sandbox::{BoxInfo, Docker};
use wicket_store::{LeaseRow, Ledger};

/// Where boxes run: Docker here, or on a node.
pub trait Boxes: Send + Sync {
    fn list(&self) -> impl Future<Output = Result<Vec<BoxInfo>>> + Send;
    fn kill(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
}

impl Boxes for Docker {
    async fn list(&self) -> Result<Vec<BoxInfo>> {
        self.boxes().await
    }
    async fn kill(&self, name: &str) -> Result<()> {
        Docker::kill(self, name).await
    }
}

/// What makes an acquired node usable, per backend.
pub trait NodeSetup<P>: Send + Sync {
    /// What a new node boots with (Vultr: user data installing a host key generated here, whose public
    /// half is pinned before the node exists). None: nothing.
    fn boot(&self, name: &str) -> impl Future<Output = Result<Option<Boot>>> + Send;
    /// Waits for the node, enrols it (pinning `lease.host_key`) and installs wicket. Returns the enrolled
    /// node's name and ssh target.
    fn ready(&self, provider: &P, lease: &LeaseRow, node: &NodeHandle) -> impl Future<Output = Result<(String, String)>> + Send;
    /// After a lease's node is destroyed: revoke its enrolment, if this setup made one.
    fn retire(&self, ledger: &mut Ledger, lease: &LeaseRow) -> Result<()>;
}

/// One thing a pass did (or, in a dry run, would do).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Done {
    pub kind: &'static str,
    pub target: String,
    pub detail: String,
}

/// The machine half: a placer over the configured backend.
pub struct Machines<'a, P, S> {
    pub placer: &'a Placer<P, LeaseApprover>,
    pub approver: &'a LeaseApprover,
    pub setup: &'a S,
    pub warm_pool: bool,
}

pub struct Pass<'a, P, S, B, F> {
    pub ledger: &'a mut Ledger,
    pub machines: Option<Machines<'a, P, S>>,
    /// Docker on this machine.
    pub local: &'a B,
    /// Docker on an enrolled node, by name (None: unreachable or not set up).
    pub node_boxes: F,
    /// Whether an owner label's process is running (None: not this machine's to say).
    pub owner_alive: fn(&str) -> Option<bool>,
    /// The runs each node reported having (None: it couldn't be reached), for runs whose supervisor
    /// is gone; fetched before the pass ([`node_runs`]).
    pub node_runs: HashMap<String, Option<Vec<String>>>,
    /// Starts a new supervisor for a run (`wicket attach <run>`, detached).
    pub adopt: fn(&str) -> Result<()>,
    /// Whether a run's box may still run on its node at a time (Unix ms), and until when (#153).
    pub fenced: fn(&str, i64) -> Option<(String, i64)>,
    pub now: i64,
    pub dry_run: bool,
    done: Vec<Done>,
    /// Effective statuses after this pass's changes (what a dry run would have changed).
    runs_ended: HashSet<String>,
    leases_ended: HashSet<String>,
}

impl<'a, P, S, B, F> Pass<'a, P, S, B, F>
where
    P: Provider,
    S: NodeSetup<P>,
    B: Boxes,
    F: Fn(&str) -> Option<B> + Send + Sync,
{
    pub fn new(ledger: &'a mut Ledger, machines: Option<Machines<'a, P, S>>, local: &'a B, node_boxes: F, now: i64, dry_run: bool) -> Self {
        Pass {
            ledger,
            machines,
            local,
            node_boxes,
            owner_alive: crate::owner::owner_alive,
            node_runs: HashMap::new(),
            adopt: crate::run::spawn_attach,
            fenced: crate::noderun::fenced_until,
            now,
            dry_run,
            done: vec![],
            runs_ended: HashSet::new(),
            leases_ended: HashSet::new(),
        }
    }

    pub fn with_node_runs(mut self, m: HashMap<String, Option<Vec<String>>>) -> Self {
        self.node_runs = m;
        self
    }

    pub async fn run(mut self) -> Result<Vec<Done>> {
        self.runs()?;
        self.lease_decisions()?;
        self.lease_ends().await?;
        if self.machines.is_some() {
            self.reconcile_machines().await?;
        }
        self.boxes().await?;
        Ok(self.done)
    }

    /// Records a change: reported, and (unless a dry run) audited.
    fn did(&mut self, kind: &'static str, target: &str, detail: &str, run: Option<&str>) {
        if !self.dry_run {
            let _ = self.ledger.audit(
                &TenantId::single(),
                run.map(|r| RunId(r.to_string())).as_ref(),
                &format!("reconcile.{kind}"),
                &serde_json::json!({ "target": target, "detail": detail }),
            );
        }
        self.note(kind, target, detail);
    }

    /// Reports something left alone (not audited: it would repeat every pass).
    fn note(&mut self, kind: &'static str, target: &str, detail: &str) {
        self.done.push(Done { kind, target: target.to_string(), detail: detail.to_string() });
    }

    fn run_status(&self, run: &str) -> Result<Option<String>> {
        if self.runs_ended.contains(run) {
            return Ok(Some(LOST.into()));
        }
        Ok(self.ledger.run_status(run)?)
    }

    fn end_run(&mut self, run: &str, why: &str) -> Result<()> {
        if !self.dry_run && self.ledger.run_status(run)?.as_deref() == Some("running") {
            // Its agent too, if it was the agent's activation (#474): nothing re-attaches a lost run.
            if let Some(state) = self.ledger.run_lost(run, why)? {
                if let Some((agent, _)) = self.ledger.agent_of_run(run)? {
                    let detail = format!("its run {run} was lost: it is {state}");
                    self.did("agent_ended", &agent, &detail, Some(run));
                }
            }
        }
        self.runs_ended.insert(run.to_string());
        Ok(())
    }

    fn live_leases(&self, statuses: &[&str]) -> Result<Vec<LeaseRow>> {
        Ok(self.ledger.leases(statuses)?.into_iter().filter(|l| !self.leases_ended.contains(&l.id)).collect())
    }

    // ---- runs ----

    fn runs(&mut self) -> Result<()> {
        for (run, owner) in self.ledger.running_runs()? {
            let Some(o) = owner else { continue };
            if (self.owner_alive)(&o) != Some(false) {
                // A child's supervisor, in its parent's live process, that didn't end when its parent
                // stopped it (#409): reported each pass, and left for when that process ends.
                if let Some(at) = self.ledger.run_stuck(&run)? {
                    let detail = format!(
                        "stuck: its supervisor, in process {o}, hasn't ended since its parent asked it to stop ({}s ago); it is taken over once that process ends",
                        (self.now - at).max(0)
                    );
                    self.note("run_stuck", &run, &detail);
                }
                continue;
            }
            let Some(node) = self.ledger.run_node(&run)? else {
                self.end_run(&run, "its wicket process is gone (found by the reconciler)")?;
                self.did("run_lost", &run, "its wicket process is gone", Some(&run));
                continue;
            };
            match self.node_runs.get(&node).cloned() {
                Some(Some(list)) if list.contains(&run) => {
                    if !self.dry_run {
                        if let Err(e) = (self.adopt)(&run) {
                            self.note("error", &run, &format!("starting its new supervisor: {e:#}"));
                            continue;
                        }
                    }
                    self.did(
                        "run_adopted",
                        &run,
                        &format!("its supervisor is gone, its box still runs on node {node}: a new one takes it over"),
                        Some(&run),
                    );
                }
                Some(Some(_)) => {
                    // The node says it has no box for the run: confirmed stopped (#153).
                    if !self.dry_run {
                        if let Ok(()) = crate::run::check_run_id(&run) {
                            crate::noderun::confirm_stopped(&crate::data_dir().join("runs").join(&run));
                        }
                    }
                    let why = format!("its wicket process is gone, and node {node} has no box for it");
                    self.end_run(&run, &why)?;
                    self.did("run_lost", &run, &why, Some(&run));
                }
                _ => {
                    // Its node can't be asked: the run still ends if its node is no longer active
                    // (revoked: nothing will supervise it there again), or past its own deadline.
                    let active = self.ledger.node(&node)?.is_some_and(|n| n.status == "active");
                    let overdue = run_deadline(&run).is_some_and(|d| d < self.now);
                    // Still authorized on its node (#153): the box may be running there, so the run
                    // isn't lost yet, whatever the node's status, until its authority has ended.
                    if let Some((_, until)) = (self.fenced)(&run, self.now.saturating_mul(1000)) {
                        self.note(
                            "unreachable",
                            &run,
                            &format!(
                                "its supervisor is gone and node {node} can't be asked about it; it is still authorized there until {}: left for a later pass",
                                crate::noderun::fmt_ms(until)
                            ),
                        );
                        continue;
                    }
                    if !active || overdue {
                        let why = match active {
                            false => format!("its wicket process is gone, and node {node} is no longer active"),
                            true => format!("its wicket process is gone, node {node} can't be reached, and it is past its timeout"),
                        };
                        self.end_run(&run, &why)?;
                        self.did("run_lost", &run, &why, Some(&run));
                    } else {
                        self.note(
                            "unreachable",
                            &run,
                            &format!("its supervisor is gone and node {node} can't be asked about it: left for the next pass"),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    // ---- leases ----

    fn lease_decisions(&mut self) -> Result<()> {
        for lease in self.live_leases(&["pending"])? {
            let Some(rid) = lease.request_id.clone() else { continue };
            let Ok(r) = self.ledger.request(&rid) else { continue };
            match r.status.as_str() {
                "pending" => {}
                "granted" => {
                    // Provisioned only as it was decided on, and while its approval lasts (#369).
                    if let Some(why) = self.lease_unbound(&lease, &r)? {
                        if !self.dry_run {
                            self.ledger.lease_ended(&lease.id, "denied", &why, None)?;
                            self.ledger.audit(
                                &TenantId(lease.tenant.clone()),
                                Some(&RunId(lease.run.clone())),
                                "effect.refused",
                                &serde_json::json!({ "lease": lease.id, "request": rid, "why": why }),
                            )?;
                        }
                        self.leases_ended.insert(lease.id.clone());
                        self.did("lease_closed", &lease.id, &why, Some(&lease.run));
                        continue;
                    }
                    if !self.dry_run {
                        self.ledger.lease_transition(&lease.id, &["pending"], "approved", &format!("request {rid} granted"))?;
                    }
                    self.did("lease_approved", &lease.id, &format!("request {rid} granted by an operator"), Some(&lease.run));
                }
                s => {
                    let status = if s == "denied" { "denied" } else { "withdrawn" };
                    if !self.dry_run {
                        self.ledger.lease_ended(&lease.id, status, &format!("request {rid} {s}"), None)?;
                    }
                    self.leases_ended.insert(lease.id.clone());
                    self.did("lease_closed", &lease.id, &format!("request {rid} {s}"), Some(&lease.run));
                }
            }
        }
        Ok(())
    }

    /// Why a granted lease may not be provisioned, if it may not (#369): its approval has ended, or
    /// the lease is no longer what was approved. A request filed before approvals were bound to
    /// their effect carries no arguments, and is provisioned as before.
    fn lease_unbound(&self, lease: &wicket_store::LeaseRow, r: &wicket_store::Request) -> Result<Option<String>> {
        let Some(asked) = r.args_sha256.as_deref() else { return Ok(None) };
        let Some(g) = self.ledger.grant_for_request(&r.id)? else {
            return Ok(Some(format!("request {} has no live grant", r.id)));
        };
        if g.expires_at <= wicket_store::now() {
            return Ok(Some(format!("its approval ({}) ended before it was provisioned", g.id)));
        }
        let granted = self.ledger.grant_effect(&g.id)?.and_then(|(_, a)| a);
        let now = crate::capacity::lease_args(lease);
        if granted.as_deref() != Some(asked) || now != asked {
            return Ok(Some(format!("the lease is not what its approval ({}) was for: it changed after it was decided", g.id)));
        }
        Ok(None)
    }

    async fn lease_ends(&mut self) -> Result<()> {
        for lease in self.live_leases(&["approved", "active"])? {
            let holder = self.run_status(&lease.run)?;
            let uncollected = match lease.node_name.as_deref() {
                Some(n) => self.ledger.uncollected_runs_on_node(n)?.contains(&lease.run),
                None => false,
            };
            let why = if holder.as_deref() != Some("running") && uncollected {
                // Its node keeps files of its run a fetch didn't bring back (#300, #324): ending
                // the lease would destroy them with the node.
                self.note(
                    "lease_held",
                    &lease.id,
                    &format!("its run {} has ended, but its node keeps files a fetch didn't bring back", lease.run),
                );
                None
            } else if holder.as_deref() != Some("running") {
                Some(format!("its run {} has ended ({})", lease.run, holder.as_deref().unwrap_or("unknown")))
            } else if lease.status == "active" && lease.not_after.is_some_and(|t| t <= self.now) {
                Some("its lease end has passed".to_string())
            } else {
                None
            };
            if let Some(why) = why {
                self.end_lease(&lease, "ended", &why).await?;
            }
        }
        Ok(())
    }

    /// Ends a lease: the runs placed on it are stopped, and what its node billed is recorded. Its node
    /// is destroyed by the machine half (nothing desires it any more).
    async fn end_lease(&mut self, lease: &LeaseRow, status: &str, why: &str) -> Result<()> {
        let placed: Vec<String> = self
            .ledger
            .runs_on_lease(&lease.id)?
            .into_iter()
            .filter(|(r, s)| s == "running" || self.runs_ended.contains(r))
            .map(|(r, _)| r)
            .collect();
        if !placed.is_empty() {
            let boxes = match lease.node_name.as_deref().and_then(|n| (self.node_boxes)(n)) {
                Some(b) => b.list().await.unwrap_or_default(),
                None => vec![],
            };
            for run in placed {
                for b in boxes.iter().filter(|b| b.run.as_deref() == Some(run.as_str())) {
                    self.stop_box(lease.node_name.as_deref(), b, "its capacity lease ended").await?;
                }
                if !self.runs_ended.contains(&run) {
                    self.end_run(&run, &format!("its capacity lease {} ended: {why}", lease.id))?;
                    self.did("run_stopped", &run, &format!("placed on lease {}, which ended", lease.id), Some(&run));
                }
            }
        }
        let mut billed = None;
        if let (Some(m), Some(id)) = (&self.machines, &lease.node_id) {
            if let Ok(Some(n)) = m.placer.get(&NodeId(id.clone())).await {
                billed = Some(n.billed_through(self.now).0 as i64);
            }
        }
        if !self.dry_run {
            self.ledger.lease_ended(&lease.id, status, why, billed)?;
        }
        self.leases_ended.insert(lease.id.clone());
        let detail = match billed {
            Some(b) => format!("{why}; billed {}", MicroUsd(b as u64)),
            None => why.to_string(),
        };
        self.did(if status == "ended" { "lease_ended" } else { "lease_failed" }, &lease.id, &detail, Some(&lease.run));
        Ok(())
    }

    // ---- machines ----

    async fn reconcile_machines(&mut self) -> Result<()> {
        let (owner, warm, observed) = {
            let m = self.machines.as_ref().expect("machines");
            (m.placer.owner().clone(), m.warm_pool, m.placer.list().await.context("listing the provider's owned nodes")?)
        };
        // Nodes `wicket node create` made are held to their own lease ([`placed_pass`]), not destroyed
        // for having no capacity lease.
        let placed: HashSet<String> = self.ledger.placed_nodes(&[])?.into_iter().map(|p| p.id).collect();
        let observed: Vec<NodeHandle> = observed.into_iter().filter(|n| !placed.contains(&n.id.0)).collect();
        let leases = self.live_leases(&["approved", "active"])?;
        let desired: Vec<plan::Desired> = leases
            .iter()
            .map(|l| plan::Desired {
                idempotency_key: lease_key(&l.id),
                lease_until: l.not_after.unwrap_or(self.now + l.duration_secs.max(1)),
                pinned: false,
            })
            .collect();
        let by_key: HashMap<String, LeaseRow> = leases.into_iter().map(|l| (lease_key(&l.id), l)).collect();
        // Every lease's idempotency tag, ended ones too: a node with none of them is one nothing records.
        let recorded: HashSet<String> = self.ledger.leases(&[])?.iter().map(|l| owner.idem_tag(&lease_key(&l.id))).collect();
        let now = self.now;
        let young = |id: &NodeId| {
            observed
                .iter()
                .find(|n| &n.id == id)
                .filter(|n| Owner::idem_tag_of(n).is_none_or(|t| !recorded.contains(t)))
                .and_then(|n| plan::too_new_to_judge(n, now))
        };
        // Destroys first, so the envelope sees room before anything is created.
        let mut actions = plan::reconcile(&owner, &desired, &observed, self.now, warm, &PoolRules::default());
        actions.sort_by_key(|a| !matches!(a, plan::Action::Destroy { .. }));
        for a in actions {
            match a {
                plan::Action::Ignore { node, reason } => self.note("ignored", &node.0, &format!("{reason:?}: never touched")),
                plan::Action::Pool { node, until } => self.note(
                    "kept_warm",
                    &node.0,
                    &format!("no lease; paid until {}, destroyed then", wicket_core::time::unix_rfc3339(until)),
                ),
                plan::Action::Destroy { node, reason: plan::DestroyReason::NoLease } if young(&node).is_some() => {
                    // Nothing records it, and it is new: its creator (`wicket node create`) may not
                    // have recorded it yet (#324).
                    let until = young(&node).unwrap_or(self.now);
                    self.note(
                        "young",
                        &node.0,
                        &format!(
                            "nothing records it, and it was just created: left for its creator until {}",
                            wicket_core::time::unix_rfc3339(until)
                        ),
                    )
                }
                plan::Action::Destroy { node, reason } => self.destroy(&node, &format!("{reason:?}")).await?,
                plan::Action::Keep { node, idempotency_key } => {
                    let Some(lease) = by_key.get(&idempotency_key).cloned() else { continue };
                    let n = observed.iter().find(|n| n.id == node).cloned().expect("observed");
                    if lease.node_id.as_deref() != Some(node.0.as_str()) {
                        if !self.dry_run {
                            self.ledger.set_lease_node(&lease.id, &node.0, n.ssh_target.as_deref(), n.lease_until)?;
                        }
                        self.did("adopted", &node.0, &format!("matches lease {} (recorded after a crash)", lease.id), Some(&lease.run));
                    }
                    if lease.status == "approved" {
                        self.make_ready(&lease.id, n).await?;
                    }
                }
                plan::Action::Create { idempotency_key } => {
                    let Some(lease) = by_key.get(&idempotency_key).cloned() else { continue };
                    if lease.node_id.is_some() {
                        self.end_lease(&lease, "failed", "its node is gone").await?;
                    } else {
                        self.provision(&lease).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn destroy(&mut self, node: &NodeId, reason: &str) -> Result<()> {
        let lease = self.ledger.leases(&[])?.into_iter().find(|l| l.node_id.as_deref() == Some(node.0.as_str()));
        if self.dry_run {
            self.note("destroy", &node.0, &format!("would destroy ({reason})"));
            return Ok(());
        }
        let r = self.machines.as_ref().expect("machines").placer.release(node, ReleaseMode::Now).await;
        match r {
            Ok(r) => {
                if let Some(l) = &lease {
                    self.machines.as_ref().expect("machines").setup.retire(self.ledger, l)?;
                }
                self.did("destroyed", &node.0, &format!("{reason} ({r:?})"), lease.as_ref().map(|l| l.run.as_str()));
            }
            Err(e @ (PlacementError::NotOwned(_) | PlacementError::Protected(_))) => {
                self.did("refused", &node.0, &format!("left alone: {e} (its tags changed since it was listed)"), None)
            }
            Err(e) => self.did("error", &node.0, &format!("destroy failed: {e}"), None),
        }
        Ok(())
    }

    /// Creates the node for an approved lease.
    async fn provision(&mut self, lease: &LeaseRow) -> Result<()> {
        let key = lease_key(&lease.id);
        if self.dry_run {
            self.note("create", &key, &format!("would acquire a node for lease {}", lease.id));
            return Ok(());
        }
        let name = capacity::node_name(lease);
        let boot = self.machines.as_ref().expect("machines").setup.boot(&name).await;
        let boot = match boot {
            Ok(b) => b,
            Err(e) => return self.end_lease(lease, "failed", &format!("preparing its boot: {e:#}")).await,
        };
        // Pinned before the node exists: a retried pass pins the key the node really booted with.
        if let Some(b) = &boot {
            self.ledger.set_lease_host_key(&lease.id, &b.host_key)?;
        }
        let req = capacity::request_for(lease, boot)?;
        let r = {
            let m = self.machines.as_ref().expect("machines");
            m.approver.allow(&name, MicroUsd(lease.reserved.max(0) as u64));
            let r = m.placer.acquire(&req).await;
            m.approver.clear();
            r
        };
        let n = match r {
            Ok(n) => n,
            Err(e) => return self.end_lease(lease, "failed", &format!("acquiring its node: {e}")).await,
        };
        self.ledger.set_lease_node(&lease.id, &n.id.0, n.ssh_target.as_deref(), n.lease_until)?;
        self.did(
            "created",
            &n.id.0,
            &format!(
                "for lease {} ({}, {}/h, until {})",
                lease.id,
                n.plan.as_deref().unwrap_or("?"),
                n.billing.hourly_rate(),
                n.lease_until.map(wicket_core::time::unix_rfc3339).unwrap_or_default()
            ),
            Some(&lease.run),
        );
        self.make_ready(&lease.id, n).await
    }

    /// Enrols and installs an approved lease's node, and activates the lease. On failure the lease
    /// fails and the node is destroyed at once.
    async fn make_ready(&mut self, lease_id: &str, n: NodeHandle) -> Result<()> {
        if self.dry_run {
            self.note("set_up", &n.id.0, &format!("would enrol and install it for lease {lease_id}"));
            return Ok(());
        }
        let lease = self.ledger.lease(lease_id)?.context("lease")?;
        let r = {
            let m = self.machines.as_ref().expect("machines");
            m.setup.ready(m.placer.provider(), &lease, &n).await
        };
        match r {
            Ok((name, target)) => {
                let until = n.lease_until.or(lease.not_after).unwrap_or(self.now + lease.duration_secs);
                self.ledger.lease_activated(&lease.id, &name, &target, until)?;
                self.did(
                    "lease_active",
                    &lease.id,
                    &format!("node {name} ({target}) until {}", wicket_core::time::unix_rfc3339(until)),
                    Some(&lease.run),
                );
            }
            Err(e) => {
                self.end_lease(&lease, "failed", &format!("setting up its node: {e:#}")).await?;
                self.destroy(&n.id, "its lease failed").await?;
            }
        }
        Ok(())
    }

    // ---- boxes ----

    async fn boxes(&mut self) -> Result<()> {
        let local = match self.local.list().await {
            Ok(v) => v,
            Err(e) => {
                self.note("unreachable", "docker", &format!("{e:#}"));
                vec![]
            }
        };
        for b in local {
            self.judge_box(None, &b).await?;
        }
        for row in self.ledger.nodes()?.into_iter().filter(|n| n.status == "active") {
            let Some(d) = (self.node_boxes)(&row.name) else { continue };
            match d.list().await {
                Ok(v) => {
                    for b in v {
                        self.judge_box(Some(&row.name), &b).await?;
                    }
                }
                Err(e) => self.note("unreachable", &row.name, &format!("{e:#}")),
            }
        }
        Ok(())
    }

    async fn judge_box(&mut self, node: Option<&str>, b: &BoxInfo) -> Result<()> {
        let Some(run) = b.run.as_deref() else { return Ok(()) };
        let status = self.run_status(run)?;
        let why = match status.as_deref() {
            None => {
                self.note("left_alone", &b.name, "its run is not in this ledger");
                return Ok(());
            }
            // Its run decides (adopted, or ended above).
            Some("running") => return Ok(()),
            Some(s) => format!("its run has ended ({s})"),
        };
        self.stop_box(node, b, &why).await
    }

    async fn stop_box(&mut self, node: Option<&str>, b: &BoxInfo, why: &str) -> Result<()> {
        let at = node.map(|n| format!(" on {n}")).unwrap_or_default();
        if !self.dry_run {
            let r = match node {
                None => self.local.kill(&b.name).await,
                Some(n) => match (self.node_boxes)(n) {
                    Some(d) => d.kill(&b.name).await,
                    None => Err(anyhow::anyhow!("node {n} is unreachable")),
                },
            };
            if let Err(e) = r {
                self.note("error", &b.name, &format!("stopping it{at}: {e:#}"));
                return Ok(());
            }
        }
        self.did("box_stopped", &b.name, &format!("{why}{at}"), b.run.as_deref());
        Ok(())
    }
}

// ---- placed nodes (#294) ----

/// The placed nodes' half of a pass: every active node `wicket node create` recorded under
/// `placer`'s owner and backend whose lease has ended is released if no running run is placed on it,
/// and otherwise kept and flagged. `retire` runs after a release (revoking its enrolment).
pub async fn placed_pass<Q: Provider, A: SpendApprover>(
    ledger: &mut Ledger,
    placer: &Placer<Q, A>,
    retire: fn(&mut Ledger, &NodeHandle) -> Result<bool>,
    now: i64,
    dry_run: bool,
) -> Result<Vec<Done>> {
    let mut done = vec![];
    let rows = ledger.placed_nodes(&["active"])?;
    for row in rows.into_iter().filter(|r| Owner::new(&r.owner) == *placer.owner() && r.backend == placer.provider().id()) {
        // Its money stays reserved while it bills (#256): renewed a day at a time, until it ends.
        if !dry_run {
            let _ = ledger.renew_money(&wicket_store::money::node_money_key(&row.name), wicket_store::now() + 24 * 3600);
        }
        if row.lease_until > now {
            continue;
        }
        let ended = wicket_core::time::unix_rfc3339(row.lease_until);
        let mut record = |ledger: &mut Ledger, kind: &'static str, detail: String, audit: bool| {
            if audit && !dry_run {
                let _ = ledger.audit(
                    &TenantId::single(),
                    None,
                    &format!("reconcile.{kind}"),
                    &serde_json::json!({ "target": row.id, "name": row.name, "lease_until": row.lease_until, "detail": detail }),
                );
            }
            done.push(Done { kind, target: row.id.clone(), detail });
        };
        // A per-node service's instance (#579) never holds a node by itself: it serves the boxes
        // there, and stops when they are gone.
        let instances: Vec<String> = ledger.live_service_instances()?.into_iter().map(|i| i.run).collect();
        let running: Vec<String> = ledger.running_runs_on_node(&row.name)?.into_iter().filter(|r| !instances.contains(r)).collect();
        // A run whose files a fetch didn't bring back holds the node too (#300, #324): releasing
        // it would destroy them.
        let uncollected: Vec<String> = ledger.uncollected_runs_on_node(&row.name)?.into_iter().filter(|r| !running.contains(r)).collect();
        if !running.is_empty() || !uncollected.is_empty() {
            let runs = running.iter().chain(&uncollected).cloned().collect::<Vec<_>>().join(",");
            let mut why = vec![];
            if !running.is_empty() {
                why.push(format!("run {} still runs on it", running.join(",")));
            }
            if !uncollected.is_empty() {
                why.push(format!("it keeps the files of run {} that a fetch didn't bring back", uncollected.join(",")));
            }
            let detail = format!(
                "placed node {} is past its lease (ended {ended}) but {}: kept, and billing until it is released (wicket node release {})",
                row.name,
                why.join(", and "),
                row.id
            );
            let changed = if dry_run { false } else { ledger.set_placed_node_held(&row.id, Some(&runs))? };
            // Past its lease it bills hours its worst case didn't reserve (#494, #495): reserved
            // now, through the next hour, so the next node's spend check counts them.
            if let (false, Some(hourly)) = (dry_run, row.hourly) {
                let held =
                    wicket_placement::billing::held_reservation(wicket_placement::MicroUsd(hourly.max(0) as u64), row.created_at, now);
                ledger.raise_money(&wicket_store::money::node_money_key(&row.name), held.0 as i64)?;
            }
            record(ledger, "placed_held", detail, changed);
            continue;
        }
        let why = format!("its lease ended at {ended} and no run is placed on it");
        if dry_run {
            record(ledger, "release", format!("would release placed node {} ({why})", row.name), false);
            continue;
        }
        let node = match placer.get(&NodeId(row.id.clone())).await {
            Ok(n) => n,
            Err(e) => {
                record(ledger, "error", format!("reading placed node {}: {e}", row.name), false);
                continue;
            }
        };
        // Drained first (#579): the per-node service instances on it, which hold no node by
        // themselves, are stopped, audited, before the node goes with their volumes.
        for i in ledger.live_service_instances()?.into_iter().filter(|i| i.node == row.name) {
            let why = format!("its node {} is being released", row.name);
            match wicket_control::services::stop(ledger, &i, &why) {
                Ok(()) => record(ledger, "service_stopped", format!("service {} instance {}: {why}", i.service, i.run), true),
                Err(e) => record(ledger, "error", format!("stopping service {} instance {}: {e:#}", i.service, i.run), false),
            }
        }
        match placer.release(&NodeId(row.id.clone()), ReleaseMode::Now).await {
            Ok(r) => {
                let gone = r == Released::AlreadyGone || node.is_none();
                ledger.placed_node_ended(&row.id, "released", &why)?;
                let mut detail = match gone {
                    true => format!("placed node {}: {why}; it was already gone", row.name),
                    false => format!("placed node {}: {why}; released ({r:?})", row.name),
                };
                if let Some(n) = &node {
                    if !gone {
                        detail.push_str(&format!(", billed {}", n.billed_through(now)));
                    }
                    match retire(ledger, n) {
                        Ok(true) => detail.push_str(&format!("; its enrolment as node {} is revoked", n.name)),
                        Ok(false) => {}
                        Err(e) => detail.push_str(&format!("; revoking its enrolment failed: {e:#}")),
                    }
                }
                record(ledger, "placed_released", detail, true);
            }
            Err(e @ (PlacementError::NotOwned(_) | PlacementError::Protected(_))) => {
                ledger.placed_node_ended(&row.id, "left", &e.to_string())?;
                record(ledger, "refused", format!("placed node {} is past its lease but left alone: {e}", row.name), true);
            }
            Err(e) => record(ledger, "error", format!("releasing placed node {}: {e}", row.name), false),
        }
    }
    Ok(done)
}

/// [`placed_pass`] for every owner and API key placed nodes were recorded under (Vultr: the only
/// backend `wicket node create` has).
async fn placed_nodes(ledger: &mut Ledger, now: i64, dry_run: bool) -> Result<Vec<Done>> {
    let mut groups: Vec<(String, String)> = ledger
        .placed_nodes(&["active"])?
        .into_iter()
        .filter(|r| r.backend == "vultr" && r.lease_until <= now)
        .map(|r| (r.owner, r.api_key_secret))
        .collect();
    groups.sort();
    groups.dedup();
    let mut done = vec![];
    for (owner, secret) in groups {
        match crate::nodecreate::release_placer(&owner, &secret) {
            Ok(p) => done.extend(placed_pass(ledger, &p, crate::nodecreate::retire_enrolment, now, dry_run).await?),
            Err(e) => done.push(Done {
                kind: "error",
                target: format!("placed nodes of {owner}"),
                detail: format!("can't reach their provider with the key in secret {secret}: {e:#}"),
            }),
        }
    }
    Ok(done)
}

// ---- the command ----

/// Holds `<data dir>/reconcile.lock` while alive.
pub struct Lock(#[allow(dead_code)] std::fs::File);

impl Lock {
    pub fn take() -> Result<Lock> {
        use std::os::fd::AsRawFd;
        let p = crate::data_dir().join("reconcile.lock");
        std::fs::create_dir_all(crate::data_dir())?;
        let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&p)?;
        // SAFETY: flock on a file descriptor this function owns.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("locking reconcile.lock");
        }
        Ok(Lock(f))
    }
}

/// Docker on an enrolled node, over its pinned ssh.
fn node_docker(name: &str) -> Option<Docker> {
    // This host's own node runs its boxes on the Docker the pass already lists.
    if name == crate::localnode::NAME {
        return None;
    }
    crate::enrol::resolve_installed(name, None).ok().filter(|n| n.name.is_some()).map(|n| Docker::over_ssh(n.ssh_prefix()))
}

/// When a run's box must have stopped (Unix seconds), from the run's record (none for a run without
/// one): its box's start plus its zone's timeout, after which its node also holds no authority for it
/// (#153: block 0 never outlasts the timeout), plus [`FENCE_MARGIN_SECS`]. A run on a node that can't
/// be asked is ended only after this, so nothing replaces a box its node may still be running.
fn run_deadline(run: &str) -> Option<i64> {
    crate::run::check_run_id(run).ok()?;
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(crate::data_dir().join("runs").join(run).join("ctl/run.json")).ok()?).ok()?;
    let m = wicket_agent::load(v["manifest"].as_str()?).ok()?;
    Some(v["started_ms"].as_i64()? / 1000 + m.zone.limits.timeout().ok()?.as_secs() as i64 + FENCE_MARGIN_SECS)
}

/// Past a run's timeout, how long before its node is certainly done with it: a long-lived agent's
/// node backstop (120 s) and clock skew between the hosts.
const FENCE_MARGIN_SECS: i64 = 180;

/// For each node of a running run whose supervisor is gone: the runs it has (exited or not), or
/// None if it can't be reached within 10 s. Unless `dry_run`, this host's own node is started first
/// if it isn't serving (it adopts its boxes as it starts).
pub async fn node_runs(ledger: &Ledger, dry_run: bool) -> Result<HashMap<String, Option<Vec<String>>>> {
    let mut nodes: HashSet<String> = HashSet::new();
    for (run, owner) in ledger.running_runs()? {
        if owner.as_deref().map(crate::owner::owner_alive) == Some(Some(false)) {
            if let Some(n) = ledger.run_node(&run)? {
                nodes.insert(n);
            }
        }
    }
    let shared = std::sync::Arc::new(std::sync::Mutex::new(Ledger::open(&crate::ledger_path())?));
    let mut out = HashMap::new();
    for n in nodes {
        if n == crate::localnode::NAME && !dry_run {
            // This host's own node: started if it isn't serving (it adopts its boxes as it starts).
            if let Err(e) = crate::localnode::ensure(&shared).await {
                say_err!("[wicket] this host's own node did not start: {e:#}");
            }
        }
        let scope = format!("reconcile:{}", std::process::id());
        let r = tokio::time::timeout(std::time::Duration::from_secs(10), crate::nodecall::Link::connect(&n, &scope, &shared)).await;
        let runs = match r {
            Ok(Ok(l)) => Some(l.runs.iter().map(|r| r.run.clone()).collect()),
            _ => None,
        };
        out.insert(n, runs);
    }
    Ok(out)
}

/// One pass with this installation's ledger, Docker, nodes and placement configuration.
pub async fn pass(dry_run: bool) -> Result<Vec<Done>> {
    let _lock = Lock::take()?;
    let mut ledger = Ledger::open(&crate::ledger_path())?;
    let now = wicket_store::now();
    // Triggers (#578) first: the schedules' minutes and the timers that came due since the last
    // pass, whatever the nodes and machines below make of this one.
    let mut done = triggers_pass(&ledger, now, dry_run, &wicket_control::hibernate::trigger_wake, &trigger_owner_may);
    let asked = node_runs(&ledger, dry_run).await?;
    let local = Docker::from_env();
    done.extend(machines_pass(&mut ledger, asked, &local, now, dry_run).await?);
    done.extend(placed_nodes(&mut ledger, now, dry_run).await?);
    // The CI principals' standing grants (#258): renewed while their release key is trusted,
    // revoked once it isn't.
    if !dry_run {
        match crate::update::renew_signers(&ledger) {
            Ok(changes) => done.extend(changes.into_iter().map(|(kind, key, detail)| Done { kind, target: key, detail })),
            Err(e) => done.push(Done { kind: "error", target: "release keys".into(), detail: format!("renewing their grants: {e:#}") }),
        }
    }
    // Per-node services (#579): an instance on each node whose boxes use one, started if missing.
    match wicket_control::services::pass(&ledger, dry_run) {
        Ok(p) => {
            done.extend(p.started.into_iter().map(|(s, run)| Done {
                kind: "service_started",
                target: format!("{} on {}", s.service, s.node),
                detail: if dry_run { format!("for {} (dry run)", s.tenant) } else { format!("for {}: run {run}", s.tenant) },
            }));
            done.extend(p.stopped.into_iter().map(|(run, why)| Done { kind: "service_stopped", target: run, detail: why }));
            done.extend(p.failed.into_iter().map(|(s, e)| Done {
                kind: "error",
                target: format!("service {} on {}", s.service, s.node),
                detail: e,
            }));
        }
        Err(e) => done.push(Done { kind: "error", target: "services".into(), detail: format!("{e:#}") }),
    }
    // Audit retention on the host (#582): over its size limit, the audit table's oldest records
    // (ones every sink has, behind a checkpoint one acknowledged) are pruned and the space given
    // back. Never without a sink and the state store.
    match crate::statesync::audit_retention(&ledger, !dry_run) {
        Ok(r) if r.pruned > 0 || r.waiting.is_some() => done.push(Done {
            kind: if r.pruned > 0 { "audit_pruned" } else { "audit_retention" },
            target: "ledger".into(),
            detail: wicket_home::audit_export::retention_line(&r),
        }),
        Ok(_) => {}
        Err(e) => done.push(Done { kind: "error", target: "audit retention".into(), detail: format!("{e:#}") }),
    }
    // The ledger's own upkeep (#582): settled rows of runs long ended to the archive, planner
    // statistics, and a WAL checkpoint.
    if !dry_run {
        match ledger.maintain(now) {
            Ok(m) if m.archived_grants + m.archived_requests > 0 => done.push(Done {
                kind: "archived",
                target: "ledger".into(),
                detail: format!(
                    "{} grant(s) and {} request(s) of runs ended over {} days ago",
                    m.archived_grants,
                    m.archived_requests,
                    wicket_store::ARCHIVE_AFTER_SECS / 86400
                ),
            }),
            Ok(_) => {}
            Err(e) => done.push(Done { kind: "error", target: "ledger".into(), detail: format!("maintaining it: {e:#}") }),
        }
    }
    if !dry_run && crate::storegc::due() {
        // The store clients block: off the async runtime.
        let passes = tokio::task::spawn_blocking(|| crate::storegc::run(&Ledger::open(&crate::ledger_path())?, false)).await?;
        match passes {
            Ok(ps) => {
                done.extend(ps.iter().map(|p| Done { kind: "store_gc", target: p.store.into(), detail: crate::storegc::summary(p, false) }))
            }
            Err(e) => done.push(Done { kind: "store_gc", target: "stores".into(), detail: format!("failed: {e:#}") }),
        }
    }
    Ok(done)
}

/// The triggers' scheduler pass ([`wicket_control::triggers::pass`]), as the pass's report: one
/// line per firing, skip or failure (each already audited as `trigger.*`), and per due one in a
/// dry run.
fn triggers_pass(
    ledger: &Ledger,
    now: i64,
    dry_run: bool,
    wake: wicket_control::triggers::Waker<'_>,
    owner: wicket_control::triggers::OwnerCheck<'_>,
) -> Vec<Done> {
    match wicket_control::triggers::pass(ledger, now, dry_run, wake, owner) {
        Ok(fired) => fired
            .into_iter()
            .map(|f| Done {
                kind: match f.status.as_str() {
                    "started" => "trigger_fired",
                    "queued" => "trigger_queued",
                    "skipped" => "trigger_skipped",
                    "due" => "trigger_due",
                    "paused" => "trigger_paused",
                    _ => "trigger_failed",
                },
                target: format!("trigger {} ({})", f.name, f.trigger),
                detail: f.detail,
            })
            .collect(),
        Err(e) => vec![Done { kind: "error", target: "triggers".into(), detail: format!("{e:#}") }],
    }
}

/// Whether a trigger's owner may still have it fire (#578): `operators.yaml`
/// ([`wicket_control::triggers::operator_may`]) and, on a host where wicketd decides who may do
/// what, wicketd's policy as it stands now: the run class that keeping one needed, for the unix
/// user the owner is. A user removed from the host, or from the policy's groups, is a definite no
/// (the trigger is paused). A lookup that fails (the user database doesn't answer, a policy file
/// doesn't read) is `Unknown`: that firing is skipped, and the trigger kept. Root and wicket's own
/// user keep theirs, as wicketd lets them do anything.
fn trigger_owner_may(t: &wicket_store::Trigger) -> std::result::Result<(), wicket_control::triggers::NotOwner> {
    use crate::daemon::policy;
    use wicket_control::triggers::NotOwner;
    wicket_control::triggers::operator_may(t)?;
    let installed = std::path::Path::new(policy::POLICY_PATH).exists() || std::path::Path::new(crate::daemon::SOCKET_PATH).exists();
    if !installed {
        // Development mode: one user, who owns wicket's data and every trigger in it.
        return Ok(());
    }
    let Some(wicket_identity::Principal::Operator { via, name, .. }) = wicket_identity::Principal::parse(&t.owner) else {
        return Err(NotOwner::No(format!("{} is not an operator's principal", t.owner)));
    };
    if via != "unix" {
        return Err(NotOwner::No(format!("{} isn't a unix user, whom wicketd's policy names", t.owner)));
    }
    let peer = crate::daemon::proto::user_as_peer(&name)
        .map_err(NotOwner::Unknown)?
        .ok_or_else(|| NotOwner::No(format!("there is no user {name} on this host")))?;
    let rules = policy::Policy::load(std::path::Path::new(policy::POLICY_PATH)).map_err(|e| NotOwner::Unknown(format!("{e:#}")))?;
    // SAFETY: a plain getter.
    let me = unsafe { libc::geteuid() };
    policy::authorize(&peer, policy::Class::Run, &rules, me).map(|_| ()).map_err(NotOwner::No)
}

/// Runs, leases, the capacity leases' machines (with placement.yaml) and boxes.
async fn machines_pass(
    ledger: &mut Ledger,
    asked: HashMap<String, Option<Vec<String>>>,
    local: &Docker,
    now: i64,
    dry_run: bool,
) -> Result<Vec<Done>> {
    let Some(cfg) = PlacementConfig::load()? else {
        let none: Option<Machines<'_, static_hosts::StaticHosts, setup::Static>> = None;
        return Pass::new(ledger, none, local, node_docker, now, dry_run).with_node_runs(asked).run().await;
    };
    let approver = LeaseApprover::default();
    match cfg.backend {
        capacity::Backend::Static => {
            let provider = static_hosts::StaticHosts::persistent(cfg.static_hosts.clone(), crate::data_dir().join("placement-static.json"));
            let placer = Placer::new(provider, approver.clone(), cfg.owner());
            let s = setup::Static { install: cfg.install_static };
            let m = Machines { placer: &placer, approver: &approver, setup: &s, warm_pool: cfg.warm_pool };
            Pass::new(ledger, Some(m), local, node_docker, now, dry_run).with_node_runs(asked.clone()).run().await
        }
        capacity::Backend::Vultr => {
            let v = cfg.vultr.clone().context("vultr settings")?;
            let provider = setup::vultr_provider(&v)?;
            let placer = Placer::new(provider, approver.clone(), cfg.owner());
            let s = setup::Vultr { ssh_key: v.ssh_key.clone(), hosts: cfg.node_hosts.clone(), wait: v.ready_wait()? };
            let m = Machines { placer: &placer, approver: &approver, setup: &s, warm_pool: cfg.warm_pool };
            Pass::new(ledger, Some(m), local, node_docker, now, dry_run).with_node_runs(asked.clone()).run().await
        }
    }
}

pub fn print(done: &[Done], dry_run: bool) {
    for d in done {
        say!("{:<15} {}  {}", d.kind, d.target, d.detail);
    }
    let changed = done
        .iter()
        .filter(|d| {
            !matches!(d.kind, "ignored" | "kept_warm" | "left_alone" | "unreachable" | "placed_held" | "store_gc" | "audit_retention")
        })
        .count();
    say!("reconcile: {changed} change(s){}", if dry_run { " (dry run: nothing changed)" } else { "" });
}

/// `wicket reconcile [--dry-run] [--every <interval>]`.
pub async fn command(dry_run: bool, every: Option<std::time::Duration>) -> Result<()> {
    if every.is_some() {
        // `wicket self update` moves the reconciler service to the new build with SIGHUP.
        crate::update::reexec_on_hangup(crate::update::pidfile("reconcile"), crate::update::Versions::control().root, || {});
    }
    // #258: not while an agent's head is a version-1 bundle, which this build can't read.
    crate::hibernate::refuse_v1_heads(&Ledger::open(&crate::ledger_path())?)?;
    loop {
        match pass(dry_run).await {
            Ok(d) => print(&d, dry_run),
            Err(e) if every.is_some() => say_err!("reconcile pass failed: {e:#}"),
            Err(e) => return Err(e),
        }
        match every {
            Some(t) => tokio::time::sleep(t).await,
            None => return Ok(()),
        }
    }
}

/// The node setups for each backend.
pub mod setup {
    use super::*;
    use crate::capacity::VultrSettings;
    use std::path::PathBuf;
    use wicket_placement::vultr::{ApiKey, Client, VultrConfig, VultrProvider};

    /// The operator's own machines: each is already an enrolled node of the same name.
    pub struct Static {
        pub install: bool,
    }

    impl NodeSetup<static_hosts::StaticHosts> for Static {
        async fn boot(&self, _name: &str) -> Result<Option<Boot>> {
            Ok(None)
        }
        async fn ready(&self, _p: &static_hosts::StaticHosts, _lease: &LeaseRow, node: &NodeHandle) -> Result<(String, String)> {
            let row = Ledger::open(&crate::ledger_path())?
                .node(&node.name)?
                .filter(|r| r.status == "active")
                .with_context(|| format!("static host {} is not an enrolled node: enrol it (wicket node enrol) first", node.name))?;
            if self.install {
                crate::update::install(&row.name, None, false).await?;
            }
            Ok((row.name, row.target))
        }
        fn retire(&self, _ledger: &mut Ledger, _lease: &LeaseRow) -> Result<()> {
            Ok(()) // the operator's machine stays enrolled
        }
    }

    pub fn vultr_provider(v: &VultrSettings) -> Result<VultrProvider> {
        let key = wicket_proxy::vault::Vault::new(wicket_proxy::vault::Vault::default_dir()).get(&v.api_key_secret)?;
        let client = match &v.api_base {
            Some(b) => Client::with_base(b, ApiKey::new(key))?,
            None => Client::new(ApiKey::new(key))?,
        };
        let d = VultrConfig::default();
        Ok(VultrProvider::new(
            client,
            VultrConfig {
                os_id: v.os_id.unwrap_or(d.os_id),
                sshkey_ids: v.ssh_key_ids.clone(),
                plan_type: v.plan_type.clone().unwrap_or(d.plan_type),
                default_region: v.region.clone(),
                ..d
            },
        ))
    }

    /// Fresh Vultr nodes: booted with a host key generated here, enrolled with it pinned, wicket installed.
    pub struct Vultr {
        pub ssh_key: Option<PathBuf>,
        pub hosts: Vec<String>,
        /// A node that never answers on its ssh port fails its lease after `wait.silent_limit`, and
        /// is destroyed like any node whose setup failed.
        pub wait: wicket_placement::boot::ReadyWait,
    }

    impl NodeSetup<VultrProvider> for Vultr {
        async fn boot(&self, name: &str) -> Result<Option<Boot>> {
            let key = wicket_placement::boot::generate_host_key(&format!("wicket-node-{name}")).await?;
            let user_data = wicket_placement::boot::cloud_config(wicket_placement::boot::NODE_SETUP, &key)?;
            Ok(Some(Boot { user_data, host_key: key.public.clone() }))
        }
        async fn ready(&self, p: &VultrProvider, lease: &LeaseRow, node: &NodeHandle) -> Result<(String, String)> {
            let pinned = lease.host_key.clone().context("no host key was pinned for this lease's node")?;
            let name = capacity::node_name(lease);
            if self.hosts.is_empty() {
                anyhow::bail!("placement.yaml has no node_hosts for the node's CA");
            }
            let (_, target) = crate::nodecreate::bring_up(
                p,
                &node.id,
                &name,
                &pinned,
                self.ssh_key.clone(),
                Some(self.hosts.clone()),
                std::time::Duration::from_secs(24 * 3600),
                &self.wait,
            )
            .await?;
            crate::update::install(&name, self.ssh_key.as_deref(), false).await?;
            Ok((name, target))
        }
        fn retire(&self, ledger: &mut Ledger, lease: &LeaseRow) -> Result<()> {
            if let Some(name) = &lease.node_name {
                if ledger.node(name)?.is_some_and(|r| r.status == "active") {
                    crate::enrol::revoke(ledger, &crate::enrol::Paths::installation().nodes_dir, name)?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capacity::PlacementConfig;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use wicket_placement::billing::BillingModel;
    use wicket_placement::model::PROTECTED_TAG;
    use wicket_placement::static_hosts::StaticHosts;
    use wicket_proxy::{CapacityAsk, CapacityState};
    use wicket_store::Approval as Grant;

    const NOW: i64 = 1_700_000_000;

    /// A provider account in memory. `strip_on_get` makes `get` return a node without its tags, as if
    /// someone changed them between the list and the destroy.
    #[derive(Clone, Default)]
    struct Fake {
        nodes: Arc<Mutex<BTreeMap<String, NodeHandle>>>,
        creates: Arc<Mutex<usize>>,
        destroyed: Arc<Mutex<Vec<String>>>,
        strip_on_get: Arc<AtomicBool>,
    }

    impl Fake {
        fn insert(&self, id: &str, tags: Vec<String>) {
            let n = NodeHandle {
                id: NodeId(id.into()),
                backend: "fake".into(),
                name: id.into(),
                ssh_target: Some("wicket@203.0.113.20".into()),
                region: Some("lhr".into()),
                plan: Some("small".into()),
                isolation: IsolationTier::Gvisor,
                resources: Resources { vcpus: 1, memory_mib: 1024 },
                billing: BillingModel::vultr(MicroUsd(14_000)),
                created_at: NOW - 600,
                lease_until: Owner::lease_from_tags(&tags),
                host_key: None,
                tags,
                state: NodeState::Active,
            };
            self.nodes.lock().unwrap().insert(id.into(), n);
        }
        fn ids(&self) -> Vec<String> {
            self.nodes.lock().unwrap().keys().cloned().collect()
        }
    }

    impl Provider for Fake {
        fn id(&self) -> &str {
            "fake"
        }
        async fn offers(&self, _r: &CapacityRequest) -> anyhow::Result<Vec<Offer>> {
            Ok(vec![Offer {
                plan: "small".into(),
                region: Some("lhr".into()),
                resources: Resources { vcpus: 2, memory_mib: 4096 },
                isolation: IsolationTier::Gvisor,
                billing: BillingModel::vultr(MicroUsd(14_000)),
            }])
        }
        async fn create(&self, spec: &CreateSpec) -> anyhow::Result<NodeHandle> {
            let n = {
                let mut c = self.creates.lock().unwrap();
                *c += 1;
                *c
            };
            let id = format!("i-new-{n}");
            self.insert(&id, spec.tags.clone());
            Ok(self.nodes.lock().unwrap()[&id].clone())
        }
        async fn get(&self, id: &NodeId) -> anyhow::Result<Option<NodeHandle>> {
            let mut n = self.nodes.lock().unwrap().get(&id.0).cloned();
            if self.strip_on_get.load(Ordering::SeqCst) {
                if let Some(n) = &mut n {
                    n.tags.clear();
                }
            }
            Ok(n)
        }
        async fn list_tagged(&self, tag: &str) -> anyhow::Result<Vec<NodeHandle>> {
            Ok(self.nodes.lock().unwrap().values().filter(|n| n.has_tag(tag)).cloned().collect())
        }
        async fn destroy(&self, id: &NodeId) -> anyhow::Result<()> {
            self.nodes.lock().unwrap().remove(&id.0);
            self.destroyed.lock().unwrap().push(id.0.clone());
            Ok(())
        }
    }

    /// Docker's boxes on one machine.
    #[derive(Clone, Default)]
    struct FakeBoxes {
        boxes: Arc<Mutex<Vec<BoxInfo>>>,
        killed: Arc<Mutex<Vec<String>>>,
    }

    impl FakeBoxes {
        fn with(boxes: &[(&str, &str, &str)]) -> FakeBoxes {
            let f = FakeBoxes::default();
            *f.boxes.lock().unwrap() = boxes
                .iter()
                .map(|(n, r, o)| BoxInfo { name: n.to_string(), run: Some(r.to_string()), owner: Some(o.to_string()) })
                .collect();
            f
        }
        fn killed(&self) -> Vec<String> {
            self.killed.lock().unwrap().clone()
        }
    }

    impl Boxes for FakeBoxes {
        async fn list(&self) -> Result<Vec<BoxInfo>> {
            Ok(self.boxes.lock().unwrap().clone())
        }
        async fn kill(&self, name: &str) -> Result<()> {
            self.boxes.lock().unwrap().retain(|b| b.name != name);
            self.killed.lock().unwrap().push(name.to_string());
            Ok(())
        }
    }

    /// Enrols nothing: the node is "ready" at once under the lease's node name (or the static host's).
    #[derive(Clone, Default)]
    struct FakeSetup {
        retired: Arc<Mutex<Vec<String>>>,
    }

    impl<P: Provider> NodeSetup<P> for FakeSetup {
        async fn boot(&self, _name: &str) -> Result<Option<Boot>> {
            Ok(None)
        }
        async fn ready(&self, _p: &P, lease: &LeaseRow, node: &NodeHandle) -> Result<(String, String)> {
            let name = if node.backend == "static" { node.name.clone() } else { capacity::node_name(lease) };
            Ok((name, node.ssh_target.clone().unwrap_or_default()))
        }
        fn retire(&self, _l: &mut Ledger, lease: &LeaseRow) -> Result<()> {
            self.retired.lock().unwrap().push(lease.id.clone());
            Ok(())
        }
    }

    /// Owner labels in these tests: `alive:…` runs, `dead:…` is gone, anything else is another machine's.
    fn alive(label: &str) -> Option<bool> {
        match label.split(':').next() {
            Some("alive") => Some(true),
            Some("dead") => Some(false),
            _ => None,
        }
    }

    fn started(l: &Ledger, run: &str, owner: &str) {
        l.run_started(&TenantId::single(), &RunId(run.into()), "z", "agent").unwrap();
        l.set_run_owner(run, owner).unwrap();
    }

    fn cfg(backend: &str) -> PlacementConfig {
        let y = match backend {
            "static" => "backend: static\nowner: example\nmax_hourly_usd: '0'\nmax_total_usd: '0'\nstatic_hosts:\n  - { name: n1, ssh_target: wicket@203.0.113.7, capacity: { vcpus: 4, memory_mib: 8192 }, isolation: gvisor }\n",
            _ => "backend: vultr\nowner: example\nmax_hourly_usd: '0.05'\nmax_total_usd: '0.05'\nvultr: { ssh_key_ids: [k1] }\n",
        };
        PlacementConfig::parse(y).unwrap()
    }

    fn capacity_ask(minutes: i64, max: &str) -> CapacityAsk {
        CapacityAsk {
            vcpus: 1,
            memory_mib: 1024,
            isolation: "gvisor".into(),
            region: Some("lhr".into()),
            duration_secs: minutes * 60,
            max_hourly_usd: max.into(),
            reason: "a bigger build".into(),
        }
    }

    /// Asks for a lease as `run` and has a human approve it. Returns the lease id.
    fn approved_lease(l: &mut Ledger, c: &PlacementConfig, run: &str) -> String {
        let st = capacity::ask(l, c, &TenantId::single(), &RunId(run.into()), "z", &capacity_ask(30, "0.02")).unwrap();
        assert!(matches!(st, CapacityState::Waiting(_)));
        let lease = l.leases(&["pending"]).unwrap().pop().unwrap();
        let rid = lease.request_id.clone().unwrap();
        assert!(l.request(&rid).unwrap().reason.contains(&lease.id));
        l.approve(&rid, &Grant { uses: Some(1), ttl: std::time::Duration::from_secs(60), path_prefix: None, decided_by: "test".into() })
            .unwrap();
        lease.id
    }

    struct World<P> {
        placer: Placer<P, LeaseApprover>,
        approver: LeaseApprover,
        setup: FakeSetup,
        local: FakeBoxes,
        nodes: BTreeMap<String, FakeBoxes>,
    }

    impl<P: Provider> World<P> {
        fn new(provider: P) -> World<P> {
            let approver = LeaseApprover::default();
            let placer = Placer::new(provider, approver.clone(), Owner::new("example")).with_clock(Arc::new(|| NOW));
            World { placer, approver, setup: FakeSetup::default(), local: FakeBoxes::default(), nodes: BTreeMap::new() }
        }

        async fn pass(&self, l: &mut Ledger, now: i64, dry_run: bool) -> Vec<Done> {
            let m = Machines { placer: &self.placer, approver: &self.approver, setup: &self.setup, warm_pool: false };
            let nodes = self.nodes.clone();
            let mut p = Pass::new(l, Some(m), &self.local, move |n: &str| nodes.get(n).cloned(), now, dry_run);
            p.owner_alive = alive;
            p.run().await.unwrap()
        }
    }

    fn kinds(d: &[Done]) -> Vec<&str> {
        d.iter().map(|d| d.kind).collect()
    }

    fn audited(l: &Ledger, kind: &str) -> usize {
        l.audit_tail(1000).unwrap().iter().filter(|r| r.2 == kind).count()
    }

    static ADOPTED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    fn adopt(run: &str) -> Result<()> {
        ADOPTED.lock().unwrap().push(run.to_string());
        Ok(())
    }

    /// #151: a run whose supervisor is gone is taken over if its node still has its box, ended as
    /// lost if its node says the box is gone, and left alone while its node can't be asked; its box
    /// is never stopped while the run is running.
    #[tokio::test]
    async fn a_run_whose_supervisor_is_gone_is_adopted_if_its_node_still_has_it() {
        let w = World::new(Fake::default());
        let mut l = Ledger::open_in_memory().unwrap();
        for (run, node) in [("run_kept", "n1"), ("run_gone", "n1"), ("run_far", "n2")] {
            l.run_started(&TenantId::single(), &RunId(run.into()), "z", "a").unwrap();
            l.set_run_owner(run, "dead:1:1").unwrap();
            l.set_run_node(run, node).unwrap();
        }
        // n2 is enrolled and active, but can't be reached; n3 was revoked.
        let node = |name: &str| wicket_store::NodeRow {
            name: name.into(),
            tenant: "t0".into(),
            target: format!("unix:{name}"),
            host_key: String::new(),
            host_key_fp: String::new(),
            node_key: String::new(),
            ssh_key: None,
            hosts: vec![],
            enrolled_at: NOW,
            status: "active".into(),
            revoked_at: None,
        };
        l.enrol_builtin_node(&node("n2")).unwrap();
        l.enrol_builtin_node(&node("n3")).unwrap();
        l.revoke_node("n3").unwrap();
        l.run_started(&TenantId::single(), &RunId("run_revoked".into()), "z", "a").unwrap();
        l.set_run_owner("run_revoked", "dead:1:1").unwrap();
        l.set_run_node("run_revoked", "n3").unwrap();
        let mut asked = HashMap::new();
        asked.insert("n1".to_string(), Some(vec!["run_kept".to_string()]));
        asked.insert("n2".to_string(), None);
        asked.insert("n3".to_string(), None);
        /// #153: run_fenced's box is still authorized on its (revoked, unreachable) node until
        /// NOW + 60 s, so it may still run there.
        fn fenced(run: &str, now_ms: i64) -> Option<(String, i64)> {
            (run == "run_fenced" && now_ms < (NOW + 60) * 1000).then(|| ("n3".to_string(), (NOW + 60) * 1000))
        }
        l.run_started(&TenantId::single(), &RunId("run_fenced".into()), "z", "a").unwrap();
        l.set_run_owner("run_fenced", "dead:1:1").unwrap();
        l.set_run_node("run_fenced", "n3").unwrap();
        async fn pass_at(
            w: &World<Fake>,
            l: &mut Ledger,
            asked: &HashMap<String, Option<Vec<String>>>,
            dry_run: bool,
            at: i64,
        ) -> Vec<Done> {
            let m = Machines { placer: &w.placer, approver: &w.approver, setup: &w.setup, warm_pool: false };
            let nodes = w.nodes.clone();
            let mut p = Pass::new(l, Some(m), &w.local, move |n: &str| nodes.get(n).cloned(), at, dry_run).with_node_runs(asked.clone());
            p.owner_alive = alive;
            p.adopt = adopt;
            p.fenced = fenced;
            p.run().await.unwrap()
        }
        async fn pass(w: &World<Fake>, l: &mut Ledger, asked: &HashMap<String, Option<Vec<String>>>, dry_run: bool) -> Vec<Done> {
            pass_at(w, l, asked, dry_run, NOW).await
        }
        // A dry run says so and changes nothing.
        let d = pass(&w, &mut l, &asked, true).await;
        assert!(d.iter().any(|x| x.kind == "run_adopted" && x.target == "run_kept"));
        assert!(ADOPTED.lock().unwrap().is_empty());
        assert_eq!(l.run_status("run_gone").unwrap().as_deref(), Some("running"));
        let d = pass(&w, &mut l, &asked, false).await;
        assert_eq!(*ADOPTED.lock().unwrap(), vec!["run_kept".to_string()]);
        assert_eq!(l.run_status("run_kept").unwrap().as_deref(), Some("running"));
        assert_eq!(l.run_status("run_gone").unwrap().as_deref(), Some(LOST));
        assert_eq!(l.run_status("run_far").unwrap().as_deref(), Some("running"));
        assert!(d.iter().any(|x| x.kind == "unreachable" && x.target == "run_far"));
        // A revoked node will never supervise its runs again: they end.
        assert_eq!(l.run_status("run_revoked").unwrap().as_deref(), Some(LOST));
        // Unless the box may still run there (#153): unreachable, still authorized until its
        // authority ends, not lost; then it ends.
        assert_eq!(l.run_status("run_fenced").unwrap().as_deref(), Some("running"));
        assert!(
            d.iter().any(|x| x.kind == "unreachable" && x.target == "run_fenced" && x.detail.contains("still authorized there until")),
            "{d:?}"
        );
        assert_eq!(audited(&l, "reconcile.run_adopted"), 1);
        pass_at(&w, &mut l, &asked, false, NOW + 61).await;
        assert_eq!(l.run_status("run_fenced").unwrap().as_deref(), Some(LOST));
    }

    /// #474: a long-lived agent's first box never starts on its node, so its run is lost straight
    /// away: the agent ends with it, instead of staying `active` with nobody behind it.
    #[tokio::test]
    async fn a_lost_run_ends_its_long_lived_agent() {
        let w = World::new(Fake::default());
        let mut l = Ledger::open_in_memory().unwrap();
        l.run_started(&TenantId::single(), &RunId("run_a".into()), "z", "a").unwrap();
        l.set_run_owner("run_a", "dead:1:1").unwrap();
        l.set_run_node("run_a", "pc").unwrap();
        l.create_agent(&wicket_store::NewAgent {
            id: "agt_a",
            tenant: "t0",
            zone: "z",
            name: "worker",
            run: "run_a",
            session_id: "s",
            manifest: "m",
            image: "img",
            workspace: None,
            claim_until: NOW + 30,
        })
        .unwrap();
        let asked = HashMap::from([("pc".to_string(), Some(vec![]))]);
        let nodes = w.nodes.clone();
        let m = Machines { placer: &w.placer, approver: &w.approver, setup: &w.setup, warm_pool: false };
        let mut p = Pass::new(&mut l, Some(m), &w.local, move |n: &str| nodes.get(n).cloned(), NOW, false).with_node_runs(asked);
        p.owner_alive = alive;
        p.adopt = adopt;
        let d = p.run().await.unwrap();
        assert_eq!(l.run_status("run_a").unwrap().as_deref(), Some(LOST));
        let a = l.agent("agt_a").unwrap().unwrap();
        assert_eq!(a.state, "ended");
        assert!(a.note.unwrap().contains("node pc has no box for it"));
        assert!(d.iter().any(|x| x.kind == "agent_ended" && x.target == "agt_a"), "{d:?}");
        assert_eq!(audited(&l, "reconcile.agent_ended"), 1);
    }

    #[tokio::test]
    async fn orphan_machines_go_and_untagged_or_protected_ones_are_never_touched() {
        let o = Owner::new("example");
        let fake = Fake::default();
        fake.insert("orphan", vec![o.tag(), o.idem_tag("capacity:l-gone")]);
        fake.insert("control-host", vec![]);
        fake.insert("someone-elses", vec![Owner::new("other").tag()]);
        fake.insert("broker", vec![o.tag(), PROTECTED_TAG.into()]);
        let w = World::new(fake.clone());
        let mut l = Ledger::open_in_memory().unwrap();
        // A dry run changes nothing.
        let d = w.pass(&mut l, NOW, true).await;
        assert!(kinds(&d).contains(&"destroy"));
        assert_eq!(fake.ids().len(), 4);
        assert_eq!(audited(&l, "reconcile.destroyed"), 0);
        let d = w.pass(&mut l, NOW, false).await;
        assert_eq!(*fake.destroyed.lock().unwrap(), vec!["orphan".to_string()]);
        assert_eq!(fake.ids(), vec!["broker", "control-host", "someone-elses"]);
        assert!(d.iter().any(|x| x.kind == "ignored" && x.target == "broker"));
        assert_eq!(audited(&l, "reconcile.destroyed"), 1);
    }

    #[tokio::test]
    async fn a_tag_changed_between_list_and_destroy_saves_the_machine() {
        let o = Owner::new("example");
        let fake = Fake::default();
        fake.insert("orphan", vec![o.tag(), o.idem_tag("capacity:l-gone")]);
        fake.strip_on_get.store(true, Ordering::SeqCst);
        let w = World::new(fake.clone());
        let mut l = Ledger::open_in_memory().unwrap();
        let d = w.pass(&mut l, NOW, false).await;
        assert!(fake.destroyed.lock().unwrap().is_empty());
        assert!(d.iter().any(|x| x.kind == "refused" && x.target == "orphan"), "{d:?}");
    }

    /// #409: a child whose supervisor is stuck in its parent's live process is reported each pass
    /// (not audited, not taken over); once that process is gone it is handled like any other run.
    #[tokio::test]
    async fn a_stuck_child_supervisor_is_reported_until_its_process_ends() {
        let mut l = Ledger::open_in_memory().unwrap();
        started(&l, "run_stuck", "alive:1");
        started(&l, "run_stuck_dead", "dead:1");
        started(&l, "run_fine", "alive:1");
        l.set_run_stuck("run_stuck", NOW - 90).unwrap();
        l.set_run_stuck("run_stuck_dead", NOW - 90).unwrap();
        let w = World::new(Fake::default());
        for _ in 0..2 {
            let d = w.pass(&mut l, NOW, false).await;
            let stuck: Vec<&Done> = d.iter().filter(|x| x.kind == "run_stuck").collect();
            assert_eq!(stuck.len(), 1, "{d:?}");
            assert_eq!(stuck[0].target, "run_stuck");
            assert!(stuck[0].detail.contains("90s ago"), "{}", stuck[0].detail);
            assert_eq!(l.run_status("run_stuck").unwrap().as_deref(), Some("running"));
        }
        assert_eq!(audited(&l, "reconcile.run_stuck"), 0);
        // Its process gone (no node recorded): ended as lost, as any run.
        assert_eq!(l.run_status("run_stuck_dead").unwrap().as_deref(), Some(LOST));
        assert_eq!(l.run_status("run_fine").unwrap().as_deref(), Some("running"));
    }

    #[tokio::test]
    async fn boxes_whose_run_ended_or_whose_process_is_gone_stop_and_unknown_ones_stay() {
        let mut l = Ledger::open_in_memory().unwrap();
        started(&l, "run_dead", "dead:1");
        started(&l, "run_live", "alive:1");
        started(&l, "run_done", "alive:2");
        started(&l, "run_elsewhere", "another-machine:3:4");
        l.run_ended(&RunId("run_done".into()), "succeeded", "").unwrap();
        let mut w = World::new(Fake::default());
        w.local = FakeBoxes::with(&[
            ("b-dead", "run_dead", "dead:1"),
            ("b-live", "run_live", "alive:1"),
            ("b-done", "run_done", "alive:2"),
            ("b-elsewhere", "run_elsewhere", "another-machine:3:4"),
            ("b-foreign", "run_not_in_this_ledger", "dead:9"),
        ]);
        let d = w.pass(&mut l, NOW, false).await;
        assert_eq!(w.local.killed(), vec!["b-dead", "b-done"]);
        assert_eq!(l.run_status("run_dead").unwrap().as_deref(), Some(LOST));
        assert_eq!(l.run_status("run_elsewhere").unwrap().as_deref(), Some("running"));
        assert!(d.iter().any(|x| x.kind == "left_alone" && x.target == "b-foreign"));
        // A second pass has nothing to do.
        let d = w.pass(&mut l, NOW, false).await;
        assert!(d.iter().all(|x| x.kind == "left_alone"), "{d:?}");
    }

    #[tokio::test]
    async fn a_node_created_before_a_crash_is_adopted_not_created_again() {
        let o = Owner::new("example");
        let mut l = Ledger::open_in_memory().unwrap();
        started(&l, "run_a", "alive:1");
        let c = cfg("vultr");
        let lease = approved_lease(&mut l, &c, "run_a");
        // The previous control process created it and died before recording it.
        let fake = Fake::default();
        fake.insert("i-made-before", vec![o.tag(), o.idem_tag(&lease_key(&lease)), Owner::lease_tag(NOW + 3000)]);
        let w = World::new(fake.clone());
        let d = w.pass(&mut l, NOW, false).await;
        assert!(kinds(&d).contains(&"adopted"), "{d:?}");
        assert_eq!(*fake.creates.lock().unwrap(), 0);
        let x = l.lease(&lease).unwrap().unwrap();
        assert_eq!((x.status.as_str(), x.node_id.as_deref(), x.not_after), ("active", Some("i-made-before"), Some(NOW + 3000)));
    }

    /// #369: a lease is provisioned only while its approval lasts and as it was approved: one whose
    /// grant ended first is closed, not provisioned, and that is on the record.
    #[tokio::test]
    async fn a_lease_whose_approval_ended_is_not_provisioned() {
        let dir = std::env::temp_dir().join(format!("wicket-rec-{}", ulid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = cfg("static");
        let w = World::new(StaticHosts::persistent(c.static_hosts.clone(), dir.join("static.json")));
        let mut l = Ledger::open_in_memory().unwrap();
        started(&l, "run_a", "alive:1");
        let lease = approved_lease(&mut l, &c, "run_a");
        let rid = l.lease(&lease).unwrap().unwrap().request_id.unwrap();
        let asked = l.request(&rid).unwrap().args_sha256.expect("the ask carries its arguments");
        assert_eq!(asked, capacity::lease_args(&l.lease(&lease).unwrap().unwrap()));
        let g = l.grant_for_request(&rid).unwrap().unwrap();
        assert_eq!(l.grant_effect(&g.id).unwrap().and_then(|(_, a)| a), Some(asked));
        l.revoke_grant(&g.id).unwrap();
        let d = w.pass(&mut l, NOW, false).await;
        assert_eq!(kinds(&d), vec!["lease_closed"], "{d:?}");
        assert_eq!(l.lease(&lease).unwrap().unwrap().status, "denied");
        assert!(l.audit_tail(20).unwrap().iter().any(|r| r.2 == "effect.refused"));
    }

    #[tokio::test]
    async fn request_capacity_on_static_hosts_from_ask_to_lease_end() {
        let dir = std::env::temp_dir().join(format!("wicket-rec-{}", ulid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = cfg("static");
        let provider = StaticHosts::persistent(c.static_hosts.clone(), dir.join("static.json"));
        let mut w = World::new(provider);
        let mut l = Ledger::open_in_memory().unwrap();
        started(&l, "run_a", "alive:1");
        let run = RunId("run_a".into());
        // The ask: pending, nothing reserved on the operator's own machines, waiting for a human.
        capacity::ask(&mut l, &c, &TenantId::single(), &run, "z", &capacity_ask(30, "0")).unwrap();
        let lease = l.leases(&["pending"]).unwrap().pop().unwrap();
        assert_eq!(lease.reserved, 0);
        assert!(matches!(capacity::status(&l, &run, &lease.id).unwrap(), CapacityState::Waiting(_)));
        // Nothing happens until a human approves.
        w.pass(&mut l, NOW, false).await;
        assert_eq!(l.lease(&lease.id).unwrap().unwrap().status, "pending");
        let rid = lease.request_id.clone().unwrap();
        assert_eq!(l.pending(&TenantId::single()).unwrap()[0].method, capacity::METHOD);
        l.approve(&rid, &Grant { uses: Some(1), ttl: std::time::Duration::from_secs(60), path_prefix: None, decided_by: "test".into() })
            .unwrap();
        let d = w.pass(&mut l, NOW, false).await;
        assert_eq!(kinds(&d), vec!["lease_approved", "created", "lease_active"], "{d:?}");
        let x = l.lease(&lease.id).unwrap().unwrap();
        assert_eq!((x.status.as_str(), x.node_name.as_deref()), ("active", Some("n1")));
        let CapacityState::Settled(t) = capacity::status(&l, &run, &lease.id).unwrap() else { panic!("not settled") };
        assert!(t.starts_with("ready:"), "{t}");
        // spawn's placement hint: the lease (or its node) places a child there; anything else is refused.
        let hint = serde_json::json!({ "lease": lease.id });
        let p = crate::spawn::placement(&l, "run_a", None, Some(&hint), NOW).unwrap().unwrap();
        assert_eq!(p, crate::spawn::Placed { node: "n1".into(), lease: Some(lease.id.clone()) });
        let by_node = crate::spawn::placement(&l, "run_a", None, Some(&serde_json::json!({ "node": "n1" })), NOW).unwrap();
        assert_eq!(by_node, Some(p));
        assert!(crate::spawn::placement(&l, "run_b", None, Some(&hint), NOW).is_err(), "another run's lease");
        assert!(crate::spawn::placement(&l, "run_a", None, Some(&serde_json::json!({ "node": "n9" })), NOW).is_err());
        assert!(crate::spawn::placement(&l, "run_a", Some("n9"), Some(&serde_json::json!({ "node": "n9" })), NOW).unwrap().is_some());
        // A child placed on it, with a box on the node.
        started(&l, "run_child", "alive:2");
        l.set_run_lease("run_child", &lease.id).unwrap();
        w.nodes.insert("n1".into(), FakeBoxes::with(&[("b-child", "run_child", "node-machine:1:1")]));
        // At lease end: the child stops, the lease ends, the allocation is freed.
        let end = x.not_after.unwrap();
        let d = w.pass(&mut l, end + 1, false).await;
        assert_eq!(w.nodes["n1"].killed(), vec!["b-child"]);
        assert_eq!(l.run_status("run_child").unwrap().as_deref(), Some(LOST));
        assert_eq!(l.lease(&lease.id).unwrap().unwrap().status, "ended");
        assert!(kinds(&d).contains(&"destroyed"), "{d:?}");
        assert!(w.placer.provider().list_tagged(&Owner::new("example").tag()).await.unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn leases_reserve_their_worst_case_against_the_budget_until_they_end() {
        let mut l = Ledger::open_in_memory().unwrap();
        started(&l, "run_a", "alive:1");
        let c = cfg("vultr"); // $0.05 total, $0.05/h
        let run = RunId("run_a".into());
        let t = TenantId::single();
        // 90 minutes at $0.02/h: two started hours, $0.04 reserved.
        capacity::ask(&mut l, &c, &t, &run, "z", &capacity_ask(90, "0.02")).unwrap();
        assert_eq!(l.leases(&[]).unwrap()[0].reserved, 40_000);
        let e = capacity::ask(&mut l, &c, &t, &run, "z", &capacity_ask(30, "0.02")).err().unwrap().to_string();
        assert!(e.contains("over this installation's budget"), "{e}");
        // The human denies the first: its reservation is given back.
        let rid = l.leases(&[]).unwrap()[0].request_id.clone().unwrap();
        l.deny(&rid, "test").unwrap();
        let w = World::new(Fake::default());
        let d = w.pass(&mut l, NOW, false).await;
        assert_eq!(kinds(&d), vec!["lease_closed"]);
        capacity::ask(&mut l, &c, &t, &run, "z", &capacity_ask(30, "0.02")).unwrap();
        // The approver lets the placer spend only on the lease being provisioned, up to its reservation.
        let a = LeaseApprover::default();
        a.allow("cap-x", MicroUsd(20_000));
        let ask = |name: &str, worst: u64| SpendRequest {
            backend: "vultr".into(),
            plan: "p".into(),
            region: None,
            node_name: name.into(),
            purpose: String::new(),
            hourly: MicroUsd(20_000),
            lifetime_secs: 1800,
            worst_case: MicroUsd(worst),
            warm: false,
        };
        assert_eq!(a.approve(&ask("cap-x", 20_000)).await, Approval::Approved);
        assert!(matches!(a.approve(&ask("cap-x", 30_000)).await, Approval::Denied(_)));
        assert!(matches!(a.approve(&ask("cap-y", 1)).await, Approval::Denied(_)));
    }

    /// #300, #324: a capacity lease whose run ended with files its node kept (a fetch that failed)
    /// isn't ended, so its node isn't destroyed with them; once they are collected it ends.
    #[tokio::test]
    async fn a_lease_whose_run_left_uncollected_files_is_kept() {
        let dir = std::env::temp_dir().join(format!("wicket-rec-{}", ulid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = cfg("static");
        let w = World::new(StaticHosts::persistent(c.static_hosts.clone(), dir.join("static.json")));
        let mut l = Ledger::open_in_memory().unwrap();
        started(&l, "run_files", "alive:1");
        let lease = approved_lease(&mut l, &c, "run_files");
        w.pass(&mut l, NOW, false).await;
        let node = l.lease(&lease).unwrap().unwrap().node_name.expect("its node");
        l.run_ended(&RunId("run_files".into()), "failed", "fetching its files failed").unwrap();
        l.set_run_uncollected("run_files", Some(&node)).unwrap();
        let d = w.pass(&mut l, NOW + 60, false).await;
        assert_eq!(l.lease(&lease).unwrap().unwrap().status, "active", "{d:?}");
        assert!(d.iter().any(|x| x.kind == "lease_held"), "{d:?}");
        l.set_run_uncollected("run_files", None).unwrap();
        w.pass(&mut l, NOW + 120, false).await;
        assert_eq!(l.lease(&lease).unwrap().unwrap().status, "ended");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn killing_the_control_plane_mid_run_leaves_nothing_after_one_pass_static() {
        let dir = std::env::temp_dir().join(format!("wicket-rec-{}", ulid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = cfg("static");
        let mut w = World::new(StaticHosts::persistent(c.static_hosts.clone(), dir.join("static.json")));
        let mut l = Ledger::open_in_memory().unwrap();
        // A parent run here with a lease on n1 and a child there, both running.
        started(&l, "run_parent", "alive:1");
        let lease = approved_lease(&mut l, &c, "run_parent");
        w.pass(&mut l, NOW, false).await;
        assert_eq!(l.lease(&lease).unwrap().unwrap().status, "active");
        started(&l, "run_child", "alive:2");
        l.set_run_lease("run_child", &lease).unwrap();
        w.local = FakeBoxes::with(&[("b-parent", "run_parent", "dead:1")]);
        w.nodes.insert("n1".into(), FakeBoxes::with(&[("b-child", "run_child", "node-machine:7:7")]));
        // Every control-plane process is killed (SIGKILL): their owner labels now name dead processes.
        l.set_run_owner("run_parent", "dead:1").unwrap();
        l.set_run_owner("run_child", "dead:2").unwrap();
        // Restart: one pass.
        w.pass(&mut l, NOW + 60, false).await;
        assert!(w.local.boxes.lock().unwrap().is_empty(), "no box left here");
        assert!(w.nodes["n1"].boxes.lock().unwrap().is_empty(), "no box left on the node");
        assert!(l.running_runs().unwrap().is_empty());
        assert_eq!(l.lease(&lease).unwrap().unwrap().status, "ended");
        assert!(w.placer.provider().list_tagged(&Owner::new("example").tag()).await.unwrap().is_empty(), "no allocation left");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ulid_like() -> String {
        format!("{}-{}", std::process::id(), wicket_store::new_lease_id())
    }

    // ---- the Vultr backend against a local mock of its API ----

    use wicket_placement::mock as vultr_mock;

    fn vultr(base: &str) -> wicket_placement::vultr::VultrProvider {
        use wicket_placement::vultr::*;
        let c = Client::with_base(base, ApiKey::new(vultr_mock::KEY))
            .unwrap()
            .with_retry(Retry { attempts: 2, base: std::time::Duration::from_millis(1) });
        VultrProvider::new(c, VultrConfig { sshkey_ids: vec!["k1".into()], ..VultrConfig::default() })
    }

    fn deletes(st: &vultr_mock::Shared) -> Vec<String> {
        st.lock().unwrap().seen.iter().filter(|s| s.method == "DELETE").map(|s| s.path.rsplit('/').next().unwrap().to_string()).collect()
    }

    #[tokio::test]
    async fn vultr_after_a_crash_adopts_its_node_destroys_the_orphan_and_nothing_else() {
        let (base, st) = vultr_mock::serve().await;
        let o = Owner::new("example");
        let mut l = Ledger::open_in_memory().unwrap();
        started(&l, "run_a", "alive:1");
        let lease = approved_lease(&mut l, &cfg("vultr"), "run_a");
        // The instances were created at 2023-11-14T22:03:20Z, ten minutes before NOW.
        let t = NOW + 600;
        {
            let mut m = st.lock().unwrap();
            m.instances = vec![
                vultr_mock::instance("orphan", &[o.tag(), o.idem_tag("capacity:l-old")]),
                vultr_mock::instance("mine", &[o.tag(), o.idem_tag(&lease_key(&lease)), Owner::lease_tag(NOW + 3000)]),
                vultr_mock::instance("control-host", &[]),
                vultr_mock::instance("broker", &[o.tag(), PROTECTED_TAG.into()]),
            ];
        }
        let w = World::new(vultr(&base));
        let d = w.pass(&mut l, t, false).await;
        assert_eq!(deletes(&st), vec!["orphan"], "{d:?}");
        assert!(!st.lock().unwrap().seen.iter().any(|s| s.method == "POST"), "nothing created: the lease's node was adopted");
        let x = l.lease(&lease).unwrap().unwrap();
        assert_eq!((x.status.as_str(), x.node_id.as_deref()), ("active", Some("mine")));

        // The control plane is killed mid-run; after restart one pass ends the run, its lease and its node.
        l.set_run_owner("run_a", "dead:1").unwrap();
        let d = w.pass(&mut l, t + 60, false).await;
        assert_eq!(deletes(&st), vec!["orphan", "mine"], "{d:?}");
        let x = l.lease(&lease).unwrap().unwrap();
        assert_eq!(x.status, "ended");
        assert_eq!(x.billed, Some(20_000), "one started hour at $0.014, rounded up to the cent");
        let left: Vec<String> = st.lock().unwrap().instances.iter().map(|i| i["id"].as_str().unwrap().to_string()).collect();
        assert_eq!(left, vec!["control-host", "broker"]);
    }

    #[tokio::test]
    async fn a_paid_lease_past_its_end_loses_its_node_and_runs_and_gives_its_money_back() {
        let (base, st) = vultr_mock::serve().await;
        let o = Owner::new("example");
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        started(&l, "run_a", "alive:1");
        let lease = approved_lease(&mut l, &cfg("vultr"), "run_a");
        assert_eq!(l.lease_reservations(&t.0, None, false).unwrap(), (20_000, 20_000));
        let end = NOW + 3000;
        st.lock().unwrap().instances =
            vec![vultr_mock::instance("mine", &[o.tag(), o.idem_tag(&lease_key(&lease)), Owner::lease_tag(end)])];
        let w = World::new(vultr(&base));
        w.pass(&mut l, NOW + 600, false).await;
        assert_eq!(l.lease(&lease).unwrap().unwrap().status, "active");
        // A child placed on it; its holder is still alive.
        started(&l, "run_child", "alive:2");
        l.set_run_lease("run_child", &lease).unwrap();
        // Before the end nothing changes; a dry run past it changes nothing either.
        w.pass(&mut l, end - 1, false).await;
        let d = w.pass(&mut l, end + 1, true).await;
        assert!(kinds(&d).contains(&"destroy"), "{d:?}");
        assert!(deletes(&st).is_empty());
        assert_eq!(l.lease(&lease).unwrap().unwrap().status, "active");
        assert_eq!(l.run_status("run_child").unwrap().as_deref(), Some("running"));
        // At the end: the child stops, the node goes, the lease ends and its reservation is released.
        w.pass(&mut l, end + 1, false).await;
        assert_eq!(deletes(&st), vec!["mine"]);
        assert_eq!(l.run_status("run_child").unwrap().as_deref(), Some(LOST));
        assert_eq!(l.run_status("run_a").unwrap().as_deref(), Some("running"), "the holder keeps running");
        assert_eq!(l.lease(&lease).unwrap().unwrap().status, "ended");
        assert_eq!(l.lease_reservations(&t.0, None, false).unwrap(), (0, 0));
        assert!(audited(&l, "reconcile.destroyed") >= 1);
    }

    // The pass needs the ledger the hook shares; nothing else takes the lock in this test.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn request_capacity_through_the_gateway_hook_from_ask_to_ready() {
        let dir = std::env::temp_dir().join(format!("wicket-rec-{}", ulid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = cfg("static");
        let w = World::new(StaticHosts::persistent(c.static_hosts.clone(), dir.join("static.json")));
        let l = Ledger::open_in_memory().unwrap();
        started(&l, "run_a", "alive:1");
        let ledger = Arc::new(Mutex::new(l));
        let hook = capacity::hook(TenantId::single(), RunId("run_a".into()), "z".into(), ledger.clone(), c.clone());
        let CapacityState::Waiting(msg) = hook(wicket_proxy::CapacityCall::Ask(capacity_ask(30, "0"))).unwrap() else {
            panic!("an ask waits for a human")
        };
        let lease = ledger.lock().unwrap().leases(&["pending"]).unwrap().pop().unwrap();
        assert!(msg.contains(&lease.id), "the agent is told its lease id: {msg}");
        assert!(matches!(hook(wicket_proxy::CapacityCall::Status(lease.id.clone())).unwrap(), CapacityState::Waiting(_)));
        {
            let mut l = ledger.lock().unwrap();
            let grant = Grant { uses: Some(1), ttl: std::time::Duration::from_secs(60), path_prefix: None, decided_by: "test".into() };
            l.approve(lease.request_id.as_deref().unwrap(), &grant).unwrap();
            w.pass(&mut l, NOW, false).await;
        }
        let CapacityState::Settled(s) = hook(wicket_proxy::CapacityCall::Status(lease.id.clone())).unwrap() else { panic!("not settled") };
        assert!(s.starts_with("ready:"), "{s}");
        // Another run can't read it.
        let other = capacity::hook(TenantId::single(), RunId("run_b".into()), "z".into(), ledger.clone(), c);
        assert!(other(wicket_proxy::CapacityCall::Status(lease.id.clone())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn vultr_refuses_to_destroy_a_node_whose_tag_changed_after_the_list() {
        let (base, st) = vultr_mock::serve().await;
        let o = Owner::new("example");
        {
            let mut m = st.lock().unwrap();
            m.instances = vec![vultr_mock::instance("orphan", &[o.tag(), o.idem_tag("capacity:l-old")])];
            m.strip_on_get = true;
        }
        let w = World::new(vultr(&base));
        let mut l = Ledger::open_in_memory().unwrap();
        let d = w.pass(&mut l, NOW + 600, false).await;
        assert!(deletes(&st).is_empty());
        assert!(d.iter().any(|x| x.kind == "refused"), "{d:?}");
    }

    // ---- nodes from `wicket node create` (#294), against the Vultr mock and a fake clock ----

    static RETIRED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    fn retire(_l: &mut Ledger, n: &NodeHandle) -> Result<bool> {
        RETIRED.lock().unwrap().push(n.name.clone());
        Ok(true)
    }

    /// Records `id` as `wicket node create` does, named `name`, its lease ending at `end`.
    fn placed(l: &Ledger, st: &vultr_mock::Shared, id: &str, name: &str, end: i64) {
        let o = Owner::new("example");
        let mut i = vultr_mock::instance(id, &[o.tag(), o.idem_tag(&format!("place-create:{name}")), Owner::lease_tag(end)]);
        i["label"] = serde_json::json!(name);
        st.lock().unwrap().instances.push(i);
        l.record_placed_node(&wicket_store::PlacedNodeRow {
            id: id.into(),
            backend: "vultr".into(),
            name: name.into(),
            owner: "example".into(),
            api_key_secret: "vultr-api-key".into(),
            created_at: NOW - 600,
            lease_until: end,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: None,
        })
        .unwrap();
    }

    /// The whole pass at `now`: runs, leases, capacity machines and boxes, then placed nodes.
    async fn full_pass(w: &World<wicket_placement::vultr::VultrProvider>, l: &mut Ledger, now: i64, dry_run: bool) -> Vec<Done> {
        let mut d = w.pass(l, now, dry_run).await;
        d.extend(placed_pass(l, &w.placer, retire, now, dry_run).await.unwrap());
        d
    }

    #[tokio::test]
    async fn an_idle_placed_node_is_released_at_its_lease_end_without_place_release() {
        let (base, st) = vultr_mock::serve().await;
        let o = Owner::new("example");
        let mut l = Ledger::open_in_memory().unwrap();
        // Created ten minutes before NOW with a 1h lifetime: its lease ends at minute 50.
        let end = NOW - 600 + 50 * 60;
        placed(&l, &st, "placed-idle", "idle-node", end);
        // A capacity node no lease asks for, beside it: the machine half still destroys it at once.
        st.lock().unwrap().instances.push(vultr_mock::instance("orphan", &[o.tag(), o.idem_tag("capacity:l-old")]));
        let w = World::new(vultr(&base));
        // Before its lease end the placed node is kept: having no capacity lease doesn't make it an orphan.
        let d = full_pass(&w, &mut l, NOW, false).await;
        assert_eq!(deletes(&st), vec!["orphan"], "{d:?}");
        full_pass(&w, &mut l, end - 1, false).await;
        assert_eq!(deletes(&st), vec!["orphan"]);
        // A dry run at its end says what it would do and changes nothing.
        let d = full_pass(&w, &mut l, end, true).await;
        assert!(d.iter().any(|x| x.kind == "release" && x.target == "placed-idle"), "{d:?}");
        assert_eq!(deletes(&st), vec!["orphan"]);
        assert_eq!(l.placed_node("placed-idle").unwrap().unwrap().status, "active");
        // At its end, with nothing on it: released through the placer, recorded, audited with why.
        let d = full_pass(&w, &mut l, end, false).await;
        assert_eq!(deletes(&st), vec!["orphan", "placed-idle"], "{d:?}");
        let x = d.iter().find(|x| x.kind == "placed_released").expect("released");
        assert!(x.detail.contains("its lease ended at") && x.detail.contains("no run is placed on it"), "{}", x.detail);
        assert!(x.detail.contains("revoked"), "{}", x.detail);
        assert!(RETIRED.lock().unwrap().contains(&"idle-node".to_string()));
        let row = l.placed_node("placed-idle").unwrap().unwrap();
        assert_eq!(row.status, "released");
        assert_eq!(audited(&l, "reconcile.placed_released"), 1);
        assert!(st.lock().unwrap().instances.iter().all(|i| i["id"] != "placed-idle"));
        // The next pass has nothing left to do for it.
        let d = full_pass(&w, &mut l, end + 60, false).await;
        assert!(!d.iter().any(|x| x.target == "placed-idle"), "{d:?}");
        assert_eq!(audited(&l, "reconcile.placed_released"), 1);
    }

    /// #324: `wicket node create` records its node once the provider answers. A pass that lists the
    /// instance before that leaves it alone while it is new, rather than destroying a node its human
    /// was just given; once the grace is over, a node still unrecorded is an orphan and goes.
    #[tokio::test]
    async fn a_node_just_created_and_not_yet_recorded_is_left_for_its_creator() {
        let (base, st) = vultr_mock::serve().await;
        let o = Owner::new("example");
        let mut l = Ledger::open_in_memory().unwrap();
        // Created just before NOW, not recorded yet.
        let new = |id: &str, key: &str| {
            let mut i = vultr_mock::instance(id, &[o.tag(), o.idem_tag(key)]);
            i["date_created"] = serde_json::json!("2023-11-14T22:13:00+00:00"); // NOW - 20
            i
        };
        st.lock().unwrap().instances.push(new("just-made", "place-create:p0"));
        let w = World::new(vultr(&base));
        let d = full_pass(&w, &mut l, NOW + 30, false).await;
        assert!(deletes(&st).is_empty(), "{d:?}");
        assert!(d.iter().any(|x| x.kind == "young" && x.target == "just-made"), "{d:?}");
        // Recorded meanwhile: it is the placed node's from then on, kept to its lease.
        let end = NOW + 3000;
        l.record_placed_node(&wicket_store::PlacedNodeRow {
            id: "just-made".into(),
            backend: "vultr".into(),
            name: "p0".into(),
            owner: "example".into(),
            api_key_secret: "vultr-api-key".into(),
            created_at: NOW,
            lease_until: end,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: None,
        })
        .unwrap();
        full_pass(&w, &mut l, NOW + 700, false).await;
        assert!(deletes(&st).is_empty(), "recorded: kept to its lease");
        // One never recorded is an orphan once the grace is over.
        st.lock().unwrap().instances.push(new("crashed", "place-create:p1"));
        full_pass(&w, &mut l, NOW + 60, false).await;
        assert!(deletes(&st).is_empty());
        full_pass(&w, &mut l, NOW - 20 + wicket_placement::reconcile::UNRECORDED_GRACE_SECS, false).await;
        assert_eq!(deletes(&st), vec!["crashed"]);
    }

    /// #300, #324: a run whose files a fetch didn't bring back holds its placed node past its lease,
    /// as a running run does: releasing it would destroy them. A human's `place release` decides.
    #[tokio::test]
    async fn a_placed_node_keeping_a_runs_uncollected_files_is_not_released() {
        let (base, st) = vultr_mock::serve().await;
        let mut l = Ledger::open_in_memory().unwrap();
        let end = NOW + 2400;
        placed(&l, &st, "placed-files", "files-node", end);
        started(&l, "run_done", "alive:1");
        l.set_run_node("run_done", "files-node").unwrap();
        l.run_ended(&RunId("run_done".into()), "failed", "fetching its files failed").unwrap();
        l.set_run_uncollected("run_done", Some("files-node")).unwrap();
        let w = World::new(vultr(&base));
        let d = full_pass(&w, &mut l, end + 1, false).await;
        assert!(deletes(&st).is_empty(), "{d:?}");
        let x = d.iter().find(|x| x.kind == "placed_held").expect("flagged");
        assert!(x.detail.contains("run_done") && x.detail.contains("didn't bring back"), "{}", x.detail);
        assert_eq!(l.placed_node("placed-files").unwrap().unwrap().held_by.as_deref(), Some("run_done"));
        // Collected (or given up by a human): released at the next pass.
        l.set_run_uncollected("run_done", None).unwrap();
        full_pass(&w, &mut l, end + 60, false).await;
        assert_eq!(deletes(&st), vec!["placed-files"]);
    }

    /// #494, #495: a node held past its lease bills hours its worst case didn't reserve. The pass
    /// reserves them (every started hour and the next), so the next node's spend check counts them;
    /// a dry run changes nothing.
    #[tokio::test]
    async fn a_held_placed_node_has_what_it_bills_past_its_lease_reserved() {
        let (base, st) = vultr_mock::serve().await;
        let mut l = Ledger::open_in_memory().unwrap();
        let end = NOW + 2400;
        placed(&l, &st, "placed-held", "held-node", end);
        let mut row = l.placed_node("placed-held").unwrap().unwrap();
        row.hourly = Some(14_000);
        l.record_placed_node(&row).unwrap();
        let key = wicket_store::money::node_money_key("held-node");
        let budget = wicket_store::LeaseBudget { max_hourly: 42_000, max_total: 56_000 };
        // Its worst case at creation: one hour, rounded to the cent.
        l.reserve_money("t", &key, 14_000, 20_000, 3600, budget, wicket_store::money::NODE_MONEY_BY).unwrap().unwrap();
        started(&l, "run_busy", "alive:1");
        l.set_run_node("run_busy", "held-node").unwrap();
        let w = World::new(vultr(&base));
        full_pass(&w, &mut l, end + 1, true).await;
        assert_eq!(l.money_reserved("t").unwrap().1, 20_000, "a dry run reserves nothing");
        full_pass(&w, &mut l, end + 1, false).await;
        // 3001 s old: its first hour, and the second, $0.028 → $0.03.
        assert_eq!(l.money_reserved("t").unwrap().1, 30_000);
        assert!(
            l.reserve_money(
                "t",
                &wicket_store::money::node_money_key("next"),
                14_000,
                30_000,
                3600,
                budget,
                wicket_store::money::NODE_MONEY_BY
            )
            .unwrap()
            .is_err(),
            "the next node's $0.03 no longer fits the $0.056"
        );
    }

    /// #256 (#326's mutants): a pass keeps a placed node's money reserved a day at a time while it
    /// bills, lease or not; a dry run leaves it as it was.
    #[tokio::test]
    async fn a_pass_renews_a_placed_nodes_money_for_a_day_and_a_dry_run_does_not() {
        let (base, st) = vultr_mock::serve().await;
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, &st, "placed-renew", "renew-node", NOW + 2400);
        let budget = wicket_store::LeaseBudget { max_hourly: 42_000, max_total: 56_000 };
        let key = wicket_store::money::node_money_key("renew-node");
        l.reserve_money("t", &key, 14_000, 20_000, 60, budget, wicket_store::money::NODE_MONEY_BY).unwrap().unwrap();
        let expires = |l: &Ledger| {
            let path = format!("/quota/money.reserved/{key}");
            let g = l.grants(&TenantId("t".into()), false, 100).unwrap().into_iter().find(|g| g.grant.path == path).expect("reserved");
            g.grant.expires_at - wicket_store::now()
        };
        assert!(expires(&l) <= 60);
        let w = World::new(vultr(&base));
        placed_pass(&mut l, &w.placer, retire, NOW, true).await.unwrap();
        assert!(expires(&l) <= 60, "a dry run renews nothing");
        placed_pass(&mut l, &w.placer, retire, NOW, false).await.unwrap();
        let left = expires(&l);
        assert!((24 * 3600 - 5..=24 * 3600).contains(&left), "renewed for a day: {left} s left");
    }

    /// #326's mutants: the provider's node went between the pass reading it and releasing it. The
    /// release says it was already gone, and names no bill (nothing was destroyed by this pass).
    #[tokio::test]
    async fn a_placed_node_gone_before_its_release_is_reported_as_already_gone() {
        let (base, st) = vultr_mock::serve().await;
        let mut l = Ledger::open_in_memory().unwrap();
        let end = NOW + 2400;
        placed(&l, &st, "placed-race", "race-node", end);
        let inst = st.lock().unwrap().instances.iter().find(|i| i["id"] == "placed-race").cloned().unwrap();
        let w = World::new(vultr(&base));
        // One read first, so the provider has its plans (it asks for them once).
        assert!(w.placer.get(&NodeId("placed-race".into())).await.unwrap().is_some());
        // The pass's read finds it; the release's own read doesn't.
        st.lock().unwrap().injected.extend([
            (200, serde_json::json!({ "instance": inst })),
            (404, serde_json::json!({"error": "Invalid instance-id.", "status": 404})),
        ]);
        let d = placed_pass(&mut l, &w.placer, retire, end + 1, false).await.unwrap();
        let x = d.iter().find(|x| x.kind == "placed_released").unwrap_or_else(|| panic!("released: {d:?}"));
        assert!(x.detail.contains("already gone") && !x.detail.contains("billed"), "{}", x.detail);
        // A node this pass destroyed says so, with what it billed.
        placed(&l, &st, "placed-gone", "gone-node", end);
        let d = placed_pass(&mut l, &w.placer, retire, end + 1, false).await.unwrap();
        let x = d.iter().find(|x| x.kind == "placed_released" && x.target == "placed-gone").expect("released");
        assert!(x.detail.contains("released (") && x.detail.contains("billed"), "{}", x.detail);
    }

    #[tokio::test]
    async fn a_held_placed_node_is_kept_and_flagged_then_released_when_its_run_ends() {
        let (base, st) = vultr_mock::serve().await;
        let mut l = Ledger::open_in_memory().unwrap();
        let end = NOW + 2400;
        placed(&l, &st, "placed-busy", "busy-node", end);
        // A run is still placed on it (by its enrolled name), its supervisor alive.
        started(&l, "run_busy", "alive:1");
        l.set_run_node("run_busy", "busy-node").unwrap();
        let w = World::new(vultr(&base));
        let d = full_pass(&w, &mut l, end + 1, false).await;
        assert!(deletes(&st).is_empty(), "{d:?}");
        let x = d.iter().find(|x| x.kind == "placed_held").expect("flagged");
        assert!(
            x.detail.contains("past its lease") && x.detail.contains("run_busy") && x.detail.contains("wicket node release placed-busy")
        );
        let row = l.placed_node("placed-busy").unwrap().unwrap();
        assert_eq!((row.status.as_str(), row.held_by.as_deref()), ("active", Some("run_busy")));
        assert_eq!(audited(&l, "reconcile.placed_held"), 1);
        // The console shows it as past its lease and held.
        let v = crate::serve::placed_view(&l, end + 1).unwrap();
        assert_eq!((v[0]["past_lease"].as_bool(), v[0]["held_by"].as_str()), (Some(true), Some("run_busy")));
        // Every pass says so; the audit records it once, not every pass.
        let d = full_pass(&w, &mut l, end + 120, false).await;
        assert!(d.iter().any(|x| x.kind == "placed_held"));
        assert_eq!(audited(&l, "reconcile.placed_held"), 1);
        assert!(deletes(&st).is_empty());
        // Once the run ends, the next pass releases it.
        l.run_ended(&RunId("run_busy".into()), "succeeded", "").unwrap();
        let d = full_pass(&w, &mut l, end + 180, false).await;
        assert_eq!(deletes(&st), vec!["placed-busy"], "{d:?}");
        assert_eq!(l.placed_node("placed-busy").unwrap().unwrap().status, "released");
    }

    /// #579's review, 3: a per-node service's instance neither holds nor bills a node past its
    /// lease, and is drained (stopped, audited) before the node goes.
    #[tokio::test]
    async fn a_service_instance_holds_no_node_and_is_drained_before_release() {
        let (base, st) = vultr_mock::serve().await;
        let mut l = Ledger::open_in_memory().unwrap();
        let end = NOW + 2400;
        placed(&l, &st, "placed-svc", "svc-node", end);
        started(&l, "run_cache", "alive:1");
        l.set_run_node("run_cache", "svc-node").unwrap();
        l.record_service_instance("run_cache", "npm-cache", "svc-node", "t0", "aa", wicket_store::now()).unwrap();
        let w = World::new(vultr(&base));
        let d = placed_pass(&mut l, &w.placer, retire, end + 1, false).await.unwrap();
        assert!(!d.iter().any(|x| x.kind == "placed_held"), "an instance alone holds nothing: {d:?}");
        assert!(d.iter().any(|x| x.kind == "service_stopped" && x.detail.contains("run_cache")), "{d:?}");
        assert_eq!(deletes(&st), vec!["placed-svc"], "released, as with no run on it");
        assert!(l.revoked_in_chain("run_cache").unwrap().is_some(), "the instance's run is revoked");
        assert_eq!(audited(&l, "service.instance_stopped"), 1);
    }

    /// #579's review, 3: a node past its lease with a user's box on it is held for that box, its
    /// service instance beside it or not (it's the box that holds it).
    #[tokio::test]
    async fn a_node_with_a_user_box_is_held_whatever_service_instance_is_on_it() {
        let (base, st) = vultr_mock::serve().await;
        let mut l = Ledger::open_in_memory().unwrap();
        let end = NOW + 2400;
        placed(&l, &st, "placed-both", "both-node", end);
        for (run, owner) in [("run_user", "alive:1"), ("run_cache2", "alive:2")] {
            started(&l, run, owner);
            l.set_run_node(run, "both-node").unwrap();
        }
        l.record_service_instance("run_cache2", "npm-cache", "both-node", "t0", "aa", wicket_store::now()).unwrap();
        let w = World::new(vultr(&base));
        let d = placed_pass(&mut l, &w.placer, retire, end + 1, false).await.unwrap();
        let held = d.iter().find(|x| x.kind == "placed_held").expect("held");
        assert!(held.detail.contains("run_user") && !held.detail.contains("run_cache2"), "{}", held.detail);
        assert!(deletes(&st).is_empty());
        assert!(l.revoked_in_chain("run_cache2").unwrap().is_none(), "not drained while the node stays");
    }

    #[tokio::test]
    async fn a_placed_node_protected_after_creation_is_left_alone_and_recorded_so() {
        let (base, st) = vultr_mock::serve().await;
        let mut l = Ledger::open_in_memory().unwrap();
        let end = NOW + 2400;
        placed(&l, &st, "placed-kept", "kept-node", end);
        st.lock().unwrap().instances[0]["tags"].as_array_mut().unwrap().push(serde_json::json!(PROTECTED_TAG));
        let w = World::new(vultr(&base));
        let d = full_pass(&w, &mut l, end, false).await;
        assert!(deletes(&st).is_empty(), "{d:?}");
        assert!(d.iter().any(|x| x.kind == "refused" && x.target == "placed-kept"), "{d:?}");
        assert_eq!(l.placed_node("placed-kept").unwrap().unwrap().status, "left");
        // Another installation's placed nodes are not this placer's to look at.
        l.record_placed_node(&wicket_store::PlacedNodeRow {
            id: "theirs".into(),
            backend: "vultr".into(),
            name: "theirs".into(),
            owner: "someone-else".into(),
            api_key_secret: "k".into(),
            created_at: 0,
            lease_until: 0,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: None,
        })
        .unwrap();
        let d = placed_pass(&mut l, &w.placer, retire, end + 60, false).await.unwrap();
        assert!(d.is_empty(), "{d:?}");
        assert_eq!(l.placed_node("theirs").unwrap().unwrap().status, "active");
    }
}

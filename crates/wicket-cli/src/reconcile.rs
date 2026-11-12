//! The reconciler (#38, which includes the box half of #21): one pass makes what exists agree with the
//! ledger, and `wicket reconcile --every <interval>` runs passes for ever.
//!
//! **What it compares.**
//! - *Runs*: a run recorded as `running` whose supervising `wicket run` process (its owner label,
//!   `<machine>:<pid>:<start>`) is gone on this machine is ended as `lost`. A run supervised on another
//!   machine is left alone: only that machine can tell.
//! - *Leases* (`wicket_store::LeaseRow`): a pending lease whose request a human granted becomes
//!   `approved`, one denied or withdrawn ends. An approved or active lease ends when its holder run has
//!   ended or (active) when `not_after` has passed; runs placed on it are stopped first.
//! - *Machines*: the provider's instances carrying this installation's owner tag, against the approved
//!   and active leases (`wicket_placement::reconcile`, matching by each lease's idempotency tag). A node
//!   no live lease asks for is destroyed, or with `warm_pool` kept until minute 50 of its paid hour; a
//!   duplicate is destroyed; a node that matches a lease the ledger has no node for (a crash between
//!   create and record) is adopted; an approved lease with no node gets one (acquire, enrol with the
//!   host key pinned at creation, `wicket node install`). Untagged instances are never listed, so never
//!   touched; protected ones are reported and left. **Ownership is checked again right before every
//!   destroy** (`Placer::release` reads the instance and refuses one without the owner tag or with
//!   `wicket-protected`), so a tag changed between list and destroy saves the machine.
//! - *Boxes*: Docker's `wicket=1` containers, here and on every active enrolled node (over its pinned
//!   ssh), by their `wicket.run` label. A box whose run has ended, or (here) whose owner process is gone,
//!   is stopped. **A box whose run this ledger doesn't know is left alone**: Docker may be shared.
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
use crate::reap::LOST;
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
            owner_alive: crate::reap::owner_alive,
            now,
            dry_run,
            done: vec![],
            runs_ended: HashSet::new(),
            leases_ended: HashSet::new(),
        }
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
            self.ledger.run_ended(&RunId(run.to_string()), LOST, why)?;
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
            if (self.owner_alive)(&o) == Some(false) {
                self.end_run(&run, "its wicket process is gone (found by the reconciler)")?;
                self.did("run_lost", &run, "its wicket process is gone", Some(&run));
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
                    if !self.dry_run {
                        self.ledger.lease_transition(&lease.id, &["pending"], "approved", &format!("request {rid} granted"))?;
                    }
                    self.did("lease_approved", &lease.id, &format!("request {rid} granted by a human"), Some(&lease.run));
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

    async fn lease_ends(&mut self) -> Result<()> {
        for lease in self.live_leases(&["approved", "active"])? {
            let holder = self.run_status(&lease.run)?;
            let why = if holder.as_deref() != Some("running") {
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
        // Destroys first, so the envelope sees room before anything is created.
        let mut actions = plan::reconcile(&owner, &desired, &observed, self.now, warm, &PoolRules::default());
        actions.sort_by_key(|a| !matches!(a, plan::Action::Destroy { .. }));
        for a in actions {
            match a {
                plan::Action::Ignore { node, reason } => self.note("ignored", &node.0, &format!("{reason:?}: never touched")),
                plan::Action::Pool { node, until } => {
                    self.note("kept_warm", &node.0, &format!("no lease; paid until {}, destroyed then", capacity::fmt_time(until)))
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
                n.lease_until.map(capacity::fmt_time).unwrap_or_default()
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
                    &format!("node {name} ({target}) until {}", capacity::fmt_time(until)),
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
            Some("running") if node.is_none() && b.owner.as_deref().map(self.owner_alive) == Some(Some(false)) => {
                self.end_run(run, "its box's wicket process is gone (found by the reconciler)")?;
                "its wicket process is gone".to_string()
            }
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

/// One pass with this installation's ledger, Docker, nodes and placement configuration.
pub async fn pass(dry_run: bool) -> Result<Vec<Done>> {
    let _lock = Lock::take()?;
    let mut ledger = Ledger::open(&crate::ledger_path())?;
    let local = Docker::from_env();
    let now = wicket_store::now();
    let Some(cfg) = PlacementConfig::load()? else {
        let none: Option<Machines<'_, static_hosts::StaticHosts, setup::Static>> = None;
        return Pass::new(&mut ledger, none, &local, node_docker, now, dry_run).run().await;
    };
    let approver = LeaseApprover::default();
    match cfg.backend {
        capacity::Backend::Static => {
            let provider = static_hosts::StaticHosts::persistent(cfg.static_hosts.clone(), crate::data_dir().join("placement-static.json"));
            let placer = Placer::new(provider, approver.clone(), cfg.owner(), cfg.envelope()?);
            let s = setup::Static { install: cfg.install_static };
            let m = Machines { placer: &placer, approver: &approver, setup: &s, warm_pool: cfg.warm_pool };
            Pass::new(&mut ledger, Some(m), &local, node_docker, now, dry_run).run().await
        }
        capacity::Backend::Vultr => {
            let v = cfg.vultr.clone().context("vultr settings")?;
            let provider = setup::vultr_provider(&v)?;
            let placer = Placer::new(provider, approver.clone(), cfg.owner(), cfg.envelope()?);
            let s = setup::Vultr { ssh_key: v.ssh_key.clone(), hosts: cfg.node_hosts.clone() };
            let m = Machines { placer: &placer, approver: &approver, setup: &s, warm_pool: cfg.warm_pool };
            Pass::new(&mut ledger, Some(m), &local, node_docker, now, dry_run).run().await
        }
    }
}

pub fn print(done: &[Done], dry_run: bool) {
    for d in done {
        println!("{:<15} {}  {}", d.kind, d.target, d.detail);
    }
    let changed = done.iter().filter(|d| !matches!(d.kind, "ignored" | "kept_warm" | "left_alone" | "unreachable")).count();
    println!("reconcile: {changed} change(s){}", if dry_run { " (dry run: nothing changed)" } else { "" });
}

/// `wicket reconcile [--dry-run] [--every <interval>]`.
pub async fn command(dry_run: bool, every: Option<std::time::Duration>) -> Result<()> {
    loop {
        match pass(dry_run).await {
            Ok(d) => print(&d, dry_run),
            Err(e) if every.is_some() => eprintln!("reconcile pass failed: {e:#}"),
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
                crate::enrol::install(&row.name, None, false).await?;
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
            let (_, target) = crate::place::bring_up(
                p,
                &node.id,
                &name,
                &pinned,
                self.ssh_key.clone(),
                Some(self.hosts.clone()),
                std::time::Duration::from_secs(24 * 3600),
            )
            .await?;
            crate::enrol::install(&name, self.ssh_key.as_deref(), false).await?;
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
            let placer = Placer::new(
                provider,
                approver.clone(),
                Owner::new("example"),
                MoneyEnvelope { max_hourly: MicroUsd(1_000_000), max_total: MicroUsd(10_000_000) },
            )
            .with_clock(Arc::new(|| NOW));
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
            committed_hourly: MicroUsd::ZERO,
            committed_total: MicroUsd::ZERO,
            max_hourly: MicroUsd::ZERO,
            max_total: MicroUsd::ZERO,
        };
        assert_eq!(a.approve(&ask("cap-x", 20_000)).await, Approval::Approved);
        assert!(matches!(a.approve(&ask("cap-x", 30_000)).await, Approval::Denied(_)));
        assert!(matches!(a.approve(&ask("cap-y", 1)).await, Approval::Denied(_)));
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
}

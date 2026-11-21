//! Releasing a placed node (#710): what the decider is shown, the decision, and the release itself,
//! for `wicket node release` and the console's release of a node past its lease alike.
//!
//! A node `wicket node create` made is released by the reconciler once its lease ends, unless a
//! run still runs on it or keeps files a fetch didn't bring back: then it is kept, and bills, until
//! a human releases it. Releasing it destroys the machine, the boxes and service instances still
//! running there and the files it keeps, so the decision is bound to what the decider was shown
//! ([`PastLease::effect`]):
//!
//! 1. [`decide`]: an operator only within its authority (`operators.yaml`: `capacity` at R4), and
//!    from the console only a node past its lease; root on the host any node. Always on the effect
//!    shown, which must still be the node as it is now. A refusal is audited (`decision.refused`).
//!    The decision is audited (`placement.node_release_decided`) **before** anything is released:
//!    if that write fails, nothing is.
//! 2. [`release`], with the node's own placer (its owner and API key, as the reconciler's):
//!    - the node must still be what was decided on, and still active, just before the provider is
//!      asked (another release, or the reconciler, may have ended it);
//!    - the provider destroys the machine, recorded first (`placement.node_release_destroying`): a
//!      later release that finds it gone after one that never finished knows a release destroyed
//!      it. A failure is audited `placement.node_release_failed`, and the node and its services are
//!      as they were;
//!    - the node is marked released, with the decision and whether this release destroyed it in the
//!      row ([`released_detail`]). If something else ended it first, that is audited
//!      (`placement.node_release_already_ended`) and nothing more is done;
//!    - then, each step tried whatever the others did (`cleanup`): its service instances are
//!      stopped as the reconciler stops them (`service.instance_stopped`); only on a confirmed
//!      destroy are the run files that went with it forgotten; the runs still running on it are
//!      ended as lost (`reconcile.run_lost`) and revoked; its enrolment is revoked last, and only
//!      once the rest is done, so its name can't be given to another machine until then;
//!    - `placement.node_released` (with `by`, the decision's sequence, what was stopped, revoked,
//!      ended and lost). A step that failed is recorded with the rest as
//!      `placement.node_release_incomplete`.
//! 3. [`finish_incomplete`] finishes a release whose ledger side didn't (a failed step, or a crash
//!    after the node was marked released): `wicket node release` on the node runs it, and the
//!    reconciler runs it for every recent release ([`finish_released`]). It decides from the
//!    ledger, not the audit log: what the released node still has ([`Left`]), counting only runs,
//!    instances, files and an enrolment from before the release ended, so a machine given its name
//!    since is never touched (`placement.node_release_finished`).

use crate::grant::Granter;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wicket_core::TenantId;
use wicket_placement::{NodeId, Placer, Provider, ReleaseMode, Released, SpendApprover};
use wicket_store::Ledger;

/// The risk a release is decided at: it destroys running boxes and work a fetch didn't collect.
pub const RISK: i64 = 4;

/// A placed node as a decider is shown it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PastLease {
    /// The provider's instance id.
    pub id: String,
    pub name: String,
    pub backend: String,
    pub lease_until: i64,
    /// Whether its lease has ended.
    pub past_lease: bool,
    /// Runs still running on it (service instances aside: they never hold a node).
    pub running: Vec<String>,
    /// Live service instances on it, as `service:run`: stopped once the provider has destroyed it.
    pub services: Vec<String>,
    /// Ended runs whose files on it a fetch didn't bring back: they go with it.
    pub uncollected: Vec<String>,
    /// The vault secret with the provider API key it was made with, and the owner tag's name.
    pub api_key_secret: String,
    pub owner: String,
}

impl PastLease {
    /// What releasing it does, as the decider is shown it and signs.
    pub fn effect(&self) -> Value {
        json!({
            "v": 2, "kind": "node_release", "id": self.id, "name": self.name, "backend": self.backend,
            "lease_until": self.lease_until, "running": self.running, "services": self.services, "uncollected": self.uncollected,
        })
    }

    pub fn effect_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.effect().to_string().as_bytes()))
    }

    /// What releasing it does, in words.
    pub fn consequence(&self) -> String {
        let mut what = vec![format!("destroys server {} now", self.name)];
        if !self.running.is_empty() {
            what.push(format!(
                "stops the boxes of run {} still running there and ends those runs as lost (revoking the ones with an identity)",
                self.running.join(", ")
            ));
        }
        if !self.services.is_empty() {
            what.push(format!("stops the service instances {} there", self.services.join(", ")));
        }
        if !self.uncollected.is_empty() {
            what.push(format!("loses the files of run {} that a fetch didn't bring back", self.uncollected.join(", ")));
        }
        what.push("revokes its enrolment".into());
        what.join(", ")
    }
}

/// Placed node `id` (its instance id, or the name `wicket node create` gave it) as it is now, if it
/// is active.
pub fn view(l: &Ledger, id: &str, now: i64) -> Result<Option<PastLease>> {
    let Some(row) = l.placed_nodes(&["active"])?.into_iter().find(|r| r.id == id || r.name == id) else { return Ok(None) };
    let instances: Vec<wicket_store::Instance> = l.live_service_instances()?;
    let running: Vec<String> = l.running_runs_on_node(&row.name)?.into_iter().filter(|r| !instances.iter().any(|i| &i.run == r)).collect();
    let services: Vec<String> = instances.iter().filter(|i| i.node == row.name).map(|i| format!("{}:{}", i.service, i.run)).collect();
    let uncollected: Vec<String> = l.uncollected_runs_on_node(&row.name)?.into_iter().filter(|r| !running.contains(r)).collect();
    Ok(Some(PastLease {
        past_lease: row.lease_until <= now,
        id: row.id,
        name: row.name,
        backend: row.backend,
        lease_until: row.lease_until,
        running,
        services,
        uncollected,
        api_key_secret: row.api_key_secret,
        owner: row.owner,
    }))
}

/// Who decides a release.
pub enum Decider<'a> {
    /// An operator: only within its authority. From the console, only a node past its lease.
    Operator { by: &'a Granter, console: bool },
    /// Root on the control host (`wicket node release`): any owned node. Its label, and its
    /// operator identity if it can be told.
    Root { label: String, identity: Option<String> },
}

impl Decider<'_> {
    pub fn label(&self) -> String {
        match self {
            Decider::Operator { by, .. } => by.label(),
            Decider::Root { label, .. } => label.clone(),
        }
    }
}

/// How a release was decided.
pub struct Decision<'a> {
    pub by: Decider<'a>,
    /// The sha256 of the effect the decider was shown ([`PastLease::effect_sha256`]).
    pub shown: &'a str,
    pub why: &'a str,
    /// More for the decision's audit record (`via`, the signed passkey assertion).
    pub extra: Value,
}

/// Whether `by` may release a placed node: a human whose authority covers `capacity` at R4.
pub fn may_decide(by: &Granter) -> Result<crate::operators::Operator> {
    let Granter::Human(o) = by else { bail!("a node is released by a human operator, not {}", by.label()) };
    o.may_decide(&crate::operators::Asked { kind: "capacity".into(), host: String::new(), risk: Some(RISK) })
        .map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

fn refused(l: &Ledger, d: &Decision, id: &str, why: anyhow::Error) -> anyhow::Error {
    let record = json!({ "target": id, "decision": "release_node", "by": d.by.label(), "why": format!("{why:#}") });
    match l.audit(&TenantId::single(), None, "decision.refused", &record) {
        Ok(_) => why.context("refused (the refusal is on the audit record)"),
        Err(e) => why.context(format!("refused (the refusal could not be recorded: {e})")),
    }
}

/// Decides to release placed node `id` as `d` says, and audits the decision before anything is
/// released. Returns the node as decided on and the decision's audit sequence, which [`release`]
/// records with the release.
pub fn decide(l: &Ledger, id: &str, d: &Decision, now: i64) -> Result<(PastLease, i64)> {
    let (granter, identity, console) = match &d.by {
        Decider::Root { identity, .. } => ("root", identity.clone(), false),
        Decider::Operator { by, console } => match may_decide(by) {
            Ok(o) => ("human", Some(o.id), *console),
            Err(why) => return Err(refused(l, d, id, why)),
        },
    };
    let Some(n) = view(l, id, now)? else {
        return Err(refused(l, d, id, anyhow::anyhow!("no active placed node {id}")));
    };
    if console && !n.past_lease {
        return Err(refused(l, d, id, anyhow::anyhow!("{}'s lease hasn't ended: it is released at its end", n.name)));
    }
    let effect = n.effect_sha256();
    if d.shown != effect {
        return Err(refused(
            l,
            d,
            id,
            anyhow::anyhow!(
                "{} changed after you were shown it (its runs, its services or its lease): look again before releasing it",
                n.name
            ),
        ));
    }
    let mut record = json!({
        "decision": "release_node", "id": n.id, "name": n.name, "backend": n.backend, "lease_until": n.lease_until,
        "past_lease": n.past_lease, "running": n.running, "services": n.services, "uncollected": n.uncollected,
        "effect_sha256": effect, "by": d.by.label(), "granter": granter, "granter_identity": identity, "why": d.why,
    });
    if let (Some(r), Value::Object(x)) = (record.as_object_mut(), d.extra.clone()) {
        r.extend(x);
    }
    let seq = l
        .audit(&TenantId::single(), None, "placement.node_release_decided", &record)
        .context("the decision could not be recorded in the audit log, so nothing was released")?;
    Ok((n, seq))
}

/// Releases placed node `n` with `p`, the node's own placer ([`crate::nodecreate::release_placer`]
/// with its owner and API key), after [`decide`] recorded decision `seq`. See the module's header
/// for the steps. `retire` revokes the enrolment of the machine named so, enrolled by the time given
/// ([`crate::nodecreate::retire_enrolment_named`]). Returns what happened, in words.
pub async fn release<Q: Provider, A: SpendApprover>(
    l: &mut Ledger,
    p: &Placer<Q, A>,
    n: &PastLease,
    by: &str,
    seq: i64,
    retire: Retire,
    now: i64,
) -> Result<String> {
    let failed = |l: &Ledger, kind: &str, e: &str| {
        let _ = l.audit(&TenantId::single(), None, kind, &json!({ "id": n.id, "name": n.name, "by": by, "decision": seq, "error": e }));
    };
    // Still what was decided on, and still active: another release, or the reconciler, may have
    // ended it, or a run started on it, since.
    match view(l, &n.id, now)? {
        Some(now_n) if now_n.effect_sha256() == n.effect_sha256() => {}
        Some(_) => {
            failed(l, "placement.node_release_failed", "it changed after the decision (its runs, its services or its lease)");
            bail!("{} changed after it was decided on: nothing was released; decide again", n.name);
        }
        None => {
            failed(l, "placement.node_release_already_ended", "it was no longer an active placed node");
            bail!("{} was already released or ended", n.name);
        }
    }
    // Its service instances are stopped once the provider has answered (in `finish`), not before: a
    // release the provider refuses leaves the node, and them, as they were.
    let id = NodeId(n.id.clone());
    let node = match p.get(&id).await {
        Ok(node) => node,
        Err(e) => {
            failed(l, "placement.node_release_failed", &e.to_string());
            bail!("releasing {}: {e} (it is as it was)", n.name);
        }
    };
    // That the provider is asked to destroy a machine it has, before it is (#812 review): if the
    // destroy works but the node isn't then marked released (its process stops, or the write
    // fails), the next release finds the machine gone, and this record says a release destroyed
    // it. Only once the provider says the machine is there: a release that finds it gone already
    // destroyed nothing, and records nothing that says it did.
    let asking = match &node {
        Some(_) => Some(
            l.audit(
                &TenantId::single(),
                None,
                "placement.node_release_destroying",
                &json!({ "id": n.id, "name": n.name, "by": by, "decision": seq }),
            )
            .context("the release could not be recorded in the audit log, so nothing was released")?,
        ),
        None => None,
    };
    let r = match p.release(&id, ReleaseMode::Now).await {
        Ok(r) => r,
        Err(e) => {
            failed(l, "placement.node_release_failed", &e.to_string());
            bail!("releasing {}: {e} (it is as it was)", n.name);
        }
    };
    // Destroyed by this release, or by an earlier one that found the machine, asked the provider
    // and never finished; otherwise its own placer saw it gone, or never had it, and nothing was
    // destroyed by a release (a machine the provider says is gone may be another account's).
    let gone = r == Released::AlreadyGone || node.is_none();
    let destroyed = !gone || destroyed_before(l, &n.id, asking.unwrap_or(i64::MAX))?;
    // `finish` records its own failures, once.
    finish(l, n, by, seq, destroyed, r, retire)
}

/// Whether an earlier release of placed node `id` (before audit record `before`) asked the provider
/// to destroy it (`placement.node_release_destroying`) and wasn't told no: no
/// `placement.node_release_failed` for its decision came after. That release's destroy may have
/// worked with nothing after it written, so a machine gone since was destroyed by it.
fn destroyed_before(l: &Ledger, id: &str, before: i64) -> Result<bool> {
    let of = |kind: &str| -> Result<Vec<(i64, Value)>> {
        Ok(l.audit_of_kind(kind)?
            .into_iter()
            .filter_map(|r| serde_json::from_str::<Value>(&r.body).ok().filter(|b| b["id"].as_str() == Some(id)).map(|b| (r.seq, b)))
            .collect())
    };
    let failed = of("placement.node_release_failed")?;
    Ok(of("placement.node_release_destroying")?
        .iter()
        .any(|(seq, b)| *seq < before && !failed.iter().any(|(at, f)| at > seq && f["decision"] == b["decision"])))
}

/// Revokes the enrolment of the machine named so if it was enrolled by the time given, so it is the
/// released machine and not one enrolled under its name since. Whether it revoked.
pub type Retire = fn(&mut Ledger, &str, i64) -> Result<bool>;

/// What a released node is recorded as released with, in its row (with the status, in one write):
/// the decision and whether this release destroyed it, which a retry reads ([`finish_incomplete`]).
pub fn released_detail(by: &str, seq: i64, destroyed: bool) -> String {
    format!("released by {by} (decision {seq}, {})", if destroyed { "destroyed" } else { "already gone" })
}

/// The decision and whether it was destroyed, from a row [`released_detail`] wrote. None for a node
/// released another way (the reconciler at its lease's end, or a machine the ledger didn't track).
fn parse_released(detail: &str) -> Option<(i64, bool)> {
    let (seq, how) = detail.rsplit_once(" (decision ")?.1.strip_suffix(')')?.split_once(", ")?;
    let destroyed = match how {
        "destroyed" => true,
        "already gone" => false,
        _ => return None,
    };
    Some((seq.parse().ok()?, destroyed))
}

/// What a node released at `until` still has in the ledger: what its release, or a retry, has left
/// to undo. Only what was there by `until` counts: runs (by when they started), service instances,
/// files and an enrolment under its name from later are a machine's given its name since.
pub struct Left {
    /// Its runs still running (service instances aside).
    pub runs: Vec<String>,
    pub instances: Vec<wicket_store::Instance>,
    /// Ended runs whose files on it a fetch didn't bring back.
    pub uncollected: Vec<String>,
    /// Whether its enrolment is still live.
    pub enrolled: bool,
}

impl Left {
    /// Nothing left for a release (one that `destroyed` the machine also forgets its files).
    pub fn is_empty(&self, destroyed: bool) -> bool {
        self.runs.is_empty() && self.instances.is_empty() && (!destroyed || self.uncollected.is_empty()) && !self.enrolled
    }
}

/// What node `name`, released at `until`, still has ([`Left`]).
///
/// A run counts by when it started, not when it was placed (which isn't recorded), so a run started
/// before the release and placed after it on a machine given the name since would look like the
/// released machine's. It can't be: placing a run on a machine needs it enrolled, enrolling a name
/// needs its old enrolment revoked, and a release revokes the enrolment only once everything else
/// is done (`cleanup`). So once the name is enrolled again after `until`, nothing on it is the
/// released machine's, and nothing counts but that machine's own enrolment, which is gone.
pub fn left(l: &Ledger, name: &str, until: i64) -> Result<Left> {
    // Whatever its status now: a machine enrolled again and then revoked leaves its row (enrolling
    // replaces the name's row), and what ran on it is still not the released machine's.
    let enrolment = l.node(name)?;
    if enrolment.as_ref().is_some_and(|r| r.enrolled_at > until) {
        return Ok(Left { runs: vec![], instances: vec![], uncollected: vec![], enrolled: false });
    }
    let enrolled = enrolment.is_some_and(|r| r.status != "revoked" && r.enrolled_at <= until);
    // Service instances are runs too, stopped as instances and never ended as lost: one stopped
    // (revoked) is no longer live while its run still reads as running, so any instance's run is
    // left out, live or not.
    let live = l.live_service_instances()?;
    let mut runs = vec![];
    for r in l.running_runs_on_node_started_by(name, until)? {
        if l.service_instance_of(&r)?.is_none() {
            runs.push(r);
        }
    }
    let instances = live.into_iter().filter(|i| i.node == name && i.started_at <= until).collect();
    let uncollected = l.uncollected_runs_on_node_started_by(name, until)?;
    Ok(Left { runs, instances, uncollected, enrolled })
}

/// What the ledger still had to do after a release's destroy, best effort: every step is tried, and
/// what failed is returned rather than stopping the rest.
struct Cleanup {
    stopped: Vec<String>,
    lost: usize,
    revoked: Vec<String>,
    ended: Vec<String>,
    retired: bool,
    errors: Vec<String>,
}

/// The ledger's side of placed node `name`, destroyed (or gone) and marked released at `until`: what
/// it still has ([`left`]) undone. Its service instances stopped, its uncollected run files
/// forgotten (only if this release `destroyed` it), the runs still running on it ended as lost (and
/// revoked if they have an identity), and last its enrolment retired, only if all that worked. The
/// other steps are each tried whatever the others did; a run that ended in the meantime is left as
/// it ended, and one revoked already isn't revoked again. If what it has can't be read, nothing is
/// done (a service run would be taken for an agent's and ended as lost).
fn cleanup(l: &mut Ledger, name: &str, until: i64, by: &str, seq: Option<i64>, destroyed: bool, retire: Retire) -> Cleanup {
    let mut c = Cleanup { stopped: vec![], lost: 0, revoked: vec![], ended: vec![], retired: false, errors: vec![] };
    let why = format!("its node {name} was released");
    let left = match left(l, name, until) {
        Ok(x) => x,
        Err(e) => {
            c.errors.push(format!("reading what is on it: {e:#}"));
            return c;
        }
    };
    // Its service instances went with it: stopped as the reconciler stops them (#579), audited.
    for i in &left.instances {
        match crate::services::stop(l, i, &why) {
            Ok(true) => c.stopped.push(i.run.clone()),
            Ok(false) => {}
            Err(e) => c.errors.push(format!("stopping service instance {}: {e:#}", i.run)),
        }
    }
    // Files of runs a fetch didn't bring back went with it (#300): a human chose that. Only when a
    // release destroyed it (this one, or an earlier one that asked the provider and never finished,
    // `destroyed_before`): a machine the provider says is gone may be another account's.
    if destroyed {
        match l.forget_uncollected_on_node_started_by(name, until) {
            Ok(n) => c.lost = n,
            Err(e) => c.errors.push(format!("forgetting its uncollected run files: {e:#}")),
        }
    }
    // Its runs' boxes went with the machine: each run still running there is ended as lost (its
    // agent handed back, as a lost run's is, and `run.lost` triggers fire), and revoked if it has an
    // identity. One transaction (#812 review): a run that ended on its own meanwhile (during the
    // provider call, say) keeps how it ended and isn't revoked; one this ends is revoked and both
    // are audited, or none of it is done and a retry finds the run still running.
    for run in left.runs {
        let revoked = std::cell::Cell::new(false);
        let r = l.run_lost_if_running(&run, &why, |l| {
            let rid = wicket_core::RunId(run.clone());
            if l.identity(&run)?.is_some() && l.revoke(&run, by, &why)? {
                l.audit(
                    &TenantId::single(),
                    Some(&rid),
                    "identity.revoked",
                    &json!({ "run": run, "by": by, "reason": why, "decision": seq }),
                )?;
                revoked.set(true);
            }
            l.audit(
                &TenantId::single(),
                Some(&rid),
                "reconcile.run_lost",
                &json!({ "target": run, "detail": why, "by": by, "decision": seq }),
            )?;
            Ok(())
        });
        let r = r.map(|ended| {
            if ended {
                c.ended.push(run.clone());
                if revoked.get() {
                    c.revoked.push(run.clone());
                }
            }
        });
        if let Err(e) = r {
            c.errors.push(format!("ending run {run}: {e:#}"));
        }
    }
    // Last, and only once the rest is done: while it is enrolled, its name can't be enrolled again,
    // so nothing on that name is a new machine's until its release is finished ([`left`]).
    if !c.errors.is_empty() {
        c.errors.push("its enrolment is kept until the rest is done (finishing the release revokes it)".into());
        return c;
    }
    match retire(l, name, until) {
        Ok(r) => c.retired = r,
        Err(e) => c.errors.push(format!("revoking its enrolment: {e:#}")),
    }
    c
}

/// Records what a cleanup did (`placement.node_released`, or `placement.node_release_finished` for a
/// retry) and, if any step failed, `placement.node_release_incomplete`. Returns what happened, in
/// words, or Err if a step failed.
#[allow(clippy::too_many_arguments)]
fn record(
    l: &Ledger,
    kind: &str,
    id: &str,
    name: &str,
    by: &str,
    seq: Option<i64>,
    destroyed: bool,
    c: &Cleanup,
    mut said: String,
) -> Result<String> {
    if c.lost > 0 {
        said.push_str(&format!("; {} run(s)' uncollected files went with it", c.lost));
    }
    if !c.stopped.is_empty() {
        said.push_str(&format!("; stopped service instance {}", c.stopped.join(", ")));
    }
    if !c.ended.is_empty() {
        said.push_str(&format!("; ended run {} as lost", c.ended.join(", ")));
    }
    if c.retired {
        said.push_str(&format!("; revoked node {name}"));
    }
    let rec = json!({ "id": id, "name": name, "uncollected_runs_lost": c.lost, "by": by, "decision": seq, "destroyed": destroyed,
                      "services_stopped": c.stopped, "runs_revoked": c.revoked, "runs_ended": c.ended, "enrolment_retired": c.retired,
                      "errors": c.errors });
    let wrote = l.audit(&TenantId::single(), None, kind, &rec);
    if c.errors.is_empty() {
        wrote?;
        return Ok(said);
    }
    // A record only: a retry decides from the ledger, so a failed write here loses nothing.
    let _ = l.audit(
        &TenantId::single(),
        None,
        "placement.node_release_incomplete",
        &json!({ "id": id, "name": name, "by": by, "decision": seq, "destroyed": destroyed, "errors": c.errors }),
    );
    bail!("{said}; but the release didn't finish: {} (run `wicket node release {id}` again to finish it)", c.errors.join("; "))
}

/// Finishes the release of placed node `id` (its instance id) if its ledger side didn't finish: a
/// step failed, or the process stopped after the node was marked released. Decided from the ledger
/// ([`left`]): what the node still has from before its release ended, undone as `cleanup` does.
/// `wicket node release` runs it for a released node, and the reconciler for recent ones
/// ([`finish_released`]). Ok(None) if there is nothing left to do; Err if a step fails again.
pub fn finish_incomplete(l: &mut Ledger, id: &str, by: &str, retire: Retire) -> Result<Option<String>> {
    let row = l.placed_node(id)?.with_context(|| format!("no placed node {id}"))?;
    if row.status != "released" {
        bail!("placed node {id} is {}, not a release to finish", row.status);
    }
    let until = row.ended_at.with_context(|| format!("placed node {id} is released but has no end time"))?;
    // A release this module made says how; one made another way destroyed nothing it can tell.
    let (seq, destroyed) = match row.detail.as_deref().and_then(parse_released) {
        Some((seq, destroyed)) => (Some(seq), destroyed),
        None => (None, false),
    };
    if left(l, &row.name, until)?.is_empty(destroyed) {
        return Ok(None);
    }
    let name = row.name;
    let c = cleanup(l, &name, until, by, seq, destroyed, retire);
    record(l, "placement.node_release_finished", id, &name, by, seq, destroyed, &c, format!("finished releasing {name}")).map(Some)
}

/// A release that ended under this long ago may still be finishing: the reconciler leaves it.
pub const FINISH_GRACE_SECS: i64 = 120;
/// A retry that failed under this long ago isn't tried again by the reconciler yet.
pub const FINISH_RETRY_SECS: i64 = 600;
/// How far back the reconciler looks for releases to finish.
pub const FINISH_WINDOW_SECS: i64 = 7 * 24 * 3600;

/// The reconciler's part (#812 review): every node a release of this module's marked released in the
/// last [`FINISH_WINDOW_SECS`] whose ledger side isn't done is finished ([`finish_incomplete`], as
/// `by`). One that ended under [`FINISH_GRACE_SECS`] ago is left (its release may still be running),
/// as is one whose last try failed under [`FINISH_RETRY_SECS`] ago. Returns each node tried (its
/// instance id) and what happened; with `dry_run`, what would be tried, and nothing is.
pub fn finish_released(l: &mut Ledger, by: &str, retire: Retire, now: i64, dry_run: bool) -> Result<Vec<(String, Result<String>)>> {
    let mut todo = vec![];
    for row in l.placed_nodes(&["released"])? {
        let (Some(until), Some((_, destroyed))) = (row.ended_at, row.detail.as_deref().and_then(parse_released)) else { continue };
        if until > now - FINISH_GRACE_SECS || until < now - FINISH_WINDOW_SECS || left(l, &row.name, until)?.is_empty(destroyed) {
            continue;
        }
        todo.push(row);
    }
    if todo.is_empty() {
        return Ok(vec![]);
    }
    let failed: Vec<(i64, String)> = l
        .audit_of_kind("placement.node_release_incomplete")?
        .into_iter()
        .filter(|r| r.ts > now - FINISH_RETRY_SECS)
        .filter_map(|r| serde_json::from_str::<Value>(&r.body).ok()?["id"].as_str().map(|id| (r.ts, id.to_string())))
        .collect();
    let mut done = vec![];
    for row in todo.into_iter().filter(|r| !failed.iter().any(|(_, id)| id == &r.id)) {
        let r = if dry_run {
            Ok(format!("would finish releasing placed node {}", row.name))
        } else {
            finish_incomplete(l, &row.id, by, retire).map(|s| s.unwrap_or_else(|| format!("placed node {}: nothing left to do", row.name)))
        };
        done.push((row.id, r));
    }
    Ok(done)
}

/// After the provider answered: the ledger's side of a release.
fn finish(l: &mut Ledger, n: &PastLease, by: &str, seq: i64, destroyed: bool, r: Released, retire: Retire) -> Result<String> {
    let id = &n.id;
    let mut said = if destroyed { format!("{id}: {r:?}") } else { format!("{id} was already gone") };
    // Marked released with how, in one write: a retry reads it from the row.
    match l.placed_node_ended(id, "released", &released_detail(by, seq, destroyed)) {
        Ok(true) => {}
        Ok(false) => {
            // Something else (another release, the reconciler) ended it first: it records the rest.
            l.audit(
                &TenantId::single(),
                None,
                "placement.node_release_already_ended",
                &json!({ "id": id, "name": n.name, "by": by, "decision": seq, "destroyed": destroyed }),
            )?;
            said.push_str("; it had already been ended by another release, which recorded the rest");
            return Ok(said);
        }
        Err(e) => {
            let _ = l.audit(
                &TenantId::single(),
                None,
                "placement.node_release_incomplete",
                &json!({ "id": id, "name": n.name, "by": by, "decision": seq, "destroyed": destroyed,
                         "errors": [format!("marking it released: {e:#}")] }),
            );
            return Err(anyhow::Error::from(e).context(format!("{said}; but it couldn't be marked released")));
        }
    }
    let until = l.placed_node(id).ok().flatten().and_then(|r| r.ended_at).unwrap_or_else(wicket_store::now);
    // The ledger's name for it: its runs, services and files are recorded under it.
    let c = cleanup(l, &n.name, until, by, Some(seq), destroyed, retire);
    record(l, "placement.node_released", id, &n.name, by, Some(seq), destroyed, &c, said)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{Operator, Policy};
    use wicket_placement::mock as vultr_mock;
    use wicket_store::PlacedNodeRow;

    const NOW: i64 = 1_700_000_000;

    fn placed(l: &Ledger, id: &str, name: &str, end: i64) {
        l.record_placed_node(&PlacedNodeRow {
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

    fn human(policy: &str) -> Granter {
        Granter::Human(Operator::new("default", "passkey", "laptop", "passkey:laptop".into(), &Policy::parse(policy).unwrap()))
    }

    fn console<'a>(by: &'a Granter, shown: &'a str) -> Decision<'a> {
        Decision { by: Decider::Operator { by, console: true }, shown, why: "done with it", extra: json!({ "via": "console" }) }
    }

    fn kinds(l: &Ledger) -> Vec<String> {
        l.audit_tail(100).unwrap().into_iter().map(|r| r.2).collect()
    }

    fn no_retire(_: &mut Ledger, _: &str, _: i64) -> Result<bool> {
        Ok(false)
    }

    fn running(l: &Ledger, run: &str, node: &str) {
        l.run_started(&TenantId::single(), &wicket_core::RunId(run.into()), "z", "a").unwrap();
        l.set_run_node(run, node).unwrap();
        l.put_identity(&wicket_store::IdentityRow {
            run: run.into(),
            tenant: TenantId::single().0,
            spiffe_id: format!("spiffe://w.test/t/{run}"),
            zone: "z".into(),
            agent: "a".into(),
            parent_run: None,
            accept_from: vec![],
            jws: "x.y.z".into(),
            issued_at: NOW,
        })
        .unwrap();
    }

    /// Enrols a machine as node `name`, enrolled at `at`.
    fn enrol(l: &mut Ledger, name: &str, at: i64) {
        let t = l.create_node_token(&TenantId::single(), name, 3600).unwrap();
        let row = wicket_store::NodeRow {
            name: name.into(),
            tenant: TenantId::single().0,
            target: "wicket@203.0.113.7".into(),
            host_key: "ssh-ed25519 AAAA".into(),
            host_key_fp: "SHA256:x".into(),
            node_key: "00".repeat(32),
            ssh_key: None,
            hosts: vec![],
            enrolled_at: at,
            status: "active".into(),
            revoked_at: None,
        };
        let ca = wicket_store::NodeCaRow {
            serial: format!("{name}-{at}"),
            node: name.into(),
            issued_at: at,
            not_after: at + 3600,
            hosts: vec![],
            status: "active".into(),
        };
        l.enrol_node(&t, &row, &ca).unwrap();
    }

    /// Revokes node `name`'s enrolment in the ledger, as the real retire does (without its files).
    fn retire_in_ledger(l: &mut Ledger, name: &str, until: i64) -> Result<bool> {
        if !l.node(name)?.is_some_and(|r| r.status != "revoked" && r.enrolled_at <= until) {
            return Ok(false);
        }
        l.revoke_node(name)?;
        Ok(true)
    }

    async fn mock(
        ids: &[(&str, bool)],
    ) -> (Placer<wicket_placement::vultr::VultrProvider, wicket_placement::envelope::DenyAll>, vultr_mock::Shared) {
        use wicket_placement::vultr::*;
        let (base, st) = vultr_mock::serve().await;
        let o = wicket_placement::Owner::new("example");
        for (id, owned) in ids {
            let tags = if *owned { vec![o.tag()] } else { vec![] };
            st.lock().unwrap().instances.push(vultr_mock::instance(id, &tags));
        }
        let c = Client::with_base(&base, ApiKey::new(vultr_mock::KEY))
            .unwrap()
            .with_retry(Retry { attempts: 1, base: std::time::Duration::from_millis(1) });
        (Placer::new(VultrProvider::new(c, VultrConfig::default()), wicket_placement::envelope::DenyAll, o), st)
    }

    fn deleted(st: &vultr_mock::Shared, id: &str) -> bool {
        st.lock().unwrap().seen.iter().any(|s| s.method == "DELETE" && s.path.ends_with(&format!("/{id}")))
    }

    /// The release itself, against the Vultr API mock: its service instances are stopped, the
    /// machine is deleted, its runs revoked and the release recorded with its decision; a machine
    /// without the owner tag is left, and that is audited.
    #[tokio::test]
    async fn a_decided_release_stops_its_services_destroys_the_node_and_a_failed_one_leaves_it() {
        let (p, st) = mock(&[("i-1", true), ("i-2", false)]).await;
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-1", "placed-a", NOW - 60);
        placed(&l, "i-2", "placed-b", NOW - 60);
        running(&l, "run_busy", "placed-a");
        running(&l, "run_svc", "placed-a");
        l.record_service_instance("run_svc", "cache", "placed-a", &TenantId::single().0, "sha", NOW).unwrap();
        // A run with no identity (a program's, say) is on it too.
        l.run_started(&TenantId::single(), &wicket_core::RunId("run_anon".into()), "z", "p").unwrap();
        l.set_run_node("run_anon", "placed-a").unwrap();
        // And a service instance on the machine whose release will fail.
        running(&l, "run_svc_b", "placed-b");
        l.record_service_instance("run_svc_b", "cache", "placed-b", &TenantId::single().0, "sha", NOW).unwrap();
        let by = human("default: anything\n");

        let n = view(&l, "i-1", NOW).unwrap().unwrap();
        assert_eq!(
            (n.running.clone(), n.services.clone()),
            (vec!["run_anon".to_string(), "run_busy".to_string()], vec!["cache:run_svc".to_string()])
        );
        assert!(n.consequence().contains("stops the service instances cache:run_svc"), "{}", n.consequence());
        let (n, seq) = decide(&l, "i-1", &console(&by, &n.effect_sha256()), NOW).unwrap();
        let said = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.unwrap();
        assert!(said.contains("i-1") && said.contains("ended run run_anon, run_busy as lost"), "{said}");
        assert!(deleted(&st, "i-1"));
        assert_eq!(l.placed_node("i-1").unwrap().unwrap().status, "released");
        assert!(l.revoked("run_busy").unwrap().is_some() && l.revoked("run_svc").unwrap().is_some());
        for run in ["run_busy", "run_anon"] {
            assert_eq!(l.run_status(run).unwrap().as_deref(), Some("lost"), "{run} is ended, identity or not");
        }
        let ks = kinds(&l);
        let stop = ks.iter().position(|k| k == "service.instance_stopped").expect("the instance is stopped");
        assert!(stop < ks.iter().position(|k| k == "placement.node_released").unwrap());
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!(rec.2, "placement.node_released");
        let b: Value = serde_json::from_str(&rec.4).unwrap();
        assert_eq!(
            (b["decision"].as_i64(), b["by"].as_str(), b["destroyed"].as_bool()),
            (Some(seq), Some("passkey:laptop"), Some(true)),
            "{b}"
        );
        assert_eq!(
            (b["services_stopped"].clone(), b["runs_revoked"].clone(), b["runs_ended"].clone()),
            (json!(["run_svc"]), json!(["run_busy"]), json!(["run_anon", "run_busy"]))
        );

        // A second release of the same node (another tab): it is no longer an active placed node.
        let e = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.unwrap_err();
        assert!(format!("{e:#}").contains("already released"), "{e:#}");
        assert_eq!(st.lock().unwrap().seen.iter().filter(|s| s.method == "DELETE").count(), 1, "deleted once");

        let shown = view(&l, "i-2", NOW).unwrap().unwrap().effect_sha256();
        let (n, seq) = decide(&l, "i-2", &console(&by, &shown), NOW).unwrap();
        assert!(release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.is_err(), "not this installation's machine");
        assert!(!deleted(&st, "i-2"));
        assert_eq!(l.placed_node("i-2").unwrap().unwrap().status, "active", "it is as it was");
        assert!(l.revoked("run_svc_b").unwrap().is_none(), "its service instance too: stopped only after a release");
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!(rec.2, "placement.node_release_failed");
        assert_eq!(serde_json::from_str::<Value>(&rec.4).unwrap()["decision"].as_i64(), Some(seq));
    }

    /// A machine its own placer finds gone isn't destroyed by this release: its uncollected files
    /// aren't forgotten. A node that changed after the decision (a run started on it) isn't
    /// released, and the provider isn't asked.
    #[tokio::test]
    async fn a_gone_machine_keeps_its_uncollected_runs_and_a_changed_node_isnt_released() {
        let (p, st) = mock(&[("i-3", true)]).await;
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-gone", "placed-g", NOW - 60);
        placed(&l, "i-3", "placed-c", NOW - 60);
        running(&l, "run_files", "placed-g");
        l.run_ended(&wicket_core::RunId("run_files".into()), "ok", "done").unwrap();
        l.set_run_uncollected("run_files", Some("placed-g")).unwrap();
        let by = human("default: anything\n");

        let n = view(&l, "i-gone", NOW).unwrap().unwrap();
        assert_eq!(n.uncollected, ["run_files"]);
        let (n, seq) = decide(&l, "i-gone", &console(&by, &n.effect_sha256()), NOW).unwrap();
        let said = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.unwrap();
        assert!(said.contains("already gone"), "{said}");
        assert_eq!(l.uncollected_runs_on_node("placed-g").unwrap(), ["run_files"], "not forgotten: nothing was destroyed");
        let b: Value = serde_json::from_str(&l.audit_tail(1).unwrap().pop().unwrap().4).unwrap();
        assert_eq!((b["destroyed"].as_bool(), b["uncollected_runs_lost"].as_i64()), (Some(false), Some(0)), "{b}");

        let n = view(&l, "i-3", NOW).unwrap().unwrap();
        let (n, seq) = decide(&l, "i-3", &console(&by, &n.effect_sha256()), NOW).unwrap();
        running(&l, "run_late", "placed-c");
        let e = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.unwrap_err();
        assert!(format!("{e:#}").contains("changed after it was decided on"), "{e:#}");
        assert!(!deleted(&st, "i-3"));
        assert_eq!(l.placed_node("i-3").unwrap().unwrap().status, "active");
    }

    /// #812 review: a step after the node was marked released that fails doesn't stop the rest; it is
    /// recorded as incomplete, and a retry finishes it. A run that ended on its own meanwhile keeps
    /// how it ended.
    #[tokio::test]
    async fn a_release_that_doesnt_finish_is_recorded_and_a_retry_finishes_it() {
        let (p, _st) = mock(&[("i-1", true)]).await;
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-1", "placed-a", NOW - 60);
        enrol(&mut l, "placed-a", NOW - 600);
        running(&l, "run_a", "placed-a");
        let by = human("default: anything\n");
        let n = view(&l, "i-1", NOW).unwrap().unwrap();
        let (n, seq) = decide(&l, "i-1", &console(&by, &n.effect_sha256()), NOW).unwrap();
        fn broken(_: &mut Ledger, _: &str, _: i64) -> Result<bool> {
            anyhow::bail!("the enrolment couldn't be revoked")
        }
        let e = release(&mut l, &p, &n, "passkey:laptop", seq, broken, NOW).await.unwrap_err();
        assert!(format!("{e:#}").contains("didn't finish") && format!("{e:#}").contains("again to finish it"), "{e:#}");
        // Everything else was done.
        assert_eq!(l.placed_node("i-1").unwrap().unwrap().status, "released");
        assert_eq!(l.run_status("run_a").unwrap().as_deref(), Some("lost"));
        let ks = kinds(&l);
        assert!(ks.contains(&"placement.node_released".to_string()), "{ks:?}");
        assert!(ks.contains(&"reconcile.run_lost".to_string()), "run.lost triggers fire: {ks:?}");
        // Recorded once, with whether it was destroyed (#812 review).
        let incomplete: Vec<Value> =
            l.audit_of_kind("placement.node_release_incomplete").unwrap().iter().map(|r| serde_json::from_str(&r.body).unwrap()).collect();
        assert_eq!(incomplete.len(), 1, "{incomplete:?}");
        assert_eq!(incomplete[0]["destroyed"].as_bool(), Some(true), "{incomplete:?}");
        assert_eq!(l.placed_node("i-1").unwrap().unwrap().detail.as_deref(), Some(released_detail("passkey:laptop", seq, true).as_str()));

        // Its enrolment was kept: revoked only once the rest is done, so the retry has it to do.
        assert_eq!(incomplete[0]["errors"].as_array().map(|e| e.len()), Some(1), "only the enrolment failed: {incomplete:?}");
        assert!(left(&l, "placed-a", l.placed_node("i-1").unwrap().unwrap().ended_at.unwrap()).unwrap().enrolled);

        // A retry finishes it, once: what is left is read from the ledger.
        let said = finish_incomplete(&mut l, "i-1", "alex", retire_in_ledger).unwrap().expect("something to finish");
        assert!(said.contains("revoked node placed-a"), "{said}");
        assert_eq!(l.node("placed-a").unwrap().unwrap().status, "revoked");
        let b: Value = serde_json::from_str(&l.audit_of_kind("placement.node_release_finished").unwrap().pop().unwrap().body).unwrap();
        assert_eq!(
            (b["decision"].as_i64(), b["destroyed"].as_bool(), b["enrolment_retired"].as_bool(), b["errors"].clone()),
            (Some(seq), Some(true), Some(true), json!([])),
            "{b}"
        );
        // Then there is nothing left; the run revoked already isn't revoked, or audited, again.
        assert_eq!(finish_incomplete(&mut l, "i-1", "alex", retire_in_ledger).unwrap(), None);
        assert_eq!(kinds(&l).iter().filter(|k| *k == "identity.revoked").count(), 1);
        fn retire_ok(_: &mut Ledger, _: &str, _: i64) -> Result<bool> {
            Ok(true)
        }
        assert!(format!("{:#}", finish_incomplete(&mut l, "i-9", "alex", retire_ok).unwrap_err()).contains("no placed node"));
    }

    /// #812 review: a release whose process stopped just after the node was marked released (no
    /// record of what is left) is finished by the reconciler from the ledger: the released machine's
    /// runs end as lost, its services stop, its files go (it was destroyed, which the row says). A
    /// machine given the same name since keeps its runs, services and files. Not while the release
    /// may still be running, and not again soon after a retry failed.
    #[tokio::test]
    async fn a_release_stopped_after_it_was_marked_released_is_finished_without_touching_a_new_machine_of_its_name() {
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-1", "placed-a", NOW - 60);
        running(&l, "run_a", "placed-a");
        running(&l, "run_svc", "placed-a");
        l.record_service_instance("run_svc", "cache", "placed-a", &TenantId::single().0, "sha", NOW).unwrap();
        running(&l, "run_files", "placed-a");
        l.run_ended(&wicket_core::RunId("run_files".into()), "ok", "done").unwrap();
        l.set_run_uncollected("run_files", Some("placed-a")).unwrap();
        // The release's destroy, then marking it released, then the process stops.
        assert!(l.placed_node_ended("i-1", "released", &released_detail("passkey:laptop", 7, true)).unwrap());
        let until = l.placed_node("i-1").unwrap().unwrap().ended_at.unwrap();

        // A new machine under the same name, after the release (runs record when they start, by the
        // second).
        std::thread::sleep(std::time::Duration::from_millis(1100));
        placed(&l, "i-9", "placed-a", NOW + 3600);
        running(&l, "run_new", "placed-a");
        running(&l, "run_svc_new", "placed-a");
        l.record_service_instance("run_svc_new", "cache2", "placed-a", &TenantId::single().0, "sha", until + 1).unwrap();
        running(&l, "run_new_files", "placed-a");
        l.run_ended(&wicket_core::RunId("run_new_files".into()), "ok", "done").unwrap();
        l.set_run_uncollected("run_new_files", Some("placed-a")).unwrap();
        let left_now = left(&l, "placed-a", until).unwrap();
        assert_eq!(
            (left_now.runs.clone(), left_now.uncollected.clone(), left_now.instances.iter().map(|i| i.run.clone()).collect::<Vec<_>>()),
            (vec!["run_a".to_string()], vec!["run_files".to_string()], vec!["run_svc".to_string()])
        );

        let now = wicket_store::now();
        // Just released: its release may still be finishing.
        assert!(finish_released(&mut l, "wicket reconcile", no_retire, now, false).unwrap().is_empty());
        // Later, but a retry failed a moment ago: not yet.
        l.audit(&TenantId::single(), None, "placement.node_release_incomplete", &json!({ "id": "i-1", "errors": ["x"] })).unwrap();
        assert!(finish_released(&mut l, "wicket reconcile", no_retire, now + FINISH_GRACE_SECS + 1, false).unwrap().is_empty());
        let later = now + FINISH_RETRY_SECS + 1;
        let dry = finish_released(&mut l, "wicket reconcile", no_retire, later, true).unwrap();
        assert_eq!((dry.len(), dry[0].0.as_str()), (1, "i-1"));
        assert_eq!(l.run_status("run_a").unwrap().as_deref(), Some("running"), "a dry run does nothing");

        let done = finish_released(&mut l, "wicket reconcile", no_retire, later, false).unwrap();
        assert_eq!(done.len(), 1);
        let said = done[0].1.as_ref().unwrap();
        assert!(said.contains("ended run run_a as lost") && said.contains("stopped service instance run_svc"), "{said}");
        assert_eq!(l.run_status("run_a").unwrap().as_deref(), Some("lost"));
        assert!(l.revoked("run_a").unwrap().is_some());
        assert!(l.uncollected_runs_on_node("placed-a").unwrap() == ["run_new_files"], "only the released machine's files go");
        let b: Value = serde_json::from_str(&l.audit_of_kind("placement.node_release_finished").unwrap().pop().unwrap().body).unwrap();
        assert_eq!(
            (b["decision"].as_i64(), b["destroyed"].as_bool(), b["uncollected_runs_lost"].as_i64(), b["by"].as_str()),
            (Some(7), Some(true), Some(1), Some("wicket reconcile")),
            "{b}"
        );
        // The machine given its name since is untouched.
        assert_eq!(l.run_status("run_new").unwrap().as_deref(), Some("running"));
        assert!(l.revoked("run_new").unwrap().is_none() && l.revoked("run_svc_new").unwrap().is_none());
        assert!(l.live_service_instances().unwrap().iter().any(|i| i.run == "run_svc_new"));
        // A stopped instance stopped again isn't audited again.
        let old_svc = l.service_instance_of("run_svc").unwrap().unwrap();
        crate::services::stop(&l, &old_svc, "again").unwrap();
        assert_eq!(kinds(&l).iter().filter(|k| *k == "service.instance_stopped").count(), 1);
        assert_eq!(l.placed_node("i-9").unwrap().unwrap().status, "active");

        // Finished: nothing left, for the reconciler or `wicket node release`.
        assert!(finish_released(&mut l, "wicket reconcile", no_retire, later + FINISH_RETRY_SECS, false).unwrap().is_empty());
        assert_eq!(finish_incomplete(&mut l, "i-1", "alex", no_retire).unwrap(), None);
        // A node released another way (the reconciler, at its lease's end) isn't the reconciler's to finish.
        assert_eq!(parse_released("its lease ended at x and no run is placed on it"), None);
        assert_eq!(parse_released(&released_detail("root (x)", 3, false)), Some((3, false)));
    }

    /// A run that ends on its own while the provider is asked (after the decision's re-check) keeps
    /// how it ended: only runs still `running` are ended as lost.
    #[test]
    fn a_run_that_ended_meanwhile_isnt_rewritten_as_lost() {
        let mut l = Ledger::open_in_memory().unwrap();
        running(&l, "run_done", "placed-a");
        running(&l, "run_live", "placed-a");
        l.run_ended(&wicket_core::RunId("run_done".into()), "succeeded", "done").unwrap();
        let c = cleanup(&mut l, "placed-a", wicket_store::now(), "alex", Some(1), true, no_retire);
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        assert_eq!(c.ended, ["run_live"]);
        assert_eq!(l.run_status("run_done").unwrap().as_deref(), Some("succeeded"));
        assert!(l.revoked("run_done").unwrap().is_none(), "a run that ended on its own isn't revoked");
        assert!(l.revoked("run_live").unwrap().is_some());
        assert_eq!(l.run_status("run_live").unwrap().as_deref(), Some("lost"));
    }

    #[test]
    fn a_release_is_decided_by_a_human_it_covers_on_the_effect_shown() {
        let l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-1", "placed-a", NOW - 60);
        placed(&l, "i-2", "placed-b", NOW + 3600);
        l.run_started(&TenantId::single(), &wicket_core::RunId("run_busy".into()), "z", "a").unwrap();
        l.set_run_node("run_busy", "placed-a").unwrap();
        let n = view(&l, "placed-a", NOW).unwrap().unwrap();
        assert_eq!((n.id.as_str(), n.past_lease, n.running.clone()), ("i-1", true, vec!["run_busy".to_string()]));
        assert!(n.consequence().contains("stops the boxes of run run_busy"), "{}", n.consequence());
        let shown = n.effect_sha256();

        let anyone = human("default: anything\n");
        for (by, why) in [
            (human("default: nothing\n"), "may decide nothing"),
            (human("default: { kinds: [http] }\n"), "may not decide capacity"),
            (human("default: { kinds: [capacity], max_risk: R3 }\n"), "up to risk R3"),
        ] {
            let e = decide(&l, "i-1", &console(&by, &shown), NOW).unwrap_err();
            assert!(format!("{e:#}").contains(why), "{e:#}");
        }
        let e = decide(&l, "i-2", &console(&anyone, &view(&l, "i-2", NOW).unwrap().unwrap().effect_sha256()), NOW).unwrap_err();
        assert!(format!("{e:#}").contains("lease hasn't ended"), "{e:#}");
        assert!(decide(&l, "i-9", &console(&anyone, &shown), NOW).is_err(), "not a placed node");
        assert_eq!(kinds(&l).iter().filter(|k| *k == "decision.refused").count(), 5, "every refusal is audited");

        // The run ended between being shown and signing: what was shown is stale.
        l.run_ended(&wicket_core::RunId("run_busy".into()), "ok", "done").unwrap();
        let e = decide(&l, "i-1", &console(&anyone, &shown), NOW).unwrap_err();
        assert!(format!("{e:#}").contains("changed after you were shown it"), "{e:#}");
        assert!(!kinds(&l).contains(&"placement.node_release_decided".to_string()));

        let now_shown = view(&l, "i-1", NOW).unwrap().unwrap().effect_sha256();
        let (n, seq) = decide(&l, "i-1", &console(&anyone, &now_shown), NOW).unwrap();
        assert!(n.running.is_empty());
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!((rec.0, rec.2.as_str()), (seq, "placement.node_release_decided"));
        let b: Value = serde_json::from_str(&rec.4).unwrap();
        assert_eq!(b["granter"], "human");
        assert_eq!(b["via"], "console");
        assert_eq!(b["effect_sha256"], now_shown);
        assert_eq!(b["why"], "done with it");
        assert!(b["granter_identity"].as_str().unwrap().ends_with("/op/passkey/laptop"), "{b}");

        // Root on the host releases a node whose lease hasn't ended; an operator on the CLI too,
        // within its authority.
        let shown_b = view(&l, "placed-b", NOW).unwrap().unwrap().effect_sha256();
        let root =
            Decision { by: Decider::Root { label: "root@host".into(), identity: None }, shown: &shown_b, why: "x", extra: json!({}) };
        assert!(decide(&l, "placed-b", &root, NOW).is_ok());
        let cli = Decision { by: Decider::Operator { by: &anyone, console: false }, shown: &shown_b, why: "x", extra: json!({}) };
        assert!(decide(&l, "placed-b", &cli, NOW).is_ok());
    }

    /// #812 and #819 reviews: a release whose destroy worked but which never marked the node released
    /// (its process stopped, or the write failed) leaves the row active; the next release finds the
    /// machine gone, and counts it as destroyed, because the first found the machine and recorded
    /// that it asked the provider. Not when the first found it gone already (nothing recorded), nor
    /// when the provider told the first no. Real releases each time; the row is made active again
    /// between them, as a first release that couldn't mark it released leaves it.
    #[tokio::test]
    async fn a_machine_gone_after_a_release_that_destroyed_it_and_never_finished_counts_as_destroyed() {
        let (p, st) = mock(&[("i-d", true), ("i-r", false)]).await;
        let mut l = Ledger::open_in_memory().unwrap();
        let by = human("default: anything\n");
        let files = |l: &Ledger, name: &str| {
            let run = format!("run_files_{name}");
            if l.run_status(&run).unwrap().is_none() {
                running(l, &run, name);
                l.run_ended(&wicket_core::RunId(run.clone()), "ok", "done").unwrap();
            }
            l.set_run_uncollected(&run, Some(name)).unwrap();
        };
        async fn once(
            l: &mut Ledger,
            p: &Placer<wicket_placement::vultr::VultrProvider, wicket_placement::envelope::DenyAll>,
            by: &Granter,
            id: &str,
        ) -> Result<String> {
            let n = view(l, id, NOW).unwrap().unwrap();
            let (n, seq) = decide(l, id, &console(by, &n.effect_sha256()), NOW).unwrap();
            release(l, p, &n, "passkey:laptop", seq, no_retire, NOW).await
        }
        let destroyed = |l: &Ledger| -> Option<bool> {
            serde_json::from_str::<Value>(&l.audit_of_kind("placement.node_released").unwrap().pop().unwrap().body).unwrap()["destroyed"]
                .as_bool()
        };

        // Gone both times: the first release destroyed nothing and recorded nothing that says so.
        placed(&l, "i-gone", "placed-g", NOW - 60);
        files(&l, "placed-g");
        once(&mut l, &p, &by, "i-gone").await.unwrap();
        assert_eq!(destroyed(&l), Some(false));
        placed(&l, "i-gone", "placed-g", NOW - 60);
        once(&mut l, &p, &by, "i-gone").await.unwrap();
        assert_eq!(destroyed(&l), Some(false), "a second release of a machine no release found isn't a destroy");
        assert_eq!(l.uncollected_runs_on_node("placed-g").unwrap(), ["run_files_placed-g"], "its files are kept");
        let asked = |l: &Ledger, id: &str| {
            l.audit_of_kind("placement.node_release_destroying").unwrap().iter().filter(|r| r.body.contains(&format!("\"{id}\""))).count()
        };
        assert_eq!(asked(&l, "i-gone"), 0);

        // Destroyed by the first, which then couldn't mark it released: the second finds it gone and
        // counts it as destroyed, so the files that went with it go.
        placed(&l, "i-d", "placed-d", NOW - 60);
        once(&mut l, &p, &by, "i-d").await.unwrap();
        assert!(deleted(&st, "i-d"));
        assert_eq!(asked(&l, "i-d"), 1);
        placed(&l, "i-d", "placed-d", NOW - 60);
        files(&l, "placed-d");
        once(&mut l, &p, &by, "i-d").await.unwrap();
        assert_eq!(destroyed(&l), Some(true));
        assert!(l.uncollected_runs_on_node("placed-d").unwrap().is_empty(), "its files went with it");

        // The provider told the first no (not this installation's machine); it is gone by the second.
        placed(&l, "i-r", "placed-r", NOW - 60);
        files(&l, "placed-r");
        assert!(once(&mut l, &p, &by, "i-r").await.is_err());
        assert_eq!(l.placed_node("i-r").unwrap().unwrap().status, "active");
        st.lock().unwrap().instances.retain(|i| i["id"] != "i-r");
        once(&mut l, &p, &by, "i-r").await.unwrap();
        assert_eq!(destroyed(&l), Some(false), "a refused release destroyed nothing");
        assert_eq!(l.uncollected_runs_on_node("placed-r").unwrap(), ["run_files_placed-r"]);
    }

    /// Once the name is enrolled again after the release, nothing on it is the released machine's:
    /// enrolling it needed the old enrolment revoked, which a release does only once the rest is done.
    #[test]
    fn a_name_enrolled_again_since_the_release_leaves_nothing_of_the_released_machine() {
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-1", "placed-a", NOW - 60);
        // A run started before the release (and placed on the new machine after it).
        running(&l, "run_queued", "placed-a");
        assert!(l.placed_node_ended("i-1", "released", &released_detail("alex", 1, true)).unwrap());
        let until = l.placed_node("i-1").unwrap().unwrap().ended_at.unwrap();
        assert_eq!(left(&l, "placed-a", until).unwrap().runs, ["run_queued"], "not told apart by its start alone");
        enrol(&mut l, "placed-a", until + 1);
        assert!(left(&l, "placed-a", until).unwrap().is_empty(true));
        assert_eq!(finish_incomplete(&mut l, "i-1", "alex", retire_in_ledger).unwrap(), None);
        assert_eq!(l.run_status("run_queued").unwrap().as_deref(), Some("running"));
        assert_eq!(l.node("placed-a").unwrap().unwrap().status, "active", "the new machine's enrolment is kept");
        // Revoked since, the new machine's row stays (#819 review): still nothing of the released one.
        l.revoke_node("placed-a").unwrap();
        let left_now = left(&l, "placed-a", until).unwrap();
        assert!(left_now.is_empty(true) && left_now.runs.is_empty(), "{:?}", left_now.runs);
        assert_eq!(finish_incomplete(&mut l, "i-1", "alex", retire_in_ledger).unwrap(), None);
        assert_eq!(l.run_status("run_queued").unwrap().as_deref(), Some("running"));
    }
}

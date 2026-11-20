//! `spawn`: an agent starts another box, an agent or a program, in a zone it describes (design
//! §5.1). Authority only narrows: the zone must be a subset of the parent's (wicket_core::subset),
//! its model budget is carved out of the parent's, and it inherits the parent's forbid rules. A zone
//! beyond the parent's starts only if a human approved exactly that zone (bound by its digest).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use wicket_core::{subset, Manifest, Op, RunId};
use wicket_node::childplan::{plan_child, ChildPlan, PlanIn};
use wicket_proxy::{llm::Budget, SpawnRequest};
use wicket_store::{EffectUse, Filed, Ledger};

pub struct SpawnCtx {
    pub parent: Manifest,
    /// Box slots this run has reserved: each child takes one, plus the `max_children` it may start
    /// itself. Checked and charged under this lock, with the model budget carve-out, before a child
    /// is launched, and released if it fails to (#125).
    pub slots: Arc<Mutex<u32>>,
    /// The boxes this run may start, its children's included (#256): the amount of its `children`
    /// quota grant, less its own box, read when the run starts. What `slots` is checked against.
    pub max_children: u32,
    /// Starts a child's supervisor ([`supervise`]; tests start a stand-in).
    pub supervise: Supervise,
    pub run: RunId,
    pub dir: PathBuf,
    pub image: String,
    /// The digest the parent's box started as (#192), once its node reports it: a child that names
    /// no image is pinned to it, so a retag between the two can't change what it starts.
    pub own_digest: Arc<OnceLock<String>>,
    pub node: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub ledger: Arc<Mutex<Ledger>>,
    pub children: Arc<Mutex<Vec<(String, Supervisor)>>>,
    pub llm: Arc<OnceLock<Arc<Budget>>>,
    pub deadline: Instant,
    /// The parent's org layer (#51): what spawns the org policy allows it, whatever it is approved.
    pub org: Option<Arc<wicket_authz::OrgLayer>>,
}

/// The slots a run's children already hold (#125), from the children it has started (their spawn
/// records in `<run dir>/children/`): one each plus their own `max_children`, as `spawn` charged them,
/// at most `max`. A re-attached run (#151) starts from this, so a restart doesn't reset its bound.
/// Like a run that never restarted, a child that has ended still counts.
impl SpawnCtx {
    /// The parent's own image: pinned to the digest its box started as, once known (#192).
    pub fn own_image(&self) -> String {
        match self.own_digest.get() {
            Some(d) => wicket_core::image::pinned(&self.image, d),
            None => self.image.clone(),
        }
    }
}

pub fn reserved_slots(dir: &std::path::Path, max: u32) -> u32 {
    let Ok(rd) = std::fs::read_dir(dir.join("children")) else { return 0 };
    let used = rd
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "yaml"))
        .map(|e| {
            let kids = std::fs::read_to_string(e.path())
                .ok()
                .and_then(|y| wicket_agent::load(&y).ok())
                .and_then(|m| m.agent.map(|a| a.max_children))
                .unwrap_or(0);
            kids.saturating_add(1)
        })
        .fold(0u32, u32::saturating_add);
    used.min(max)
}

/// The `spawn` tool for this run's box (#257 slice 4c): answered here, on the control host, when its
/// node doesn't start the child itself. Blocks while the child's supervisor starts (up to 10 s).
pub fn tool(c: &SpawnCtx, args: &serde_json::Value) -> (String, bool) {
    let req = match wicket_proxy::gateway::spawn_request(args) {
        Ok(r) => r,
        Err(e) => return (e, true),
    };
    match spawn(c, req) {
        Ok(msg) => (msg, false),
        Err(e) => (format!("not started: {e}"), true),
    }
}

/// What a child's supervisor is started with: `wicket run`'s options for a child, owned.
pub struct ChildOpts {
    /// Its manifest, in the parent's `children/`.
    pub manifest: PathBuf,
    pub run_id: String,
    pub parent_run: String,
    pub image: String,
    pub node: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub lease: Option<String>,
    pub adopt: Option<(i64, String)>,
    /// What it prints goes here (`children/<run>.log`).
    pub log: std::fs::File,
    /// Its parent asks it to stop its box and end.
    pub stop: Arc<tokio::sync::Notify>,
}

/// A child's supervisor, running in its parent's process.
pub struct Supervisor {
    pub stop: Arc<tokio::sync::Notify>,
    pub thread: std::thread::JoinHandle<()>,
}

/// Starts a child's supervisor.
pub type Supervise = fn(ChildOpts) -> std::io::Result<std::thread::JoinHandle<()>>;

/// Starts child run `o.run_id`'s supervisor in this process (#257 slice 4c): [`crate::run::run`],
/// on a thread of its own with its own runtime, so everything it runs (and prints, to its log)
/// is its own, as it was when it was a `wicket run` of its own. It ends when its run does.
pub fn supervise(o: ChildOpts) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new().name(format!("supervise {}", o.run_id)).spawn(move || {
        let ChildOpts { manifest, run_id, parent_run, image, node, ssh_key, lease, adopt, log, stop } = o;
        let id = run_id.clone();
        crate::out::to(log);
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return say!("[wicket] run {run_id}'s supervisor has no runtime: {e}"),
        };
        // A panic ends this run's supervisor, not its parent's.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(crate::run::run(crate::run::RunOpts {
                manifest: &manifest,
                workdir: None,
                workspace_dir: None,
                task: None,
                image: Some(&image),
                node: node.as_deref(),
                ssh_key: ssh_key.as_deref(),
                run_id: Some(run_id),
                parent_run: Some(parent_run),
                lease,
                wrap: None,
                wake: None,
                attach: false,
                adopt,
                stop: Some(stop),
            }))
        }));
        match r {
            Ok(Ok(())) => {}
            Ok(Err(e)) => say!("Error: {e:?}"),
            Err(_) => say!("[wicket] run {id}'s supervisor panicked"),
        }
    })
}

/// How long a parent that ends waits for its children's supervisors to end once asked to stop.
pub const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// Stops a parent's children as it ends (#257 slice 4c, #409): each is asked to stop its box and
/// end, all at once, and then waited for up to `grace`. A child's supervisor runs on a thread of
/// this process, and a thread can't be killed, so one still running after that is recorded loudly
/// instead: a line in the parent's log naming it and how long it was waited for, a `run.child_stuck`
/// audit record on its run, and its run marked stuck in the ledger ([`Ledger::set_run_stuck`]),
/// which the reconciler and `wicket top` show. Returns the stuck children, with the seconds waited.
pub async fn stop_children(
    kids: Vec<(String, Supervisor)>,
    grace: std::time::Duration,
    ledger: &Mutex<Ledger>,
    tenant: &wicket_core::TenantId,
    parent: &RunId,
) -> Vec<(String, u64)> {
    let asked = Instant::now();
    for (crun, sup) in &kids {
        if !sup.thread.is_finished() {
            say!("[wicket] stopping child {crun}");
            sup.stop.notify_one();
        }
    }
    while asked.elapsed() < grace && kids.iter().any(|(_, s)| !s.thread.is_finished()) {
        tokio::time::sleep(std::time::Duration::from_millis(100).min(grace)).await;
    }
    let waited = asked.elapsed();
    let mut stuck = vec![];
    for (crun, _) in kids.iter().filter(|(_, s)| !s.thread.is_finished()) {
        let secs = waited.as_secs();
        say!(
            "[wicket] child {crun} is stuck: its supervisor hasn't ended {:.1} s after it was asked to stop. It goes on until its box ends or this process does; the reconciler and wicket top show it as stuck",
            waited.as_secs_f64()
        );
        if let Ok(l) = ledger.lock() {
            let _ = l.set_run_stuck(crun, wicket_store::now());
            let _ = l.audit(
                tenant,
                Some(&RunId(crun.clone())),
                "run.child_stuck",
                &serde_json::json!({ "parent": parent.0, "waited_ms": u64::try_from(waited.as_millis()).unwrap_or(u64::MAX) }),
            );
        }
        stuck.push((crun.clone(), secs));
    }
    stuck
}

/// Takes over the children this run's node starts for its box (#164).
pub fn adopter(c: Arc<SpawnCtx>) -> crate::noderun::Adopter {
    Arc::new(move |s| adopt(&c, s))
}

/// Takes over a child the parent's node started for it while deciding its spawn (#164): checked
/// again here, as of when it started (its zone within the parent's, what no human may approve,
/// the org policy, the parent's slots), its slots and model budget reserved as `spawn` does, and
/// recorded and supervised as a run of its own (its supervisor adopting it), which publishes its token
/// and takes over its box without starting another. The budget was checked on the node against
/// the slice it was sent; here it is carved from the parent's. Idempotent: a resend is taken once.
fn adopt(c: &SpawnCtx, s: crate::noderun::Spawned) -> Result<(), String> {
    crate::run::check_run_id(&s.child).map_err(|e| e.to_string())?;
    let p = &c.parent;
    p.agent.as_ref().ok_or("only agents start boxes")?;
    let cdir = c.dir.join("children");
    let yaml_path = cdir.join(format!("{}.yaml", s.child));
    if yaml_path.exists() {
        return Ok(());
    }
    let cm = wicket_agent::load(&s.manifest).map_err(|e| format!("its manifest: {e}"))?;
    cm.validate().map_err(|e| format!("its manifest is invalid: {e}"))?;
    let name = cm.agent.as_ref().map(|a| a.name.clone()).or_else(|| cm.program.as_ref().map(|p| p.name.clone())).unwrap_or_default();
    let zone_name = format!("{}.{name}.{}", p.zone.name, c.run.0.strip_prefix("run_").unwrap_or(&c.run.0));
    if cm.zone.name != zone_name || cm.tenant != p.tenant {
        return Err(format!("its zone {} isn't one this run's spawns make", cm.zone.name));
    }
    let hard = subset::unapprovable(&cm.zone, &p.zone);
    if !hard.is_empty() {
        return Err(format!("it can't be started, with or without approval: {}", hard.join("; ")));
    }
    if let Some(org) = &c.org {
        let sp = wicket_authz::Ceiling::from_zone(&cm.zone, "child", 0, vec![]).map_err(|e| e.to_string())?.spawn;
        if !org.allows_spawn(&s.image, sp.min_isolation, sp.mem_bytes, sp.cpus_milli, sp.pids, sp.timeout_s) {
            return Err(format!("the org policy ({}) doesn't allow it", org.version));
        }
    }
    let mut reserved = c.slots.lock().map_err(|_| "slots lock")?;
    let slots = c.max_children.saturating_sub(*reserved);
    let elapsed = std::time::Duration::from_millis(u64::try_from(wicket_feed::now_ms() - s.started_ms).unwrap_or(0));
    let images: Vec<String> = std::iter::once(c.own_image()).chain(p.zone.images.iter().cloned()).collect();
    let max_children = cm.agent.as_ref().map_or(0, |a| a.max_children);
    let bounds = subset::Bounds {
        zone: &p.zone,
        images,
        llm_remaining: None,
        llm_input_remaining: None,
        // As of when it started (and the clocks a few seconds apart).
        time_remaining: c.deadline.saturating_duration_since(Instant::now()) + elapsed + std::time::Duration::from_secs(5),
        child_slots: slots,
    };
    if let Err(v) = subset::check(&subset::Ask { zone: &cm.zone, image: &s.image, max_children }, &bounds) {
        return Err(format!("it isn't within its parent's authority: {}", v.join("; ")));
    }
    let weight = max_children.saturating_add(1).min(slots);
    // Its quotas are recorded before its supervisor starts, which reads its limits from them.
    let ids = record_quotas(c, &cm, &s.child, weight)?;
    *reserved += weight;
    if let (Some(cl), Some(llm)) = (&cm.zone.llm, c.llm.get()) {
        use std::sync::atomic::Ordering;
        llm.count.reserved_requests.fetch_add(cl.max_requests, Ordering::SeqCst);
        llm.count.reserved_output_tokens.fetch_add(cl.max_output_tokens, Ordering::SeqCst);
        llm.count.reserved_input_tokens.fetch_add(cl.max_input_tokens.unwrap_or(0), Ordering::SeqCst);
    }
    drop(reserved);
    let _ = c.ledger.lock().map(|l| {
        l.audit(
            &p.tenant,
            Some(&c.run),
            "spawn.adopted",
            &serde_json::json!({ "child": s.child, "zone": cm.zone.name, "image": s.image, "node": c.node, "started_ms": s.started_ms }),
        )
    });
    let adopt = Adopt { started_ms: s.started_ms, session: s.session.clone() };
    // Supervised as the image it started as (#192): pinned to the digest its node reported.
    let image = match &s.digest {
        Some(d) if wicket_core::image::parse(d).is_ok_and(|r| r.pin.is_some() && r.name.is_empty()) => {
            wicket_core::image::pinned(&s.image, d)
        }
        _ => s.image.clone(),
    };
    // Its task is a delegation (#252), under the id its node's handle gave the parent.
    if cm.agent.is_some() {
        let own = c.ledger.lock().ok().and_then(|l| l.identity(&c.run.0).ok().flatten());
        if let Some(o) = own.and_then(|i| wicket_identity::Principal::parse(&i.spiffe_id)) {
            let cp = wicket_identity::spiffe_id(o.trust_domain(), &p.tenant.0, &zone_name, &name);
            delegate(c, &RunId(s.child.clone()), &cp, &name, &cm.task);
        }
    }
    if let Err(e) = launch_as(c, &RunId(s.child.clone()), &s.manifest, &image, None, Some(&adopt)) {
        unrecord_quotas(c, &ids);
        return Err(e);
    }
    Ok(())
}

/// What a run is given (#256): its model budget, its box slots (`weight`: its own and the boxes it
/// may start) and its memory, as quotas. For a child, what its parent carves for it; for a root run,
/// its own zone's.
pub fn quotas(cm: &Manifest, weight: u32) -> Vec<wicket_store::Quota> {
    use wicket_store::Quota;
    let mut q = vec![];
    if let Some(l) = &cm.zone.llm {
        q.push(Quota { resource: "model.requests", amount: l.max_requests });
        q.push(Quota { resource: "model.output_tokens", amount: l.max_output_tokens });
        if let Some(i) = l.max_input_tokens {
            q.push(Quota { resource: "model.input_tokens", amount: i });
        }
    }
    q.push(Quota { resource: "children", amount: u64::from(weight) });
    if let Some(b) = cm.zone.limits.memory_bytes() {
        q.push(Quota { resource: "bytes", amount: b });
    }
    q
}

/// Records what is carved for child `child` as quota grants made by this run, lasting the child's
/// timeout (at most 24h, renewable), before the child's supervisor starts: they are the limits it
/// enforces (its model proxy's budget, its spawns' slots). Returns the grant ids; a spawn whose
/// carve-out can't be recorded doesn't start.
fn record_quotas(c: &SpawnCtx, cm: &Manifest, child: &str, weight: u32) -> Result<Vec<String>, String> {
    let ttl = cm.zone.limits.timeout().map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)).unwrap_or(0);
    let by = format!("agent:{}", c.run);
    let l = c.ledger.lock().map_err(|_| "ledger lock")?;
    let child = RunId(child.to_string());
    let ids = l
        .record_quota_grants(&c.parent.tenant, &cm.zone.name, &child, &by, &quotas(cm, weight), ttl)
        .map_err(|e| format!("recording its quotas: {e}"))?;
    let _ = l.audit(&c.parent.tenant, Some(&c.run), "spawn.quotas", &serde_json::json!({ "child": child.0, "grants": ids }));
    Ok(ids)
}

/// A child that didn't start: the quotas recorded for it are revoked.
fn unrecord_quotas(c: &SpawnCtx, ids: &[String]) {
    if let Ok(l) = c.ledger.lock() {
        for id in ids {
            let _ = l.revoke_grant(id);
        }
    }
}

/// A child its node started (#164), to take over: its supervisor adopts its box.
pub struct Adopt {
    pub started_ms: i64,
    pub session: String,
}

fn spawn(c: &SpawnCtx, req: SpawnRequest) -> Result<String, String> {
    c.parent.agent.as_ref().ok_or("only agents start boxes")?;
    // Everything up to the launch happens under the slot lock: concurrent calls see each other's
    // reservations, never the same free slots or the same budget (#125).
    let mut reserved = c.slots.lock().map_err(|_| "slots lock")?;
    let slots = c.max_children.saturating_sub(*reserved);
    if slots == 0 {
        return Err(format!("this agent may start at most {} boxes (theirs included), and has used {}", c.max_children, *reserved));
    }
    let plan = plan_child(
        &PlanIn {
            parent: &c.parent,
            run: &c.run,
            image: &c.own_image(),
            time_left: c.deadline.saturating_duration_since(Instant::now()),
            llm_left: c.llm.get().and_then(|l| l.remaining()),
            llm_input_left: c.llm.get().and_then(|l| l.remaining_input()),
            slots,
            org: c.org.as_deref(),
        },
        &req,
    )?;
    let ChildPlan { cm, yaml, image, zone_name, digest, violations, weight, is_agent, .. } = plan;
    let (p, name) = (&c.parent, &req.name);
    // Where it runs: decided before anything is asked or carved, so a bad hint costs nothing.
    let placed = {
        let l = c.ledger.lock().map_err(|_| "ledger lock")?;
        placement(&l, &c.run.0, c.node.as_deref(), req.placement.as_ref(), wicket_store::now())?
    };
    let mut beyond = false;
    if !violations.is_empty() {
        // The effect is this child, by zone and name; its arguments' hash is the rest of what the
        // approval is for (#369): a grant is used only with exactly those arguments.
        let mut op = Op::egress(&p.tenant, &c.run, &p.zone.name, "SPAWN", "wicket.internal", &format!("/zones/{zone_name}/{name}"));
        // Beyond the parent's authority is never a one-click "allow for an hour" (#118).
        op.risk = wicket_core::RiskClass::R4ExecOrPrivilege;
        let mut l = c.ledger.lock().map_err(|_| "ledger lock")?;
        match l.use_effect_grant(&op, Some(&digest)).map_err(|e| e.to_string())? {
            EffectUse::Held { pending } => {
                return Ok(format!(
                    "waiting: request {pending} for starting {name} is not decided yet, and nothing for it runs before it is. Call await_grant with {pending}; once granted, call spawn again with exactly the arguments it was asked with."
                ));
            }
            EffectUse::ArgsChanged { grant } => {
                return Err(format!(
                    "refused: starting {name} was approved ({grant}) for other arguments, and these changed after the approval (this is recorded). Call spawn with exactly the arguments that were approved."
                ));
            }
            EffectUse::Granted(gid) => {
                beyond = true;
                let _ = l.audit(
                    &p.tenant,
                    Some(&c.run),
                    "spawn.beyond_parent",
                    &serde_json::json!({ "zone": zone_name, "grant": gid, "exceeds": violations }),
                );
            }
            // A zone that may not ask (#50): nobody is asked, whatever the caller says.
            EffectUse::None if !p.zone.escalation.request => {
                return Err(format!(
                    "this zone is not within yours:\n- {}\nYour zone may not ask for more (escalation.request: false), so this will never be allowed from here; narrow it.",
                    violations.join("\n- ")
                ));
            }
            EffectUse::None if !req.escalate => {
                return Err(format!(
                    "this zone is not within yours:\n- {}\nNarrow it, or call spawn again with escalate: true to ask for exactly this zone to be approved.",
                    violations.join("\n- ")
                ));
            }
            EffectUse::None => {
                if let Ok(Some(rid)) = l.denied_recently_with(&op, Some(&digest)) {
                    return Err(format!("exactly this spawn ({rid}) was denied a few minutes ago; don't ask again"));
                }
                let reason = card(&req.kind, name, &image, &cm, &violations);
                let rid = match l.file_request(&op, Some(&digest), &reason, None).map_err(|e| e.to_string())? {
                    Filed::Held { pending } => {
                        return Ok(format!(
                            "waiting: request {pending} to start {name} with other arguments is not decided yet; nothing else for {name} is asked or started before it is. Call await_grant with {pending}."
                        ))
                    }
                    f => f.id().to_string(),
                };
                return Ok(format!(
                    "needs approval: request {rid} (this zone exceeds yours: {}). Call await_grant with {rid}; once granted, call spawn again with exactly the same arguments.",
                    violations.join("; ")
                ));
            }
        }
    }

    // Reserve: the child's slots (its own and its max_children, so descendants are bounded by this
    // agent's max_children, not 2^k) and its model budget, carved out of the parent's, recorded as
    // its quota grants before it starts.
    let child = RunId::new();
    let ids = record_quotas(c, &cm, &child.0, weight)?;
    *reserved += weight;
    // The budget checked above may have been spent since (a model call isn't under this lock): the
    // carve-out is checked again as it is made, under the counter's claims lock, so the two can't
    // both take the last of it (#325, wicket_core::budget).
    let carve = match (&cm.zone.llm, c.llm.get()) {
        (Some(cl), Some(llm)) => {
            let child_quota = wicket_proxy::llm::ModelQuota::of_zone(cl);
            if let Err(short) = llm.count.carve(llm.quota().unwrap_or_default(), child_quota) {
                unrecord_quotas(c, &ids);
                *reserved = reserved.saturating_sub(weight);
                return Err(format!("its model budget no longer fits in what is left of yours ({short}): it was spent since"));
            }
            Some((llm.clone(), child_quota))
        }
        _ => None,
    };
    drop(reserved);
    // Its principal (#250): what send_message names it by, the same in every run it has.
    let child_principal = {
        let l = c.ledger.lock().map_err(|_| "ledger lock")?;
        let own = l.identity(&c.run.0).ok().flatten().and_then(|i| wicket_identity::Principal::parse(&i.spiffe_id));
        own.map(|o| wicket_identity::spiffe_id(o.trust_domain(), &p.tenant.0, &zone_name, name))
    };
    // An agent's task is a delegation (#252), recorded before it starts so its first turn's report
    // finds it: its report comes back as a message, and the parent may continue it by name.
    if let (Some(cp), true) = (&child_principal, is_agent) {
        delegate(c, &child, cp, name, &cm.task);
    }
    let launched = launch_as(c, &child, &yaml, &image, placed.as_ref(), None);
    let child = match launched {
        Ok(child) => child,
        Err(e) => {
            if let Ok(l) = c.ledger.lock() {
                let _ = l.delegation_ended(&child.0, None);
            }
            // Nothing started: give the slots, the budget and its quotas back.
            unrecord_quotas(c, &ids);
            if let Ok(mut r) = c.slots.lock() {
                *r = r.saturating_sub(weight);
            }
            if let Some((llm, child_quota)) = carve {
                llm.count.uncarve(child_quota);
            }
            return Err(e);
        }
    };
    let budget =
        cm.zone.llm.as_ref().map(|l| format!(", a model budget of {} requests carved from yours", l.max_requests)).unwrap_or_default();
    let at = placed.as_ref().map(|p| format!(" on node {}", p.node)).unwrap_or_default();
    let principal = child_principal.as_deref().map(|p| format!(", principal {p}")).unwrap_or_default();
    let handle = match (&child_principal, is_agent) {
        (Some(cp), true) => format!("\nhandle: {}", wicket_proxy::delegate::handle(cp, &child, name)),
        _ => String::new(),
    };
    Ok(format!(
        "started {} {name} as run {}{at}: its own box and identity, zone {zone_name}{principal}{}{budget}. {}{handle}",
        req.kind,
        child,
        if beyond { " (approved beyond your own zone)" } else { ", within your own" },
        if is_agent {
            "When its turn on the task ends, its report comes to you as a message (kind report, with a receipt; use await_message); continue_child gives it another brief, its context intact. Its final run_finished comes when its run ends."
        } else {
            "It sends you run_finished when it exits."
        }
    ))
}

/// Records child `child`'s task as this run's delegation to it (#252), audited. Its record only:
/// what the child may do is its zone, already checked within this run's.
fn delegate(c: &SpawnCtx, child: &RunId, child_principal: &str, name: &str, brief: &str) {
    let Ok(l) = c.ledger.lock() else { return };
    let Some(parent) = l.identity(&c.run.0).ok().flatten() else { return };
    let id = wicket_proxy::delegate::delegation_id(&child.0);
    let recorded = l.record_delegation(&wicket_store::NewDelegation {
        id: &id,
        tenant: &c.parent.tenant.0,
        parent_run: &c.run.0,
        parent_principal: &parent.spiffe_id,
        child_run: &child.0,
        child_principal,
        name,
        brief,
    });
    let _ = l.audit(
        &c.parent.tenant,
        Some(&c.run),
        "delegation.started",
        &serde_json::json!({ "delegation": id, "child": child_principal, "child_run": child.0, "name": name, "recorded": recorded.is_ok() }),
    );
}

/// What a beyond-parent spawn card says, from wicket's own record of the child (#118): what it
/// exceeds, then what it gets — the model route and every credential injection first, then reach,
/// limits, image and children. Agent-chosen strings are stripped and clipped, and the lists bounded,
/// so nothing pushes a line out of view or rewrites it.
fn card(kind: &str, name: &str, image: &str, cm: &Manifest, violations: &[String]) -> String {
    use wicket_core::text::clip;
    let z = &cm.zone;
    let list = |items: Vec<String>, max: usize| {
        let n = items.len();
        let mut v: Vec<String> = items.into_iter().take(max).collect();
        if n > max {
            v.push(format!("and {} more", n - max));
        }
        v.join("; ")
    };
    let model = match &z.llm {
        Some(l) => format!(
            "model route {} via {} with secret {} (this zone's own), {} requests, {} output tokens, {} input tokens, {}{}",
            clip(&l.provider, 40),
            clip(&l.upstream, 200),
            clip(&l.secret, 80),
            l.max_requests,
            l.max_output_tokens,
            l.max_input_tokens.map(|i| i.to_string()).unwrap_or_else(|| "uncapped".into()),
            match &l.models {
                None => "any model".to_string(),
                Some(ms) if ms.is_empty() => "no models".to_string(),
                Some(ms) => format!("models {}", clip(&ms.join(", "), 200)),
            },
            if l.allow_server_tools { ", server-side tools allowed" } else { "" }
        ),
        None => "no model route".into(),
    };
    let inject = if z.inject.is_empty() {
        "no credential injections".into()
    } else {
        format!(
            "injects {}",
            list(
                z.inject
                    .iter()
                    .map(|i| format!("secret {} into {} {}", clip(&i.secret, 80), clip(&i.host, 120), clip(&i.header, 60)))
                    .collect(),
                8
            )
        )
    };
    let reach = list(
        z.reach
            .iter()
            .map(|r| {
                let methods = if r.methods.is_empty() { "GET, HEAD".to_string() } else { r.methods.join(", ") };
                let paths = if r.paths.is_empty() { "/**".to_string() } else { r.paths.join(", ") };
                let decode = if r.decode_slash.is_empty() {
                    String::new()
                } else {
                    format!(" (decides an encoded slash as / in segment {:?})", r.decode_slash)
                };
                format!(
                    "{} {} {}{}{decode}",
                    clip(&methods, 60),
                    clip(&r.host, 120),
                    clip(&paths, 200),
                    if r.allow_dangerous { " (allow_dangerous)" } else { "" }
                )
            })
            .collect(),
        12,
    );
    let l = &z.limits;
    let children = cm.agent.as_ref().map(|a| a.max_children).unwrap_or(0);
    let forbid = list(z.forbid.iter().map(|f| format!("{} {}", clip(&f.host, 120), clip(&f.paths.join(", "), 200))).collect(), 12);
    let accept = list(z.accept_from.iter().map(|a| clip(a, 120)).collect(), 8);
    let images = list(z.images.iter().map(|i| clip(i, 120)).collect(), 8);
    let volumes = list(z.volumes.iter().map(|v| format!("{} at {}", clip(&v.name, 60), clip(&v.path, 120))).collect(), 8);
    let or_none = |s: String| if s.is_empty() { "none".to_string() } else { s };
    format!(
        "start {kind} {} in zone {}, beyond this agent's own. It exceeds: {}. It gets: {model}; {inject}; reach {}; forbid {}; unlisted hosts {:?}; isolation {:?}; image {}; may start images {}; accepts messages from {}; volumes {}; memory {}, cpus {}, pids {}, timeout {}; may start {children} box(es).",
        clip(name, 40),
        clip(&z.name, 200),
        list(violations.iter().map(|v| clip(v, 240)).collect(), 16),
        or_none(reach),
        or_none(forbid),
        z.unlisted_hosts,
        z.isolation,
        clip(image, 120),
        or_none(images),
        or_none(accept),
        or_none(volumes),
        clip(&l.memory, 20),
        l.cpus,
        l.pids,
        clip(&l.timeout, 20),
    )
}

/// Starts the supervisor of child `child`, or (`adopt`) of a child its node started already, in
/// this process (#257 slice 4c): its own box, identity and records, as a run of its own. Returns
/// its run id once it has recorded its identity (or ended, or 10 s passed).
fn launch_as(
    c: &SpawnCtx,
    child: &RunId,
    yaml: &str,
    image: &str,
    placed: Option<&Placed>,
    adopt: Option<&Adopt>,
) -> Result<String, String> {
    let cdir = c.dir.join("children");
    std::fs::create_dir_all(&cdir).map_err(|e| e.to_string())?;
    let yaml_path = cdir.join(format!("{}.yaml", child.0));
    std::fs::write(&yaml_path, yaml).map_err(|e| e.to_string())?;
    let log = std::fs::File::create(cdir.join(format!("{}.log", child.0))).map_err(|e| e.to_string())?;
    // Placed on a lease: that lease's node, reached with the key it was enrolled with. Otherwise
    // the parent's own node (named, or the node the hint named), reached as the parent reaches it.
    let (node, lease) = match placed {
        Some(p) => (Some(p.node.clone()), p.lease.clone()),
        None => (c.node.clone(), None),
    };
    let ssh_key = if lease.is_some() { None } else { c.ssh_key.clone() };
    let stop = Arc::new(tokio::sync::Notify::new());
    let thread = match (c.supervise)(ChildOpts {
        manifest: yaml_path.clone(),
        run_id: child.0.clone(),
        parent_run: c.run.0.clone(),
        image: image.to_string(),
        node,
        ssh_key,
        lease,
        adopt: adopt.map(|a| (a.started_ms, a.session.clone())),
        log,
        stop: stop.clone(),
    }) {
        Ok(t) => t,
        Err(e) => {
            // Never started: no spawn record, so a re-attach doesn't count it (`reserved_slots`).
            let _ = std::fs::remove_file(&yaml_path);
            return Err(format!("starting the box: {e}"));
        }
    };
    // The child records its identity before its box starts; wait for it so the parent can message it.
    for _ in 0..100 {
        if thread.is_finished() {
            break;
        }
        if c.ledger.lock().ok().and_then(|l| l.identity(&child.0).ok().flatten()).is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    c.children.lock().map_err(|_| "children lock")?.push((child.0.clone(), Supervisor { stop, thread }));
    Ok(child.0.clone())
}

/// Where a child runs, from `spawn`'s placement hint.
#[derive(Debug, PartialEq, Eq)]
pub struct Placed {
    /// The enrolled node it runs on.
    pub node: String,
    /// The lease it is placed on: the reconciler stops it when the lease ends.
    pub lease: Option<String>,
}

/// Resolves a placement hint. Authority only narrows here too: `{lease}` must be a lease this run
/// holds and that is active; `{node}` must be the node this run itself runs on, or the node of an
/// active lease it holds. None: no hint, the child runs where the parent does.
pub fn placement(
    l: &Ledger,
    run: &str,
    own_node: Option<&str>,
    hint: Option<&serde_json::Value>,
    now: i64,
) -> Result<Option<Placed>, String> {
    let Some(h) = hint else { return Ok(None) };
    let lease_ok = |id: &str| -> Result<(String, String), String> {
        let x = l.lease(id).map_err(|e| e.to_string())?.filter(|x| x.run == run).ok_or(format!("no lease {id} held by this run"))?;
        match (x.status.as_str(), &x.node_name) {
            ("active", Some(n)) if x.not_after.is_none_or(|t| t > now) => Ok((x.id, n.clone())),
            ("active", Some(_)) => Err(format!("lease {id} has ended")),
            ("pending" | "approved", _) => Err(format!("lease {id} is {}: wait for it with request_capacity and lease {id}", x.status)),
            (s, _) => Err(format!("lease {id} is {s}")),
        }
    };
    if let Some(id) = h.get("lease").and_then(|v| v.as_str()) {
        let (lease, node) = lease_ok(id)?;
        return Ok(Some(Placed { node, lease: Some(lease) }));
    }
    if let Some(n) = h.get("node").and_then(|v| v.as_str()) {
        let own = own_node.is_some_and(|o| {
            o == n
                || l.node(n).ok().flatten().is_some_and(|r| r.target == o)
                || l.node_by_target(o).ok().flatten().is_some_and(|r| r.name == n)
        });
        if own {
            return Ok(Some(Placed { node: n.to_string(), lease: None }));
        }
        let held =
            l.leases(&["active"]).map_err(|e| e.to_string())?.into_iter().find(|x| x.run == run && x.node_name.as_deref() == Some(n));
        if let Some(x) = held {
            let (lease, node) = lease_ok(&x.id)?;
            return Ok(Some(Placed { node, lease: Some(lease) }));
        }
        return Err(format!(
            "node {n} is neither where this agent runs nor the node of a lease it holds: ask for one with request_capacity"
        ));
    }
    Err("placement must be {\"lease\": \"l-…\"} or {\"node\": \"<name>\"}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wicket_store::{LeaseBudget, LeaseRow};

    /// #192: a spawn's image is decided by digest where pinned: a tag of a pinned repository is that
    /// pin; a child naming no image is its parent's image as it started (pinned to its digest); a
    /// pinned request needs a pinned entry of the same digest; and the org policy decides on the
    /// entry that allows it.
    #[test]
    fn a_spawn_is_pinned_by_the_entry_that_allows_its_image() {
        let (a, b) = (format!("sha256:{}", "a".repeat(64)), format!("sha256:{}", "b".repeat(64)));
        let p = wicket_agent::load(&format!(
            "task: t\nagent: {{ name: lead, max_children: 4 }}\nzone:\n  name: z\n  llm: {{ secret: m }}\n  images: [tool@{a}, 'other:1']\n  limits: {{ memory: 1g, cpus: 1, timeout: 1h }}\n"
        ))
        .unwrap();
        let own = wicket_core::image::pinned("wicket/claude-code:dev", &b);
        let plan = |image: Option<&str>, org: Option<&wicket_authz::OrgLayer>| {
            let req = SpawnRequest {
                name: "kid".into(),
                kind: "program".into(),
                command: vec!["true".into()],
                image: image.map(String::from),
                zone: Some(json!({ "limits": { "memory": "128m", "cpus": 1, "timeout": "5m" } })),
                ..Default::default()
            };
            plan_child(
                &PlanIn {
                    parent: &p,
                    run: &RunId("run_x".into()),
                    image: &own,
                    time_left: std::time::Duration::from_secs(3600),
                    llm_left: None,
                    llm_input_left: None,
                    slots: 4,
                    org,
                },
                &req,
            )
        };
        let tag = plan(Some("tool:latest"), None).unwrap();
        assert!(tag.violations.is_empty(), "{:?}", tag.violations);
        assert_eq!((tag.image.as_str(), tag.image_pin.as_deref()), (format!("tool@{a}").as_str(), Some(a.as_str())));
        let dflt = plan(None, None).unwrap();
        assert_eq!((dflt.image, dflt.image_pin.as_deref(), dflt.image_entry), (own.clone(), Some(b.as_str()), own.clone()));
        let other = plan(Some("other:1"), None).unwrap();
        assert_eq!((other.image.as_str(), other.image_pin), ("other:1", None), "a tag entry: resolved where it starts");
        assert!(!plan(Some(&format!("tool@{b}")), None).unwrap().violations.is_empty(), "another digest of a pinned repository");
        assert!(!plan(Some(&format!("other@{a}")), None).unwrap().violations.is_empty(), "a pin a tag entry can't vouch for");
        // The org policy sees the entry: one that allows `tool@a` lets a tag of it start.
        let org = wicket_authz::OrgLayer {
            version: "v1".into(),
            http: None,
            forbid: vec![],
            spawn: Some(vec![wicket_authz::SpawnMatch { images: Some(vec![format!("tool@{a}")]), ..Default::default() }]),
            msg_from: None,
            inject: None,
        };
        assert!(plan(Some("tool:latest"), Some(&org)).is_ok());
        assert!(plan(Some("other:1"), Some(&org)).err().unwrap_or_default().contains("org policy"));
    }

    /// #348: a spawned zone inherits its parent's `limits.memory_advice` whether it states limits
    /// or not, may replace it (or clear it, empty), and a replacement past the cap is refused.
    #[test]
    fn a_spawned_zone_inherits_its_parents_memory_advice_and_may_replace_it() {
        let p = wicket_agent::load(
            "task: t\nagent: { name: lead, max_children: 4 }\nzone:\n  name: z\n  llm: { secret: m }\n  limits: { memory: 1g, cpus: 1, timeout: 1h, memory_advice: 'CARGO_BUILD_JOBS=1' }\n",
        )
        .unwrap();
        let plan = |zone: Option<serde_json::Value>| {
            let req = SpawnRequest { name: "kid".into(), kind: "agent".into(), task: Some("t".into()), zone, ..Default::default() };
            plan_child(
                &PlanIn {
                    parent: &p,
                    run: &RunId("run_x".into()),
                    image: "wicket/claude-code:dev",
                    time_left: std::time::Duration::from_secs(3600),
                    llm_left: None,
                    llm_input_left: None,
                    slots: 4,
                    org: None,
                },
                &req,
            )
        };
        let advice = |zone| plan(zone).map(|c| c.cm.zone.limits.memory_advice().map(String::from));
        let lim = |extra: serde_json::Value| {
            let mut l = json!({ "memory": "128m", "cpus": 1, "timeout": "5m" });
            l.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            Some(json!({ "limits": l }))
        };
        let inherited = Ok(Some("CARGO_BUILD_JOBS=1".to_string()));
        assert_eq!(advice(None), inherited, "no zone: the parent's");
        assert_eq!(advice(Some(json!({}))), inherited, "no limits: the parent's");
        assert_eq!(advice(lim(json!({}))), inherited, "limits without advice: the parent's");
        assert_eq!(advice(lim(json!({ "memory_advice": "one query at a time" }))), Ok(Some("one query at a time".into())), "replaced");
        assert_eq!(advice(lim(json!({ "memory_advice": "" }))), Ok(None), "cleared");
        let long = "x".repeat(wicket_core::manifest::MEMORY_ADVICE_MAX + 1);
        assert!(advice(lim(json!({ "memory_advice": long }))).unwrap_err().contains("memory_advice"), "capped");
        assert!(advice(lim(json!({ "memory_advice": "a\nb" }))).unwrap_err().contains("memory_advice"), "one line");
    }

    const NOW: i64 = 1_000_000;

    /// A lease held by `run` in `status` (`active` ones on node `node`, ending at `not_after`).
    fn lease(l: &mut Ledger, id: &str, run: &str, status: &str, node: &str, not_after: i64) {
        let row = LeaseRow {
            id: id.into(),
            tenant: "default".into(),
            run: run.into(),
            request_id: None,
            provider: "static".into(),
            spec: json!({}),
            hourly_cap: 0,
            reserved: 0,
            duration_secs: 1800,
            created_at: 0,
            not_after: None,
            status: "pending".into(),
            node_id: None,
            node_name: None,
            ssh_target: None,
            host_key: None,
            billed: None,
            ended_at: None,
            detail: None,
        };
        l.create_lease(&row, LeaseBudget { max_hourly: 0, max_total: 0 }).unwrap().unwrap();
        if status == "pending" {
            return;
        }
        assert!(l.lease_transition(id, &["pending"], "approved", "test").unwrap());
        if status == "active" {
            l.lease_activated(id, node, "wicket@203.0.113.9", not_after).unwrap();
        }
    }

    /// A parent agent that may start `max` boxes, its children run as `/bin/true` (they exit at once,
    /// so nothing waits for an identity), in a scratch directory the guard removes.
    struct Parent {
        ctx: Arc<SpawnCtx>,
        dir: PathBuf,
    }

    impl Drop for Parent {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A child's supervisor that ends at once (as `/bin/true` did, when a child was a process).
    fn ended(_: ChildOpts) -> std::io::Result<std::thread::JoinHandle<()>> {
        Ok(std::thread::spawn(|| {}))
    }

    fn parent(max: u32, zone: &str) -> Parent {
        let dir = std::env::temp_dir().join(format!("wicket-spawn-test-{}-{}", std::process::id(), wicket_core::new_request_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let m = wicket_agent::load(&format!("task: t\nagent: {{ name: lead, max_children: {max} }}\nzone:\n  name: z\n{zone}")).unwrap();
        let ctx = SpawnCtx {
            parent: m,
            slots: Default::default(),
            max_children: max,
            supervise: ended,
            run: RunId("run_01parent".into()),
            dir: dir.clone(),
            image: "img:a".into(),
            own_digest: Default::default(),
            node: None,
            ssh_key: None,
            ledger: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            children: Default::default(),
            llm: Default::default(),
            deadline: Instant::now() + std::time::Duration::from_secs(3600),
            org: None,
        };
        Parent { ctx: Arc::new(ctx), dir }
    }

    fn program(name: &str) -> SpawnRequest {
        SpawnRequest {
            name: name.into(),
            kind: "program".into(),
            task: None,
            command: vec!["true".into()],
            image: None,
            zone: Some(json!({ "reach": [{ "host": "api.example.com", "methods": ["GET"] }] })),
            max_children: 0,
            escalate: false,
            placement: None,
        }
    }

    const ZONE: &str =
        "  llm: {}\n  reach:\n    - { host: api.example.com, methods: [GET] }\n  limits: { memory: 1g, cpus: 1, timeout: 1h }\n";

    /// #125: parallel spawn calls can't all see the same free slots.
    #[test]
    fn parallel_spawns_never_exceed_max_children() {
        let p = parent(2, ZONE);
        let results: Vec<Result<String, String>> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..6)
                .map(|i| {
                    let c = p.ctx.clone();
                    sc.spawn(move || spawn(&c, program(&format!("p{i}"))))
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let started = results.iter().filter(|r| r.as_ref().is_ok_and(|s| s.starts_with("started"))).count();
        assert_eq!(started, 2, "{results:#?}");
        assert!(results.iter().filter_map(|r| r.as_ref().err()).all(|e| e.contains("at most 2 boxes")), "{results:#?}");
        assert_eq!(p.ctx.children.lock().unwrap().len(), 2);
    }

    /// #125: a child's own max_children is charged to the parent, so descendants stay bounded.
    #[test]
    fn a_childs_children_are_charged_to_the_parent() {
        let p = parent(3, ZONE);
        let agent = |name: &str, max_children| SpawnRequest {
            kind: "agent".into(),
            task: Some("work".into()),
            command: vec![],
            zone: None,
            max_children,
            ..program(name)
        };
        assert!(spawn(&p.ctx, agent("a", 1)).unwrap().starts_with("started"));
        assert_eq!(*p.ctx.slots.lock().unwrap(), 2);
        let e = spawn(&p.ctx, agent("b", 1)).unwrap_err();
        assert!(e.contains("max_children 1: this zone has 1 box(es) left"), "{e}");
        assert!(spawn(&p.ctx, program("c")).unwrap().starts_with("started"));
        assert!(spawn(&p.ctx, program("d")).unwrap_err().contains("at most 3"));
    }

    /// #256: what a spawn carves for a child (its model budget, its slots, its memory) is recorded
    /// as quota grants made by the parent, each with a lifetime of at most 24h, bound to the child,
    /// before the child starts (its limits are read from them); a launch that fails revokes them.
    #[test]
    fn a_spawn_records_its_carve_out_as_quota_grants() {
        let mut p = parent(4, ZONE);
        Arc::get_mut(&mut p.ctx).unwrap().supervise = |_| Err(std::io::Error::other("no supervisor"));
        assert!(spawn(&p.ctx, program("a")).is_err());
        {
            let l = p.ctx.ledger.lock().unwrap();
            assert!(l.grants(&wicket_core::TenantId::single(), false, 100).unwrap().is_empty(), "none live");
            let all = l.grants(&wicket_core::TenantId::single(), true, 100).unwrap();
            assert!(all.iter().all(|g| g.grant.revoked), "recorded before the launch, revoked when it failed");
        }
        Arc::get_mut(&mut p.ctx).unwrap().supervise = ended;
        let agent =
            SpawnRequest { kind: "agent".into(), task: Some("work".into()), command: vec![], zone: None, max_children: 1, ..program("a") };
        let out = spawn(&p.ctx, agent).unwrap();
        let child = out.split(" as run ").nth(1).and_then(|r| r.split(':').next()).unwrap().to_string();
        let l = p.ctx.ledger.lock().unwrap();
        let gs = l.quota_grants(&child).unwrap();
        let mut got: Vec<(String, i64)> = gs.iter().map(|g| (g.quota().unwrap().to_string(), g.amount.unwrap())).collect();
        got.sort();
        let cm = Manifest::from_yaml(&std::fs::read_to_string(p.dir.join("children").join(format!("{child}.yaml"))).unwrap()).unwrap();
        let llm = cm.zone.llm.clone().expect("a model budget");
        let mut want = vec![
            ("bytes".to_string(), 1 << 30),
            ("children".to_string(), 2),
            ("model.output_tokens".to_string(), llm.max_output_tokens as i64),
            ("model.requests".to_string(), llm.max_requests as i64),
        ];
        if let Some(i) = llm.max_input_tokens {
            want.push(("model.input_tokens".into(), i as i64));
        }
        want.sort();
        assert_eq!(got, want);
        let now = wicket_store::now();
        for g in &gs {
            assert_eq!(g.run.as_deref(), Some(child.as_str()));
            assert!(g.expires_at > now && g.expires_at <= now + 3600, "the child's timeout, never more than 24h");
            assert!(g.request_id.is_none() && !g.revoked);
        }
        let listed = l.grants(&wicket_core::TenantId::single(), false, 100).unwrap();
        assert!(listed.iter().all(|g| g.decided_by == "agent:run_01parent"), "made by the parent");
    }

    /// #125: a launch that fails gives its slots back.
    #[test]
    fn a_failed_launch_releases_its_slot() {
        let mut p = parent(1, ZONE);
        Arc::get_mut(&mut p.ctx).unwrap().supervise = |_| Err(std::io::Error::other("no supervisor"));
        assert!(spawn(&p.ctx, program("a")).unwrap_err().contains("starting the box"));
        assert_eq!(*p.ctx.slots.lock().unwrap(), 0);
        Arc::get_mut(&mut p.ctx).unwrap().supervise = ended;
        assert!(spawn(&p.ctx, program("a")).unwrap().starts_with("started"));
    }

    /// #151: a re-attached parent's slots are rebuilt from the children it started, so a parent at
    /// its limit is still refused after a restart.
    #[test]
    fn a_reattached_parent_keeps_its_spawn_bound() {
        let p = parent(3, ZONE);
        let agent =
            SpawnRequest { kind: "agent".into(), task: Some("work".into()), command: vec![], zone: None, max_children: 1, ..program("a") };
        assert!(spawn(&p.ctx, agent).unwrap().starts_with("started"));
        assert!(spawn(&p.ctx, program("b")).unwrap().starts_with("started"));
        assert!(spawn(&p.ctx, program("c")).unwrap_err().contains("at most 3"));
        // The control host restarts: a new supervisor, a new context for the same run directory.
        let reserved = reserved_slots(&p.dir, 3);
        assert_eq!(reserved, 3);
        let ctx = SpawnCtx {
            parent: p.ctx.parent.clone(),
            slots: Arc::new(Mutex::new(reserved)),
            max_children: 3,
            supervise: ended,
            run: p.ctx.run.clone(),
            dir: p.dir.clone(),
            image: "img:a".into(),
            own_digest: Default::default(),
            node: None,
            ssh_key: None,
            ledger: p.ctx.ledger.clone(),
            children: Default::default(),
            llm: Default::default(),
            deadline: Instant::now() + std::time::Duration::from_secs(3600),
            org: None,
        };
        let e = spawn(&ctx, program("c")).unwrap_err();
        assert!(e.contains("at most 3 boxes (theirs included), and has used 3"), "{e}");
        // A launch that never started leaves no record behind.
        let mut q = parent(1, ZONE);
        Arc::get_mut(&mut q.ctx).unwrap().supervise = |_| Err(std::io::Error::other("no supervisor"));
        assert!(spawn(&q.ctx, program("a")).is_err());
        assert_eq!(reserved_slots(&q.dir, 1), 0);
    }

    /// #257 slice 4c: a child's supervisor is `run::run` on a thread of this process, and what it
    /// prints goes to its log in the parent's `children/`, not to the parent's output.
    #[test]
    fn a_childs_supervisor_runs_in_process_and_prints_to_its_log() {
        let p = parent(1, ZONE);
        let log_path = p.dir.join("child.log");
        let t = supervise(ChildOpts {
            manifest: p.dir.join("children/run_01child.yaml"),
            run_id: "run_01child".into(),
            parent_run: "run_01parent".into(),
            image: "img:a".into(),
            node: None,
            ssh_key: None,
            lease: None,
            adopt: None,
            log: std::fs::File::create(&log_path).unwrap(),
            stop: Default::default(),
        })
        .unwrap();
        assert!(t.thread().name().is_some_and(|n| n.ends_with("run_01child")));
        t.join().unwrap();
        // No manifest there: the run fails before it starts anything, and says why in its log.
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(log.starts_with("Error: reading ") && log.contains("run_01child.yaml"), "{log}");
    }

    /// #409: a parent that ends stops its children; one whose supervisor hasn't ended after the
    /// grace is recorded as stuck (its run marked, an audit record), and one that ended isn't.
    #[tokio::test]
    async fn a_child_supervisor_that_does_not_end_is_recorded_as_stuck() {
        let l = Ledger::open_in_memory().unwrap();
        let t = wicket_core::TenantId("t".into());
        for r in ["run_01done", "run_01hung"] {
            l.run_started(&t, &RunId(r.into()), "z", "a").unwrap();
        }
        let ledger = Mutex::new(l);
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (stop_done, stop_hung) = (Arc::new(tokio::sync::Notify::new()), Arc::new(tokio::sync::Notify::new()));
        let done = {
            let stop = stop_done.clone();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(stop.notified())
            })
        };
        // Like #383's deadlock: never looks at its stop.
        let hung = {
            let release = release.clone();
            std::thread::spawn(move || {
                while !release.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            })
        };
        let kids = vec![
            ("run_01done".to_string(), Supervisor { stop: stop_done, thread: done }),
            ("run_01hung".to_string(), Supervisor { stop: stop_hung, thread: hung }),
        ];
        let stuck = stop_children(kids, std::time::Duration::from_millis(300), &ledger, &t, &RunId("run_01parent".into())).await;
        release.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(stuck.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(), vec!["run_01hung"]);
        let l = ledger.lock().unwrap();
        assert!(l.run_stuck("run_01hung").unwrap().is_some());
        assert_eq!(l.run_stuck("run_01done").unwrap(), None);
        let rec: serde_json::Value =
            serde_json::from_str(&l.audit_latest("run_01hung", "run.child_stuck").unwrap().expect("a record")).unwrap();
        assert_eq!(rec["parent"], "run_01parent");
        assert!(rec["waited_ms"].as_u64().unwrap() >= 300, "{rec}");
        assert!(l.audit_latest("run_01done", "run.child_stuck").unwrap().is_none());
    }

    /// #127: a spawned zone's name carries the parent run, so no other run can make it.
    #[test]
    fn spawned_zone_names_are_unique_to_the_parent_run() {
        let p = parent(1, ZONE);
        let out = spawn(&p.ctx, program("worker")).unwrap();
        assert!(out.contains("zone z.worker.01parent,"), "{out}");
    }

    /// #50: a child keeps its parent's escalation rights unless it narrows them, and can't be given
    /// one the parent lacks; a parent that may not ask doesn't ask a human for it either.
    #[test]
    fn escalation_rights_only_narrow() {
        let p = parent(4, &format!("{ZONE}  escalation: {{ request: false, grant: false }}\n"));
        let out = spawn(&p.ctx, program("worker")).unwrap();
        assert!(out.contains("zone z.worker.01parent,"), "inherited, so within: {out}");
        for (esc, needle) in [(json!({ "grant": true, "request": false }), "escalation.grant"), (json!({}), "escalation.request")] {
            let mut req = program("wider");
            req.zone.as_mut().unwrap()["escalation"] = esc;
            req.escalate = true;
            let e = spawn(&p.ctx, req).unwrap_err();
            assert!(e.contains(needle) && e.contains("escalation.request: false"), "{e}");
        }
        assert!(p.ctx.ledger.lock().unwrap().pending(&wicket_core::TenantId::single()).unwrap().is_empty(), "nobody asked");
    }

    /// #255: a program is an agent that may not ask: its zone's `escalation.request` is false unless
    /// the spawn says true (and the parent may ask), and that survives into its manifest.
    #[test]
    fn a_spawned_program_may_not_ask_unless_its_zone_says_so() {
        let p = parent(2, ZONE);
        let child = |p: &Parent| {
            let e =
                std::fs::read_dir(p.dir.join("children")).unwrap().flatten().find(|e| e.path().extension().is_some_and(|x| x == "yaml"));
            let y = std::fs::read_to_string(e.unwrap().path()).unwrap();
            wicket_agent::load(&y).unwrap()
        };
        spawn(&p.ctx, program("quiet")).unwrap();
        let m = child(&p);
        assert!(m.program.is_some() && !m.zone.escalation.request && m.zone.escalation.grant, "{:?}", m.zone.escalation);
        let q = parent(2, ZONE);
        let mut req = program("asks");
        req.zone.as_mut().unwrap()["escalation"] = json!({ "request": true });
        spawn(&q.ctx, req).unwrap();
        assert!(child(&q).zone.escalation.request);
    }

    /// #118: a different model route or credential is refused outright; a card for anything else
    /// beyond the parent is R4 and says, from wicket's record, what the child gets.
    #[test]
    fn beyond_parent_spawns_show_what_they_get() {
        let zone = "  llm: { secret: model-key }\n  reach:\n    - { host: api.example.com, methods: [GET] }\n  inject: [{ host: api.example.com, header: Authorization, format: \"Bearer {secret}\", secret: ex-token }]\n  limits: { memory: 1g, cpus: 1, timeout: 1h }\n";
        let p = parent(2, zone);
        let agent = |z: serde_json::Value| SpawnRequest {
            kind: "agent".into(),
            task: Some("work".into()),
            command: vec![],
            zone: Some(z),
            escalate: true,
            ..program("x")
        };
        for (z, needle) in [
            (json!({ "llm": { "upstream": "https://collector.example.net" } }), "upstream https://collector.example.net"),
            (json!({ "llm": { "secret": "other-key" } }), "secret other-key"),
            (
                json!({ "llm": {}, "inject": [{ "host": "collector.example.net", "header": "X-Key", "format": "{secret}", "secret": "ex-token" }] }),
                "inject secret ex-token into collector.example.net X-Key",
            ),
        ] {
            let e = spawn(&p.ctx, agent(z)).unwrap_err();
            assert!(e.contains("can't be started, with or without approval") && e.contains(needle), "{e}");
        }
        assert!(p.ctx.ledger.lock().unwrap().pending(&wicket_core::TenantId::single()).unwrap().is_empty());
        // The parent's own route, with an extra host and a hostile path: a card.
        let wide = json!({
            "llm": { "max_requests": 5 },
            "reach": [{ "host": "api.example.com", "methods": ["GET"] }, { "host": "other.example.org", "paths": ["/a\u{1b}]0;t\u{7}\u{202e}/**"] }],
            "inject": [{ "host": "api.example.com", "header": "Authorization", "format": "Bearer {secret}", "secret": "ex-token" }],
        });
        assert!(spawn(&p.ctx, agent(wide)).unwrap().starts_with("needs approval: request r-"));
        let l = p.ctx.ledger.lock().unwrap();
        let r = l.pending(&wicket_core::TenantId::single()).unwrap().pop().unwrap();
        assert_eq!((r.method.as_str(), r.host.as_str(), r.risk.as_str()), ("SPAWN", "wicket.internal", "R4ExecOrPrivilege"));
        for needle in [
            "model route anthropic via https://api.anthropic.com with secret model-key",
            "injects secret ex-token into api.example.com Authorization",
            "other.example.org",
            "It exceeds: reach rule 1",
            "uncapped input tokens",
            "accepts messages from none",
            "volumes none",
        ] {
            assert!(r.reason.contains(needle), "missing {needle:?} in {}", r.reason);
        }
        assert!(r.reason.chars().all(|c| !wicket_core::text::is_unsafe(c)), "{:?}", r.reason);
    }

    /// #369: a spawn beyond the parent is approved for exactly its arguments. While it is pending,
    /// the same child with other arguments waits on it; once granted, other arguments are refused
    /// and audited; the approved ones start it once, and a replay asks again instead of starting it.
    #[test]
    fn a_spawn_approval_is_for_exactly_its_arguments_once() {
        let zone = "  llm: { secret: model-key }\n  reach:\n    - { host: api.example.com, methods: [GET] }\n  limits: { memory: 1g, cpus: 1, timeout: 1h }\n";
        let p = parent(2, zone);
        let wide = |task: &str| SpawnRequest {
            kind: "agent".into(),
            task: Some(task.into()),
            command: vec![],
            zone: Some(
                json!({ "llm": { "max_requests": 5 }, "reach": [{ "host": "api.example.com", "methods": ["GET"] }, { "host": "other.example.org" }] }),
            ),
            escalate: true,
            ..program("worker")
        };
        let asked = spawn(&p.ctx, wide("build it")).unwrap();
        assert!(asked.starts_with("needs approval: request r-"), "{asked}");
        let pending = |p: &Parent| p.ctx.ledger.lock().unwrap().pending(&wicket_core::TenantId::single()).unwrap();
        let rid = pending(&p)[0].id.clone();
        // The effect is the child, by zone and name; its arguments are hashed beside it.
        let r = &pending(&p)[0];
        assert!(
            r.path.starts_with("/zones/") && r.path.ends_with("/worker") && r.args_sha256.as_ref().is_some_and(|a| a.len() == 64),
            "{r:?}"
        );
        // A sibling call for the same child with another task, while it is pending: it waits on it.
        let held = spawn(&p.ctx, wide("delete everything")).unwrap();
        assert!(held.starts_with(&format!("waiting: request {rid}")), "{held}");
        assert_eq!(pending(&p).len(), 1, "nothing else was asked");
        // Approved for "build it".
        p.ctx
            .ledger
            .lock()
            .unwrap()
            .approve(
                &rid,
                &wicket_store::Approval {
                    uses: Some(1),
                    ttl: std::time::Duration::from_secs(600),
                    path_prefix: None,
                    decided_by: "op".into(),
                },
            )
            .unwrap();
        let e = spawn(&p.ctx, wide("delete everything")).unwrap_err();
        assert!(e.contains("changed after the approval"), "{e}");
        let l = p.ctx.ledger.lock().unwrap();
        assert!(l.audit_tail(20).unwrap().iter().any(|r| r.2 == "effect.refused"), "the refusal is on the record");
        drop(l);
        let started = spawn(&p.ctx, wide("build it")).unwrap();
        assert!(!started.starts_with("needs approval") && !started.starts_with("waiting"), "{started}");
        // Its one use is taken: presented again, it doesn't start a second child, it asks again.
        let again = spawn(&p.ctx, wide("build it")).unwrap();
        assert!(again.starts_with("needs approval: request r-") && !again.contains(&rid), "{again}");
    }

    fn at(node: &str, lease: Option<&str>) -> Option<Placed> {
        Some(Placed { node: node.into(), lease: lease.map(String::from) })
    }

    #[test]
    fn placement_hints_resolve_only_to_where_the_parent_runs_or_to_leases_it_holds() {
        let mut l = Ledger::open_in_memory().unwrap();
        lease(&mut l, "l-mine", "r1", "active", "n-lease", NOW + 600);
        lease(&mut l, "l-old", "r1", "active", "n-old", NOW - 1);
        lease(&mut l, "l-wait", "r1", "approved", "", 0);
        lease(&mut l, "l-ask", "r1", "pending", "", 0);
        lease(&mut l, "l-theirs", "r2", "active", "n-theirs", NOW + 600);
        let p = |hint: serde_json::Value, own: Option<&str>| placement(&l, "r1", own, Some(&hint), NOW);

        // No hint: where the parent runs.
        assert_eq!(placement(&l, "r1", Some("n-own"), None, NOW).unwrap(), None);
        // A lease it holds and that is active: its node, recorded against the lease.
        assert_eq!(p(json!({"lease": "l-mine"}), None).unwrap(), at("n-lease", Some("l-mine")));
        // Someone else's lease, one past its end, one not ready yet, one that doesn't exist.
        assert!(p(json!({"lease": "l-theirs"}), None).unwrap_err().contains("no lease l-theirs held by this run"));
        assert!(p(json!({"lease": "l-old"}), None).unwrap_err().contains("has ended"));
        assert!(p(json!({"lease": "l-wait"}), None).unwrap_err().contains("is approved"));
        assert!(p(json!({"lease": "l-ask"}), None).unwrap_err().contains("is pending"));
        assert!(p(json!({"lease": "l-nope"}), None).is_err());
        // The parent's own node: no lease.
        assert_eq!(p(json!({"node": "n-own"}), Some("n-own")).unwrap(), at("n-own", None));
        // The node of a lease it holds: placed on that lease.
        assert_eq!(p(json!({"node": "n-lease"}), Some("n-own")).unwrap(), at("n-lease", Some("l-mine")));
        // Another run's lease node, or any other node: refused.
        assert!(p(json!({"node": "n-theirs"}), Some("n-own")).unwrap_err().contains("request_capacity"));
        assert!(p(json!({"node": "n-other"}), None).is_err());
        // A held lease's node, after the lease ended: refused.
        assert!(p(json!({"node": "n-old"}), None).unwrap_err().contains("has ended"));
        // Neither form.
        assert!(p(json!({"host": "x"}), None).unwrap_err().contains("placement must be"));
        assert!(p(json!("n-own"), Some("n-own")).is_err());
    }
}

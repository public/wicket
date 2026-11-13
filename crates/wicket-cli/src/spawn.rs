//! `spawn`: an agent starts another box, an agent or a program, in a zone it describes (design
//! §5.1). Authority only narrows: the zone must be a subset of the parent's (wicket_core::subset),
//! its model budget is carved out of the parent's, and it inherits the parent's forbid rules. A zone
//! beyond the parent's starts only if a human approved exactly that zone (bound by its digest).

use sha2::Digest;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use wicket_core::{subset, Manifest, Op, RunId, ZoneSpec};
use wicket_proxy::{llm::Llm, SpawnRequest};
use wicket_store::Ledger;

pub struct SpawnCtx {
    pub parent: Manifest,
    /// Box slots this run has reserved: each child takes one, plus the `max_children` it may start
    /// itself. Checked and charged under this lock, with the model budget carve-out, before a child
    /// is launched, and released if it fails to (#125).
    pub slots: Arc<Mutex<u32>>,
    /// The `wicket` binary children run as (`None`: this one). Tests point it elsewhere.
    pub exe: Option<PathBuf>,
    pub run: RunId,
    pub dir: PathBuf,
    pub image: String,
    pub node: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub ledger: Arc<Mutex<Ledger>>,
    pub children: Arc<Mutex<Vec<(String, std::process::Child)>>>,
    pub llm: Arc<OnceLock<Arc<Llm>>>,
    pub deadline: Instant,
    /// The parent's org layer (#51): what spawns the org policy allows it, whatever it is approved.
    pub org: Option<Arc<wicket_authz::OrgLayer>>,
}

/// The slots a run's children already hold (#125), from the children it has started (their spawn
/// records in `<run dir>/children/`): one each plus their own `max_children`, as `spawn` charged them,
/// at most `max`. A re-attached run (#151) starts from this, so a restart doesn't reset its bound.
/// Like a run that never restarted, a child that has ended still counts.
pub fn reserved_slots(dir: &std::path::Path, max: u32) -> u32 {
    let Ok(rd) = std::fs::read_dir(dir.join("children")) else { return 0 };
    let used = rd
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "yaml"))
        .map(|e| {
            let kids = std::fs::read_to_string(e.path())
                .ok()
                .and_then(|y| Manifest::from_yaml(&y).ok())
                .and_then(|m| m.agent.map(|a| a.max_children))
                .unwrap_or(0);
            kids.saturating_add(1)
        })
        .fold(0u32, u32::saturating_add);
    used.min(max)
}

pub fn spawner(c: SpawnCtx) -> wicket_proxy::Spawner {
    Arc::new(move |req| spawn(&c, req))
}

fn spawn(c: &SpawnCtx, req: SpawnRequest) -> Result<String, String> {
    let p = &c.parent;
    let pa = p.agent.as_ref().ok_or("only agents start boxes")?;
    let name = &req.name;
    let ok_name = !name.is_empty()
        && name.len() <= 32
        && name.starts_with(|ch: char| ch.is_ascii_lowercase())
        && name.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
    if !ok_name {
        return Err("name must match ^[a-z][a-z0-9-]{0,31}$".into());
    }
    // Everything up to the launch happens under the slot lock: concurrent calls see each other's
    // reservations, never the same free slots or the same budget (#125).
    let mut reserved = c.slots.lock().map_err(|_| "slots lock")?;
    let slots = pa.max_children.saturating_sub(*reserved);
    if slots == 0 {
        return Err(format!("this agent may start at most {} boxes (theirs included), and has used {}", pa.max_children, *reserved));
    }
    let time_left = c.deadline.saturating_duration_since(Instant::now());
    let llm_left = c.llm.get().and_then(|l| l.remaining());
    let llm_input_left = c.llm.get().and_then(|l| l.remaining_input());
    let is_agent = match req.kind.as_str() {
        "agent" => true,
        "program" => false,
        k => return Err(format!("kind must be agent or program, not {k:?}")),
    };

    // The child's zone: what the caller wrote, with omitted fields defaulted from the parent (never
    // wider than it), the parent's forbid rules prepended, and a name under the parent's that no
    // other run can make (#127): `<parent zone>.<name>.<parent run>`. A name has no dots and a run
    // id a fixed length, so two different (parent zone, name, run) never give the same zone name,
    // and none collides with another zone's grants, accept_from entries or volumes.
    let zone_name = format!("{}.{name}.{}", p.zone.name, c.run.0.strip_prefix("run_").unwrap_or(&c.run.0));
    let mut z: ZoneSpec = match &req.zone {
        Some(v) => {
            let mut v = v.clone();
            v["name"] = zone_name.clone().into();
            let obj = v.as_object_mut().ok_or("zone must be an object")?;
            if !obj.contains_key("isolation") {
                obj.insert("isolation".into(), serde_json::to_value(p.zone.isolation).unwrap_or_default());
            }
            if !obj.contains_key("unlisted_hosts") {
                obj.insert("unlisted_hosts".into(), serde_json::to_value(p.zone.unlisted_hosts).unwrap_or_default());
            }
            if !obj.contains_key("limits") {
                let mut l = serde_json::to_value(&p.zone.limits).unwrap_or_default();
                l["timeout"] = format!("{}s", time_left.as_secs()).into();
                obj.insert("limits".into(), l);
            }
            // A model section that omits the route gets the parent's own (any other is refused).
            if let (Some(llm), Some(pl)) = (obj.get_mut("llm").and_then(|l| l.as_object_mut()), &p.zone.llm) {
                for (k, val) in [("provider", &pl.provider), ("secret", &pl.secret), ("upstream", &pl.upstream)] {
                    llm.entry(k).or_insert_with(|| val.clone().into());
                }
            }
            serde_json::from_value(v).map_err(|e| format!("zone: {e}"))?
        }
        None => {
            let mut z = p.zone.clone();
            z.name = zone_name.clone();
            z.limits.timeout = format!("{}s", time_left.as_secs());
            if let Some(hosts) = &req.reach_hosts {
                z.reach.retain(|r| hosts.contains(&r.host));
                z.inject.retain(|i| hosts.contains(&i.host));
            }
            z.forbid.clear(); // re-added from the parent below
            z.volumes.clear(); // a new zone starts with its own state
            z
        }
    };
    z.forbid = p.zone.forbid.iter().cloned().chain(z.forbid).collect();
    if is_agent {
        let derived_from_parent = req.zone.as_ref().is_none_or(|v| v.get("llm").is_none());
        if derived_from_parent {
            // Half of what the parent has left, unless the caller says otherwise.
            if let (Some(pl), Some((r, t))) = (&p.zone.llm, llm_left) {
                let mut l = pl.clone();
                l.max_requests = (r / 2).max(1);
                l.max_output_tokens = (t / 2).max(1);
                l.max_input_tokens = llm_input_left.map(|i| (i / 2).max(1));
                z.llm = Some(l);
            }
        }
    } else if z.llm.is_some() {
        return Err("a program has no model route: remove zone.llm".into());
    }
    let image = req.image.clone().unwrap_or_else(|| c.image.clone());
    let images: Vec<String> = std::iter::once(c.image.clone()).chain(p.zone.images.iter().cloned()).collect();

    // The child manifest.
    let mut cm = p.clone();
    cm.zone = z;
    if is_agent {
        let task = req.task.clone().filter(|t| !t.trim().is_empty()).ok_or("an agent needs a task")?;
        cm.task = task;
        let mut a = pa.clone();
        a.name = name.clone();
        a.max_children = req.max_children;
        a.idle_timeout = "0s".into(); // a child reports to its parent, not the operator
        cm.agent = Some(a);
        cm.program = None;
    } else {
        if req.command.is_empty() {
            return Err("a program needs a command".into());
        }
        cm.task = format!("program {name}");
        cm.agent = None;
        cm.program = Some(wicket_core::ProgramSpec {
            name: name.clone(),
            command: req.command.clone(),
            source: None,
            digest: None,
            on_pending: wicket_core::OnPending::Fail,
            image: None,
        });
    }
    cm.validate().map_err(|e| format!("the new manifest is invalid: {e}"))?;
    // The org policy's spawn rule is hard: no approval lifts it (#51).
    if let Some(org) = &c.org {
        let s = wicket_authz::Ceiling::from_zone(&cm.zone, "child", 0, vec![]).map_err(|e| e.to_string())?.spawn;
        if !org.allows_spawn(&image, s.min_isolation, s.mem_bytes, s.cpus_milli, s.pids, s.timeout_s) {
            return Err(format!(
                "the org policy ({}) doesn't allow this spawn (image {image}, isolation {}, {} bytes of memory, {} millicpus, {} pids, {} s): narrow it",
                org.version, s.min_isolation, s.mem_bytes, s.cpus_milli, s.pids, s.timeout_s
            ));
        }
    }
    let yaml = serde_yaml::to_string(&cm).map_err(|e| e.to_string())?;
    // An approval binds to the request as the agent stated it (defaults derived at call time, such
    // as the time left, would change between the ask and the retry).
    let mut stated = serde_json::json!({
        "name": name, "kind": req.kind, "task": req.task, "command": req.command, "image": image,
        "zone": req.zone, "reach_hosts": req.reach_hosts, "max_children": req.max_children,
    });
    if let Some(p) = &req.placement {
        stated["placement"] = p.clone();
    }
    // Where it runs: decided before anything is asked or carved, so a bad hint costs nothing.
    let placed = {
        let l = c.ledger.lock().map_err(|_| "ledger lock")?;
        placement(&l, &c.run.0, c.node.as_deref(), req.placement.as_ref(), wicket_store::now())?
    };
    let digest = hex::encode(sha2::Sha256::digest(stated.to_string().as_bytes()));

    // Within the parent's authority, or approved by a human for exactly this zone. A different model
    // route or credential is never approvable (#118).
    let hard = subset::unapprovable(&cm.zone, &p.zone);
    if !hard.is_empty() {
        return Err(format!("this zone can't be started, with or without a human:\n- {}", hard.join("\n- ")));
    }
    let bounds = subset::Bounds {
        zone: &p.zone,
        images,
        llm_remaining: llm_left,
        llm_input_remaining: llm_input_left,
        time_remaining: time_left,
        child_slots: slots,
    };
    let ask = subset::Ask { zone: &cm.zone, image: &image, max_children: req.max_children };
    let mut beyond = false;
    if let Err(violations) = subset::check(&ask, &bounds) {
        let mut op =
            Op::egress(&p.tenant, &c.run, &p.zone.name, "SPAWN", "wicket.internal", &format!("/zones/{zone_name}/{}", &digest[..16]));
        // Beyond the parent's authority is never a one-click "allow for an hour" (#118).
        op.risk = wicket_core::RiskClass::R4ExecOrPrivilege;
        let mut l = c.ledger.lock().map_err(|_| "ledger lock")?;
        match l.consume_grant(&op).map_err(|e| e.to_string())? {
            Some(gid) => {
                beyond = true;
                let _ = l.audit(
                    &p.tenant,
                    Some(&c.run),
                    "spawn.beyond_parent",
                    &serde_json::json!({ "zone": zone_name, "grant": gid, "exceeds": violations }),
                );
            }
            None if !req.ask_human => {
                return Err(format!(
                    "this zone is not within yours:\n- {}\nNarrow it, or call spawn again with ask_human: true to ask a human to approve exactly this zone.",
                    violations.join("\n- ")
                ));
            }
            None => {
                if let Ok(Some(rid)) = l.denied_recently(&op) {
                    return Err(format!("a human denied exactly this zone ({rid}) a few minutes ago; don't ask again"));
                }
                let reason = card(&req.kind, name, &image, &cm, &violations);
                let (rid, _) = l.pending_for(&op, &reason, None).map_err(|e| e.to_string())?;
                return Ok(format!(
                    "needs human approval: request {rid} (this zone exceeds yours: {}). Call await_grant with {rid}; once granted, call spawn again with exactly the same arguments.",
                    violations.join("; ")
                ));
            }
        }
    }

    // Reserve: the child's slots (its own and its max_children, so descendants are bounded by this
    // agent's max_children, not 2^k) and its model budget, carved out of the parent's.
    let weight = req.max_children.saturating_add(1).min(slots);
    *reserved += weight;
    let carve = match (&cm.zone.llm, c.llm.get()) {
        (Some(cl), Some(llm)) => {
            use std::sync::atomic::Ordering;
            llm.reserved_requests.fetch_add(cl.max_requests, Ordering::SeqCst);
            llm.reserved_output_tokens.fetch_add(cl.max_output_tokens, Ordering::SeqCst);
            llm.reserved_input_tokens.fetch_add(cl.max_input_tokens.unwrap_or(0), Ordering::SeqCst);
            Some((llm.clone(), cl.max_requests, cl.max_output_tokens, cl.max_input_tokens.unwrap_or(0)))
        }
        _ => None,
    };
    drop(reserved);
    let launched = launch(c, &yaml, &image, placed.as_ref());
    let child = match launched {
        Ok(child) => child,
        Err(e) => {
            // Nothing started: give the slots and the budget back.
            if let Ok(mut r) = c.slots.lock() {
                *r = r.saturating_sub(weight);
            }
            if let Some((llm, r, t, i)) = carve {
                use std::sync::atomic::Ordering;
                llm.reserved_requests.fetch_sub(r, Ordering::SeqCst);
                llm.reserved_output_tokens.fetch_sub(t, Ordering::SeqCst);
                llm.reserved_input_tokens.fetch_sub(i, Ordering::SeqCst);
            }
            return Err(e);
        }
    };
    let budget =
        cm.zone.llm.as_ref().map(|l| format!(", a model budget of {} requests carved from yours", l.max_requests)).unwrap_or_default();
    let at = placed.as_ref().map(|p| format!(" on node {}", p.node)).unwrap_or_default();
    Ok(format!(
        "started {} {name} as run {}{at}: its own box and identity, zone {zone_name}{}{budget}. {}",
        req.kind,
        child,
        if beyond { " (approved by a human beyond your own zone)" } else { ", within your own" },
        if is_agent {
            "Use await_message for its messages and its final run_finished."
        } else {
            "It sends you run_finished when it exits."
        }
    ))
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
            "model route {} via {} with secret {} (this zone's own), {} requests, {} output tokens, {} input tokens{}",
            clip(&l.provider, 40),
            clip(&l.upstream, 200),
            clip(&l.secret, 80),
            l.max_requests,
            l.max_output_tokens,
            l.max_input_tokens.map(|i| i.to_string()).unwrap_or_else(|| "uncapped".into()),
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
                format!(
                    "{} {} {}{}",
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

/// Starts the child: another `wicket run`, with its own box, sockets, proxies and identity. Returns
/// its run id once it has recorded its identity (or exited, or 10 s passed).
fn launch(c: &SpawnCtx, yaml: &str, image: &str, placed: Option<&Placed>) -> Result<String, String> {
    let child = RunId::new();
    let cdir = c.dir.join("children");
    std::fs::create_dir_all(&cdir).map_err(|e| e.to_string())?;
    let yaml_path = cdir.join(format!("{}.yaml", child.0));
    std::fs::write(&yaml_path, yaml).map_err(|e| e.to_string())?;
    let log = std::fs::File::create(cdir.join(format!("{}.log", child.0))).map_err(|e| e.to_string())?;
    let exe = match &c.exe {
        Some(e) => e.clone(),
        None => crate::update::self_exe().map_err(|e| e.to_string())?,
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["run", "--run-id", &child.0, "--parent-run", &c.run.0, "--image", image]);
    match placed {
        Some(p) => {
            cmd.args(["--node", &p.node]);
            match &p.lease {
                Some(lease) => {
                    cmd.args(["--lease", lease]);
                }
                // The parent's own node: reached the way the parent reaches it. A lease's node
                // carries the key it was enrolled with.
                None => {
                    if let Some(k) = &c.ssh_key {
                        cmd.arg("--ssh-key").arg(k);
                    }
                }
            }
        }
        None => {
            if let Some(n) = &c.node {
                cmd.args(["--node", n]);
            }
            if let Some(k) = &c.ssh_key {
                cmd.arg("--ssh-key").arg(k);
            }
        }
    }
    let log2 = log.try_clone().map_err(|e| e.to_string())?;
    cmd.arg(&yaml_path).stdin(std::process::Stdio::null()).stdout(log2).stderr(log);
    let mut proc = match cmd.spawn() {
        Ok(p) => p,
        Err(e) => {
            // Never started: no spawn record, so a re-attach doesn't count it (`reserved_slots`).
            let _ = std::fs::remove_file(&yaml_path);
            return Err(format!("starting the box: {e}"));
        }
    };
    // The child records its identity before its box starts; wait for it so the parent can message it.
    for _ in 0..100 {
        if matches!(proc.try_wait(), Ok(Some(_))) {
            break;
        }
        if c.ledger.lock().ok().and_then(|l| l.identity(&child.0).ok().flatten()).is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    c.children.lock().map_err(|_| "children lock")?.push((child.0.clone(), proc));
    Ok(child.0)
}

/// Where a child runs, from `spawn`'s placement hint.
#[derive(Debug, PartialEq, Eq)]
pub struct Placed {
    /// The enrolled node (`wicket run --node`).
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

    fn parent(max: u32, zone: &str) -> Parent {
        let dir = std::env::temp_dir().join(format!("wicket-spawn-test-{}-{}", std::process::id(), wicket_core::new_request_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let m = Manifest::from_yaml(&format!("task: t\nagent: {{ name: lead, max_children: {max} }}\nzone:\n  name: z\n{zone}")).unwrap();
        let ctx = SpawnCtx {
            parent: m,
            slots: Default::default(),
            exe: Some("/bin/true".into()),
            run: RunId("run_01parent".into()),
            dir: dir.clone(),
            image: "img:a".into(),
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
            ask_human: false,
            reach_hosts: None,
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

    /// #125: a launch that fails gives its slots back.
    #[test]
    fn a_failed_launch_releases_its_slot() {
        let mut p = parent(1, ZONE);
        Arc::get_mut(&mut p.ctx).unwrap().exe = Some("/nonexistent/wicket".into());
        assert!(spawn(&p.ctx, program("a")).unwrap_err().contains("starting the box"));
        assert_eq!(*p.ctx.slots.lock().unwrap(), 0);
        Arc::get_mut(&mut p.ctx).unwrap().exe = Some("/bin/true".into());
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
            exe: Some("/bin/true".into()),
            run: p.ctx.run.clone(),
            dir: p.dir.clone(),
            image: "img:a".into(),
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
        Arc::get_mut(&mut q.ctx).unwrap().exe = Some("/nonexistent/wicket".into());
        assert!(spawn(&q.ctx, program("a")).is_err());
        assert_eq!(reserved_slots(&q.dir, 1), 0);
    }

    /// #127: a spawned zone's name carries the parent run, so no other run can make it.
    #[test]
    fn spawned_zone_names_are_unique_to_the_parent_run() {
        let p = parent(1, ZONE);
        let out = spawn(&p.ctx, program("worker")).unwrap();
        assert!(out.contains("zone z.worker.01parent,"), "{out}");
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
            ask_human: true,
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
            assert!(e.contains("can't be started, with or without a human") && e.contains(needle), "{e}");
        }
        assert!(p.ctx.ledger.lock().unwrap().pending(&wicket_core::TenantId::single()).unwrap().is_empty());
        // The parent's own route, with an extra host and a hostile path: a card.
        let wide = json!({
            "llm": { "max_requests": 5 },
            "reach": [{ "host": "api.example.com", "methods": ["GET"] }, { "host": "other.example.org", "paths": ["/a\u{1b}]0;t\u{7}\u{202e}/**"] }],
            "inject": [{ "host": "api.example.com", "header": "Authorization", "format": "Bearer {secret}", "secret": "ex-token" }],
        });
        assert!(spawn(&p.ctx, agent(wide)).unwrap().starts_with("needs human approval: request r-"));
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

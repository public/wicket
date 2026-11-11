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
    pub run: RunId,
    pub dir: PathBuf,
    pub image: String,
    pub node: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub ledger: Arc<Mutex<Ledger>>,
    pub children: Arc<Mutex<Vec<(String, std::process::Child)>>>,
    pub llm: Arc<OnceLock<Arc<Llm>>>,
    pub deadline: Instant,
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
    let started = c.children.lock().map_err(|_| "children lock")?.len() as u32;
    let slots = pa.max_children.saturating_sub(started);
    if slots == 0 {
        return Err(format!("this agent may start at most {} boxes, and has started {started}", pa.max_children));
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
    // wider than it), the parent's forbid rules prepended, and a name under the parent's.
    let zone_name = format!("{}.{name}", p.zone.name);
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

    // Within the parent's authority, or approved by a human for exactly this zone.
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
        let op = Op::egress(&p.tenant, &c.run, &p.zone.name, "SPAWN", "wicket.internal", &format!("/zones/{zone_name}/{}", &digest[..16]));
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
                let reason = format!("start {} {name} in zone {zone_name}, beyond this agent's own: {}", req.kind, violations.join("; "));
                let (rid, _) = l.pending_for(&op, &reason, None).map_err(|e| e.to_string())?;
                return Ok(format!(
                    "needs human approval: request {rid} (this zone exceeds yours: {}). Call await_grant with {rid}; once granted, call spawn again with exactly the same arguments.",
                    violations.join("; ")
                ));
            }
        }
    }

    // Carve the child's model budget out of the parent's.
    if let (Some(cl), Some(llm)) = (&cm.zone.llm, c.llm.get()) {
        use std::sync::atomic::Ordering;
        llm.reserved_requests.fetch_add(cl.max_requests, Ordering::SeqCst);
        llm.reserved_output_tokens.fetch_add(cl.max_output_tokens, Ordering::SeqCst);
        if let Some(i) = cl.max_input_tokens {
            llm.reserved_input_tokens.fetch_add(i, Ordering::SeqCst);
        }
    }

    // Launch: another `wicket run`, with its own box, sockets, proxies and identity.
    let child = RunId::new();
    let cdir = c.dir.join("children");
    std::fs::create_dir_all(&cdir).map_err(|e| e.to_string())?;
    let yaml_path = cdir.join(format!("{}.yaml", child.0));
    std::fs::write(&yaml_path, &yaml).map_err(|e| e.to_string())?;
    let log = std::fs::File::create(cdir.join(format!("{}.log", child.0))).map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    cmd.args(["run", "--run-id", &child.0, "--parent-run", &c.run.0, "--image", &image]);
    match &placed {
        Some(p) => {
            cmd.args(["--node", &p.node]);
            if let Some(lease) = &p.lease {
                cmd.args(["--lease", lease]);
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
    let proc = cmd.spawn().map_err(|e| format!("starting the box: {e}"))?;
    // The child records its identity before its box starts; wait for it so the parent can message it.
    for _ in 0..100 {
        if Ledger::open(&crate::ledger_path()).ok().and_then(|l| l.identity(&child.0).ok().flatten()).is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    c.children.lock().map_err(|_| "children lock")?.push((child.0.clone(), proc));
    let budget =
        cm.zone.llm.as_ref().map(|l| format!(", a model budget of {} requests carved from yours", l.max_requests)).unwrap_or_default();
    let at = placed.as_ref().map(|p| format!(" on node {}", p.node)).unwrap_or_default();
    Ok(format!(
        "started {} {name} as run {}{at}: its own box and identity, zone {zone_name}{}{budget}. {}",
        req.kind,
        child.0,
        if beyond { " (approved by a human beyond your own zone)" } else { ", within your own" },
        if is_agent {
            "Use await_message for its messages and its final run_finished."
        } else {
            "It sends you run_finished when it exits."
        }
    ))
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
pub fn placement(l: &Ledger, run: &str, own_node: Option<&str>, hint: Option<&serde_json::Value>, now: i64) -> Result<Option<Placed>, String> {
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
            o == n || l.node(n).ok().flatten().is_some_and(|r| r.target == o) || l.node_by_target(o).ok().flatten().is_some_and(|r| r.name == n)
        });
        if own {
            return Ok(Some(Placed { node: n.to_string(), lease: None }));
        }
        let held = l.leases(&["active"]).map_err(|e| e.to_string())?.into_iter().find(|x| x.run == run && x.node_name.as_deref() == Some(n));
        if let Some(x) = held {
            let (lease, node) = lease_ok(&x.id)?;
            return Ok(Some(Placed { node, lease: Some(lease) }));
        }
        return Err(format!("node {n} is neither where this agent runs nor the node of a lease it holds: ask for one with request_capacity"));
    }
    Err("placement must be {\"lease\": \"l-…\"} or {\"node\": \"<name>\"}".into())
}

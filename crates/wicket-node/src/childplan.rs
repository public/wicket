//! A spawn's plan (#164): deciding a child's zone and manifest from the parent's, without side
//! effects, on the control host (wicket-cli's `spawn`, which re-exports it) or on the parent's node.

use wicket_core::{subset, Manifest, RunId, ZoneSpec};
use wicket_proxy::SpawnRequest;

/// What deciding a spawn needs to know of the parent, wherever it is decided: on the control host
/// ([`spawn`]), or on the parent's node from its token and slice (#164).
pub struct PlanIn<'a> {
    pub parent: &'a Manifest,
    pub run: &'a RunId,
    /// The parent's own image (a child may always start it).
    pub image: &'a str,
    pub time_left: std::time::Duration,
    pub llm_left: Option<(u64, u64)>,
    pub llm_input_left: Option<u64>,
    /// Box slots the parent has free.
    pub slots: u32,
    /// The parent's org layer (#51).
    pub org: Option<&'a wicket_authz::OrgLayer>,
}

/// A spawn, decided: the child's manifest and what it was checked against.
pub struct ChildPlan {
    pub cm: Manifest,
    pub yaml: String,
    /// The image the child starts as: pinned (`name@sha256:…`) when what allows it is (#192).
    pub image: String,
    /// The allowed entry that lets it start (a zone's `images`, or the parent's own image): what the
    /// org policy and the parent's token decide on.
    pub image_entry: String,
    /// The digest the child's image must be where it starts, if pinned.
    pub image_pin: Option<String>,
    pub zone_name: String,
    /// The digest of the request as the agent stated it (what an approval binds to).
    pub digest: String,
    /// What it exceeds of the parent's authority (empty: within it).
    pub violations: Vec<String>,
    /// The slots it takes: its own, and the boxes it may start.
    pub weight: u32,
    pub is_agent: bool,
}

/// Decides a spawn without side effects: the child's zone and manifest from the request (omitted
/// fields from the parent, never wider), the org policy's spawn rule (hard), what no human may
/// approve (refused), and what exceeds the parent's authority (`violations`, for a human).
pub fn plan_child(i: &PlanIn, req: &SpawnRequest) -> Result<ChildPlan, String> {
    let p = i.parent;
    let pa = p.agent.as_ref().ok_or("only agents start boxes")?;
    let name = &req.name;
    let ok_name = !name.is_empty()
        && name.len() <= 32
        && name.starts_with(|ch: char| ch.is_ascii_lowercase())
        && name.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
    if !ok_name {
        return Err("name must match ^[a-z][a-z0-9-]{0,31}$".into());
    }
    let slots = i.slots;
    if slots == 0 {
        return Err(format!("this agent may start at most {} boxes (theirs included), and has used them all", pa.max_children));
    }
    let time_left = i.time_left;
    let (llm_left, llm_input_left) = (i.llm_left, i.llm_input_left);
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
    let zone_name = format!("{}.{name}.{}", p.zone.name, i.run.0.strip_prefix("run_").unwrap_or(&i.run.0));
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
            if !obj.contains_key("escalation") {
                obj.insert("escalation".into(), serde_json::to_value(p.zone.escalation).unwrap_or_default());
            }
            if !obj.contains_key("wildcards") {
                obj.insert("wildcards".into(), serde_json::to_value(p.zone.wildcards).unwrap_or_default());
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
            z.forbid.clear(); // re-added from the parent below
            z.volumes.clear(); // a new zone starts with its own state
            z
        }
    };
    z.forbid = p.zone.forbid.iter().cloned().chain(z.forbid).collect();
    // The parent's memory advice (#348), unless the caller's limits give their own (empty: none).
    let said_advice = req.zone.as_ref().and_then(|v| v.get("limits")).is_some_and(|l| l.get("memory_advice").is_some());
    if !said_advice {
        z.limits.memory_advice = p.zone.limits.memory_advice.clone();
    }
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
    } else {
        if z.llm.is_some() {
            return Err("a program has no model route: remove zone.llm".into());
        }
        // A program may not ask for more unless the request says so (#255), within what its
        // parent's zone may (the subset check below).
        let said = req.zone.as_ref().and_then(|v| v.get("escalation")).and_then(|e| e.get("request")).and_then(|r| r.as_bool());
        z.escalation.request = said.unwrap_or(false);
    }
    let image = req.image.clone().unwrap_or_else(|| i.image.to_string());
    let images: Vec<String> = std::iter::once(i.image.to_string()).chain(p.zone.images.iter().cloned()).collect();
    // By digest where pinned (#192): the entry that allows it, and the digest the box must be.
    let matched = wicket_core::image::matching(&image, &images);
    let image_entry = matched.as_ref().map(|m| m.0.clone()).unwrap_or_else(|| image.clone());
    let image_pin = matched.and_then(|m| m.1);

    // The child manifest.
    let mut cm = p.clone();
    cm.zone = z;
    if is_agent {
        let task = req.task.clone().filter(|t| !t.trim().is_empty()).ok_or("an agent needs a task")?;
        cm.task = task;
        let mut a = pa.clone();
        a.name = name.clone();
        a.max_children = req.max_children;
        a.image = None; // the image checked above, passed to its run with --image
        cm.agent = Some(a);
        cm.program = None;
    } else {
        if req.command.is_empty() {
            return Err("a program needs a command".into());
        }
        cm.task = format!("program {name}");
        cm.agent = None;
        cm.program =
            Some(wicket_core::ProgramSpec { name: name.clone(), command: req.command.clone(), source: None, digest: None, image: None });
    }
    cm.validate().map_err(|e| format!("the new manifest is invalid: {e}"))?;
    // The org policy's spawn rule is hard: no approval lifts it (#51).
    if let Some(org) = i.org {
        let s = wicket_authz::Ceiling::from_zone(&cm.zone, "child", 0, vec![]).map_err(|e| e.to_string())?.spawn;
        if !org.allows_spawn(&image_entry, s.min_isolation, s.mem_bytes, s.cpus_milli, s.pids, s.timeout_s) {
            return Err(format!(
                "the org policy ({}) doesn't allow this spawn (image {image}, isolation {}, {} bytes of memory, {} millicpus, {} pids, {} s): narrow it",
                org.version, s.min_isolation, s.mem_bytes, s.cpus_milli, s.pids, s.timeout_s
            ));
        }
    }
    let yaml = wicket_core::yaml::to_string(&cm).map_err(|e| e.to_string())?;
    // An approval binds to the request as the agent stated it (defaults derived at call time, such
    // as the time left, would change between the ask and the retry).
    let mut stated = serde_json::json!({
        "name": name, "kind": req.kind, "task": req.task, "command": req.command, "image": image,
        "zone": req.zone, "max_children": req.max_children,
    });
    if let Some(p) = &req.placement {
        stated["placement"] = p.clone();
    }
    // Its canonical JSON's hash (#369): the arguments in the effect descriptor the approval signs.
    let digest = wicket_core::effect::args_sha256(&stated);

    // Within the parent's authority, or approved by a human for exactly this zone. A different model
    // route or credential is never approvable (#118).
    let hard = subset::unapprovable(&cm.zone, &p.zone);
    if !hard.is_empty() {
        return Err(format!("this zone can't be started, with or without approval:\n- {}", hard.join("\n- ")));
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
    let violations = subset::check(&ask, &bounds).err().unwrap_or_default();
    let weight = req.max_children.saturating_add(1).min(slots);
    let image = match &image_pin {
        Some(pin) => wicket_core::image::pinned(&image, pin),
        None => image,
    };
    Ok(ChildPlan { cm, yaml, image, image_entry, image_pin, zone_name, digest, violations, weight, is_agent })
}

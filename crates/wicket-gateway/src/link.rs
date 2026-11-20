//! Links between boxes (issue #6): `expose`, `connect`, `link`, relayed by wicket.
//!
//! Boxes still have no network. A link from box A to port P of box B is:
//! - in A, a listener on `<name>.wicket.internal:P` (an address from the link pool, which
//!   `wicket-entry` put on A's loopback at start, and a line in A's hosts file, which wicket owns),
//!   forwarding to a unix socket in A's socket directory;
//! - on A's node, that socket, each connection to it relayed to the process that opened the link
//!   (`BoxOps::accept`), which opens a byte stream to 127.0.0.1:P inside B on B's node
//!   (`BoxOps::dial`) and copies bytes between the two.
//!
//! A and B may be on any nodes, this host's own included (#146): the relay reaches each over its
//! node's authenticated control channel, so a link across nodes passes through the control host.
//!
//! The process that opens a link runs its relay, and checks the ledger every couple of seconds: the
//! link is closed (and its live connections dropped) once it's cut (`unlink`, `wicket unlink`),
//! either end's identity or an ancestor's is revoked, or either run ends. Every link is recorded in
//! the ledger and the audit log.
//!
//! Policy is `wicket_core::link`. Data labels (design §4.2) do not cross links yet: wicket has no
//! label mechanism to carry, so a link's audit record notes that.

use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use wicket_core::link::{self as policy, Decision, End, Named};
use wicket_core::{Op, ZoneSpec};
use wicket_proxy::link::{BoxOps, Stream, LABELS, POLL};
use wicket_proxy::{Event, RunCtx};
use wicket_store::{EffectUse, Filed, LinkRow};

type Reply = (String, bool);

fn ledger(ctx: &RunCtx) -> std::sync::MutexGuard<'_, wicket_store::Ledger> {
    ctx.ledger.lock().expect("ledger")
}

/// `expose(port, name?)`: this box offers `port` to boxes its `accept_from` lists, by zone or by
/// principal (and to others a human approves). Its parent doesn't need it.
pub fn expose(ctx: &RunCtx, port: u16, name: Option<&str>) -> Reply {
    if port == 0 {
        return ("`port` must be 1-65535".into(), true);
    }
    let name = name.map(policy::label);
    let zone = match serde_json::to_string(&**ctx.zone) {
        Ok(z) => z,
        Err(e) => return (e.to_string(), true),
    };
    let l = ledger(ctx);
    if let Err(e) = l.expose(&ctx.tenant, &ctx.run.0, port, name.as_deref(), &zone) {
        return (e.to_string(), true);
    }
    // The box's own now, whatever exposed it before: no name's move takes it away (#668).
    let _ = l.drop_name_exposure(&ctx.run, port);
    // On the record before it takes effect (fail closed).
    if let Err(e) = l.audit(&ctx.tenant, Some(&ctx.run), "link.expose", &serde_json::json!({ "port": port, "name": name })) {
        let _ = l.unexpose(&ctx.run.0, port);
        return (format!("not exposed: the audit record could not be written ({e})"), true);
    }
    let who = if ctx.zone.accept_from.is_empty() {
        "your parent (always), and boxes an operator approves".to_string()
    } else {
        format!(
            "your parent, boxes your accept_from lists by zone or principal ({}), and boxes an operator approves",
            ctx.zone.accept_from.join(", ")
        )
    };
    (
        format!(
            "exposed port {port}{}: {who} may connect to it with connect(box: \"{}\", port: {port}). Listen on 127.0.0.1:{port} (or 0.0.0.0) in this box.",
            name.map(|n| format!(" as {n}")).unwrap_or_default(),
            ctx.run.0
        ),
        false,
    )
}

/// Resolves a box argument: a run id, "parent", or the name of one of the caller's children.
fn resolve(ctx: &RunCtx, b: &str) -> Result<String, String> {
    if b == "self" || b == ctx.run.0 {
        return Ok(ctx.run.0.clone());
    }
    if b == "parent" {
        return ctx.identity.as_ref().and_then(|i| i.current().claims.parent_run.clone()).ok_or_else(|| "this box has no parent".into());
    }
    if b.starts_with("run_") {
        return Ok(b.to_string());
    }
    let l = ledger(ctx);
    let kids: Vec<_> = l
        .children(&ctx.run.0)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|c| c.agent == b && l.run_status(&c.run).ok().flatten().as_deref() == Some("running"))
        .collect();
    match kids.as_slice() {
        [one] => Ok(one.run.clone()),
        [] => Err(format!("no running child named {b}: give a run id")),
        _ => Err(format!("several running children are named {b}: give a run id")),
    }
}

/// What the ledger knows about one end, checked usable: same tenant, running, not revoked.
struct EndInfo {
    run: String,
    agent: String,
    parent_run: Option<String>,
    zone_name: String,
    principal: String,
    accept_from: Vec<String>,
    zone: Option<ZoneSpec>,
}

impl EndInfo {
    fn end(&self) -> End<'_> {
        End {
            run: &self.run,
            parent_run: self.parent_run.as_deref(),
            zone_name: &self.zone_name,
            principal: Some(&self.principal),
            accept_from: &self.accept_from,
            zone: self.zone.as_ref(),
        }
    }
}

fn end_info(ctx: &RunCtx, ops: &dyn BoxOps, run: &str, port: Option<u16>) -> Result<(EndInfo, Option<wicket_store::ExposeRow>), String> {
    let (rec, exposed) = {
        let l = ledger(ctx);
        let rec = match l.identity(run).map_err(|e| e.to_string())? {
            Some(r) if r.tenant == ctx.tenant.0 => r,
            _ => return Err(format!("no box {run}")),
        };
        if l.run_status(run).map_err(|e| e.to_string())?.as_deref() != Some("running") {
            return Err(format!("box {} ({run}) is not running", rec.agent));
        }
        if let Some((r, ..)) = l.revoked_in_chain(run).map_err(|e| e.to_string())? {
            return Err(format!("box {run}'s identity was revoked (revoked: {r})"));
        }
        let exposed = match port {
            Some(p) => l.exposed(run, p).map_err(|e| e.to_string())?,
            None => None,
        };
        (rec, exposed)
    };
    let zone = if run == ctx.run.0 {
        Some((**ctx.zone).clone())
    } else if rec.parent_run.as_deref() == Some(&ctx.run.0) {
        ops.child_zone(run)
    } else {
        None
    }
    .or_else(|| exposed.as_ref().and_then(|e| serde_json::from_str(&e.zone).ok()));
    Ok((
        EndInfo {
            run: run.into(),
            agent: rec.agent,
            parent_run: rec.parent_run,
            zone_name: rec.zone,
            principal: rec.spiffe_id,
            accept_from: rec.accept_from,
            zone,
        },
        exposed,
    ))
}

fn check_port(port: Option<u64>) -> Result<u16, String> {
    match port {
        Some(p) if (1..=65535).contains(&p) => Ok(p as u16),
        _ => Err("`port` is required: 1-65535".into()),
    }
}

/// `connect(box, port)`: this box reaches `port` of `target`.
pub async fn connect(ctx: &RunCtx, target: &str, port: Option<u64>) -> Reply {
    match connect_inner(ctx, target, port).await {
        Ok(s) => (s, false),
        Err(e) => (format!("not linked: {e}"), true),
    }
}

async fn connect_inner(ctx: &RunCtx, target: &str, port: Option<u64>) -> Result<String, String> {
    let ops = ctx.boxes.clone().ok_or("links need a box wicket runs on a node (this one can't link)")?;
    let port = check_port(port)?;
    let to = resolve(ctx, target)?;
    let (me, _) = end_info(ctx, &*ops, &ctx.run.0, None)?;
    let (t, exposed) = end_info(ctx, &*ops, &to, Some(port))?;
    let d = policy::connect(&me.end(), &t.end(), exposed.is_some())?;
    let wanted = exposed.and_then(|e| e.name).unwrap_or_else(|| t.agent.clone());
    open(ctx, ops, &me, &t, port, d, LinkName::Label(&wanted)).await
}

/// `connect(name, port?)` (#575): this box reaches the box holding internal name `name`
/// (`<label>.<zone>`, with or without `.wicket.internal`), at the name's port. Decided as
/// `connect` decides; the link is named after the name, so the box resolves it too.
pub async fn connect_name(ctx: &RunCtx, name: &str, port: Option<u64>) -> Reply {
    match connect_name_inner(ctx, name, port).await {
        Ok(s) => (s, false),
        Err(e) => (format!("not linked: {e}"), true),
    }
}

async fn connect_name_inner(ctx: &RunCtx, name: &str, port: Option<u64>) -> Result<String, String> {
    let ops = ctx.boxes.clone().ok_or("links need a box wicket runs on a node (this one can't link)")?;
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let n = n.strip_suffix(&format!(".{}", policy::DOMAIN)).unwrap_or(&n);
    let (label, zone) = n.split_once('.').ok_or_else(|| format!("{name:?} isn't an internal name: <name>.<zone>"))?;
    // The one DNS form names are registered under (#575 review, M3).
    let zone = wicket_names::zone_part(zone).map_err(|e| format!("{name:?} isn't an internal name: {e}"))?;
    let row = ledger(ctx)
        .internal_name(&ctx.tenant, &zone, label)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no box holds the name {label}.{zone}"))?;
    let to = row.holder.clone().ok_or_else(|| format!("{label}.{zone} is held by no running box now"))?;
    let port = match port {
        None => row.port,
        Some(p) if p == u64::from(row.port) => row.port,
        Some(p) => return Err(format!("{label}.{zone} names port {}, not {p}", row.port)),
    };
    let (me, _) = end_info(ctx, &*ops, &ctx.run.0, None)?;
    let (t, exposed) = end_info(ctx, &*ops, &to, Some(port))?;
    let d = policy::connect(&me.end(), &t.end(), exposed.is_some())?;
    open(ctx, ops, &me, &t, port, d, LinkName::Exact(&format!("{label}.{zone}"))).await
}

/// What became of a box's use of a service (#579 step 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UseOutcome {
    /// Linked (or already): what the box reaches, as `connect` says it.
    Linked(String),
    /// Not yet: no instance runs on the box's node, or it hasn't registered or exposed its port.
    /// Worth trying again shortly.
    Waiting(String),
    /// The link needs a human: request `request` is filed (or pending). Try again once it's
    /// granted.
    Approval { request: String, text: String },
    /// Never, as things are: said why.
    Refused(String),
}

/// What `use_service` needs to know of the service, from its installed snapshot.
#[derive(Clone, Debug)]
pub struct ServiceRef<'a> {
    pub name: &'a str,
    pub port: u16,
    pub shared: bool,
    /// The snapshot's zone and program: the instance's identity must say these.
    pub zone: &'a str,
    pub program: &'a str,
}

/// The run of `svc`'s live instance on `node` for `tenant` (or the shared one, only for a shared
/// service), as wicket recorded starting it, and checked to be that service's: its identity's zone
/// and agent are the snapshot's. Ok(None): none yet.
pub fn instance_for(l: &wicket_store::Ledger, svc: &ServiceRef<'_>, node: &str, tenant: &str) -> Result<Option<String>, String> {
    let tenant = if svc.shared { wicket_store::SHARED_TENANT } else { tenant };
    let live = l.service_instances(svc.name, node, tenant).map_err(|e| e.to_string())?.into_iter().find(|i| i.live);
    let Some(i) = live else { return Ok(None) };
    match l.identity(&i.run).map_err(|e| e.to_string())? {
        // Started, not registered yet: wait for it.
        None => Ok(None),
        Some(id) if id.zone == svc.zone && id.agent == svc.program => Ok(Some(i.run)),
        Some(id) => Err(format!(
            "the run recorded as {}'s instance ({}) is zone {} / {}, not the service's {} / {}",
            svc.name, i.run, id.zone, id.agent, svc.zone, svc.program
        )),
    }
}

/// A box's `uses: [service]` (#579 step 3): it reaches the service's instance on its own node at
/// `<service>.wicket.internal:<port>`. Not a tool: wicket opens it for the box once it has started.
/// The target is the instance wicket started for that service on this box's node, for its tenant
/// (or the shared one, for a shared service), found in the ledger and checked against the service's
/// snapshot, never by a name a box exposed. Using a service is having its reach: the link needs a
/// human unless this zone's reach covers the service's.
pub async fn use_service(ctx: &RunCtx, svc: &ServiceRef<'_>) -> UseOutcome {
    if !ctx.zone.uses.iter().any(|u| u == svc.name) {
        return UseOutcome::Refused(format!("zone {} doesn't use {}", ctx.zone.name, svc.name));
    }
    let Some(ops) = ctx.boxes.clone() else { return UseOutcome::Refused("links need a box wicket runs on a node".into()) };
    let (node, to) = {
        let l = ledger(ctx);
        let node = match l.run_node(&ctx.run.0) {
            Ok(n) => n.unwrap_or_else(|| "local".into()),
            Err(e) => return UseOutcome::Waiting(e.to_string()),
        };
        match instance_for(&l, svc, &node, &ctx.tenant.0) {
            Ok(Some(run)) => (node, run),
            Ok(None) => return UseOutcome::Waiting(format!("no instance of {} runs on node {node} yet", svc.name)),
            Err(e) => return UseOutcome::Refused(e),
        }
    };
    let me = match end_info(ctx, &*ops, &ctx.run.0, None) {
        Ok((me, _)) => me,
        Err(e) => return UseOutcome::Waiting(e),
    };
    let (t, exposed) = match end_info(ctx, &*ops, &to, Some(svc.port)) {
        Ok(x) => x,
        // Registered but not running yet, or in between: not a reason to give up.
        Err(e) => return UseOutcome::Waiting(e),
    };
    if exposed.is_none() {
        return UseOutcome::Waiting(format!("{}'s instance {to} on node {node} hasn't exposed port {} yet", svc.name, svc.port));
    }
    let d = match policy::connect_service(&me.end(), &t.end()) {
        Ok(d) => d,
        Err(e) => return UseOutcome::Refused(e),
    };
    let needs_human = !d.allowed();
    match open(ctx, ops, &me, &t, svc.port, d, LinkName::Label(svc.name)).await {
        Err(e) => UseOutcome::Refused(e),
        Ok(text) => match text.split_whitespace().skip_while(|w| *w != "request").nth(1) {
            Some(r) if needs_human && !text.starts_with("linked") && !text.starts_with("already linked") => {
                UseOutcome::Approval { request: r.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-').to_string(), text }
            }
            // The name a link gets is unique per box: one other than the service's would leave its
            // users' environment pointing at nothing.
            _ if !text.contains(&format!("{}.{}", svc.name, policy::DOMAIN)) => {
                // Closed again: its users' environment names the service, not this.
                let id = text.split_whitespace().nth(1).unwrap_or("").trim_end_matches(':').trim_matches(|c| c == '(' || c == ')');
                let (closed, _) = unlink(ctx, id);
                UseOutcome::Refused(format!("linked under another name than {} ({text}); closed: {closed}", svc.name))
            }
            _ => UseOutcome::Linked(text),
        },
    }
}

/// `link(from, to, port)`: the caller, controlling both ends, lets `from` reach `port` of `to`.
pub async fn link(ctx: &RunCtx, from: &str, to: &str, port: Option<u64>) -> Reply {
    let r = async {
        let ops = ctx.boxes.clone().ok_or("links need a box wicket runs on a node (this one can't link)")?;
        let port = check_port(port)?;
        let (from, to) = (resolve(ctx, from)?, resolve(ctx, to)?);
        let (f, _) = end_info(ctx, &*ops, &from, None)?;
        let (t, exposed) = end_info(ctx, &*ops, &to, Some(port))?;
        let d = policy::link(&ctx.run.0, &f.end(), &t.end())?;
        let wanted = exposed.and_then(|e| e.name).unwrap_or_else(|| t.agent.clone());
        open(ctx, ops, &f, &t, port, d, LinkName::Label(&wanted)).await
    }
    .await;
    match r {
        Ok(s) => (s, false),
        Err(e) => (format!("not linked: {e}"), true),
    }
}

/// `unlink(link)`: closes a link this box opened or is an end of.
pub fn unlink(ctx: &RunCtx, id: &str) -> Reply {
    let l = ledger(ctx);
    match l.link(id) {
        Ok(Some(r)) if r.tenant == ctx.tenant.0 && [&r.by_run, &r.from_run, &r.to_run].contains(&&ctx.run.0) => {
            match l.close_link(id, &ctx.run.0, "unlinked by an agent at one end") {
                Ok(true) => (format!("closed {id}; its relay stops within {}s", POLL.as_secs()), false),
                Ok(false) => (format!("{id} was already closed"), false),
                Err(e) => (e.to_string(), true),
            }
        }
        Ok(_) => (format!("no link {id} of yours"), true),
        Err(e) => (e.to_string(), true),
    }
}

/// `links()`: the links this box opened or is an end of.
pub fn list(ctx: &RunCtx) -> Reply {
    let l = ledger(ctx);
    let rows: Vec<serde_json::Value> = l
        .links(&ctx.tenant, 500)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| [&r.by_run, &r.from_run, &r.to_run].contains(&&ctx.run.0))
        .map(|r| {
            serde_json::json!({
                "id": r.id, "status": r.status, "from": r.from_run, "to": r.to_run,
                "address": format!("{}.{}:{}", r.name, policy::DOMAIN, r.port), "basis": r.basis, "close_reason": r.close_reason,
            })
        })
        .collect();
    if rows.is_empty() {
        return ("no links".into(), false);
    }
    (serde_json::to_string_pretty(&rows).unwrap_or_default(), false)
}

/// Rewrites a box's hosts file from its open links.
async fn write_hosts(ctx: &RunCtx, ops: &dyn BoxOps, from_run: &str) {
    let names: Vec<(String, Ipv4Addr)> = ledger(ctx)
        .links_from(from_run)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.status == "open")
        .filter_map(|r| Some((r.name, r.addr.parse().ok()?)))
        .collect();
    if let Err(e) = ops.set_hosts(from_run, policy::hosts_file(&names)).await {
        tracing::warn!("rewriting {from_run}'s hosts file failed: {e}");
    }
}

/// What a link is named after.
#[derive(Clone, Copy)]
enum LinkName<'a> {
    /// A wanted name, made a label (and suffixed if another target has it): `connect(box)`, `link`, services.
    Label(&'a str),
    /// An internal name, exactly (#575): `connect(name)`.
    Exact(&'a str),
}

async fn open(
    ctx: &RunCtx,
    ops: Arc<dyn BoxOps>,
    from: &EndInfo,
    to: &EndInfo,
    port: u16,
    d: Decision,
    name: LinkName<'_>,
) -> Result<String, String> {
    let (wanted, by_name) = match name {
        LinkName::Label(w) => (w, false),
        LinkName::Exact(w) => (w, true),
    };
    ops.reachable(&from.run).await?;
    ops.reachable(&to.run).await?;
    let existing = ledger(ctx).open_link(&from.run, &to.run, port).map_err(|e| e.to_string())?;
    if let Some(r) = existing {
        if by_name && r.name != wanted {
            return Err(format!(
                "this box already links to that port as {}.{} ({}): unlink it to link it by name",
                r.name,
                policy::DOMAIN,
                r.id
            ));
        }
        return Ok(format!("already linked ({}): {}.{}:{port}", r.id, r.name, policy::DOMAIN));
    }
    // Beyond the default policy: a human approves exactly this link.
    let mut basis = d.basis.map(|b| b.as_str().to_string());
    let mut grant = None;
    if !d.allowed() {
        let op =
            Op::egress(&ctx.tenant, &ctx.run, &ctx.zone.name, "LINK", policy::DOMAIN, &format!("/links/{}/{}/{port}", from.run, to.run));
        // The approval is for this link under this name (#369): the name it was asked under is the
        // argument a grant binds, so it can't be used to open the link under another.
        let args = wicket_core::effect::args_sha256(&serde_json::json!({ "name": wanted }));
        let mut l = ledger(ctx);
        match l.use_effect_grant(&op, Some(&args)).map_err(|e| e.to_string())? {
            EffectUse::Granted(g) => {
                basis = Some(format!("approved ({g})"));
                grant = Some(g);
            }
            EffectUse::Held { pending } => {
                return Ok(format!("waiting: request {pending} for this link is not decided yet. Call await_grant with {pending}; once granted, make the same call again."));
            }
            EffectUse::ArgsChanged { grant } => {
                return Err(format!(
                    "refused: this link was approved ({grant}) under another name, and the name changed after the approval (this is recorded). Make the call with the name that was approved."
                ));
            }
            EffectUse::None => {
                if let Ok(Some(rid)) = l.denied_recently_with(&op, Some(&args)) {
                    return Err(format!("exactly this link ({rid}) was denied a few minutes ago; don't ask again"));
                }
                let reason = format!(
                    "link box {} ({}) to port {port} of box {} ({}), named {}.{}: {}",
                    from.agent,
                    from.zone_name,
                    to.agent,
                    to.zone_name,
                    wanted,
                    policy::DOMAIN,
                    d.needs_human.join("; ")
                );
                let rid = match l.file_request(&op, Some(&args), &reason, None).map_err(|e| e.to_string())? {
                    Filed::Held { pending } => {
                        return Ok(format!(
                        "waiting: request {pending} for this link under another name is not decided yet. Call await_grant with {pending}."
                    ))
                    }
                    f => f.id().to_string(),
                };
                return Ok(format!(
                    "needs approval: request {rid} ({}). Call await_grant with {rid}; once granted, make the same call again.",
                    d.needs_human.join("; ")
                ));
            }
        }
    }
    let basis = basis.unwrap_or_else(|| "approved".into());

    let links = ledger(ctx).links_from(&from.run).map_err(|e| e.to_string())?;
    // A by-name link (#575) is named exactly after the name, never suffixed, and only open links
    // count against it: a closed one doesn't keep a name (#575 review, M1).
    let (name, addr) = if by_name {
        let named = |r: &LinkRow| Some(Named { name: r.name.clone(), addr: r.addr.parse().ok()?, to_run: r.to_run.clone() });
        let open: Vec<Named> = links.iter().filter(|r| r.status == "open").filter_map(named).collect();
        let used: Vec<Named> = links.iter().filter_map(named).collect();
        policy::allocate_exact(&open, &used, &to.run, wanted)?
    } else {
        let used: Vec<Named> =
            links.into_iter().filter_map(|r| Some(Named { name: r.name, addr: r.addr.parse().ok()?, to_run: r.to_run })).collect();
        policy::allocate(&used, &to.run, wanted)?
    };
    let id = wicket_core::new_link_id();
    let sock = format!("link-{id}.sock");
    let box_sock = format!("/wicket/sock/{sock}");
    // On one node, the node carries it (#164); else this host relays each connection.
    let incoming = match ops.accept_direct(&from.run, &sock, &to.run, port).await {
        Ok(true) => None,
        _ => Some(ops.accept(&from.run, &sock).await.map_err(|e| format!("relay socket: {e}"))?),
    };
    let row = LinkRow {
        id: id.clone(),
        tenant: ctx.tenant.0.clone(),
        from_run: from.run.clone(),
        to_run: to.run.clone(),
        port,
        name: name.clone(),
        addr: addr.to_string(),
        by_run: ctx.run.0.clone(),
        basis: basis.clone(),
        status: "open".into(),
        created_at: wicket_store::now(),
        closed_at: None,
        closed_by: None,
        close_reason: None,
    };
    let added = ledger(ctx).add_link(&row);
    if let Err(e) = added {
        ops.close_accept(&from.run, &sock).await;
        return Err(e.to_string());
    }
    write_hosts(ctx, &*ops, &from.run).await;
    if let Err(e) = ops.listen(&from.run, addr, port, &box_sock).await {
        ops.close_accept(&from.run, &sock).await;
        let _ = ledger(ctx).close_link(&id, "wicket", &format!("could not listen in the box: {e}"));
        write_hosts(ctx, &*ops, &from.run).await;
        return Err(format!("could not listen in box {}: {e}", from.run));
    }
    let address = format!("{name}.{}:{port}", policy::DOMAIN);
    let audited = ledger(ctx).audit(
        &ctx.tenant,
        Some(&ctx.run),
        "link.open",
        &serde_json::json!({
            "id": id, "from": from.run, "from_zone": from.zone_name, "to": to.run, "to_zone": to.zone_name, "port": port,
            "address": address, "addr": addr.to_string(), "basis": basis, "grant": grant, "labels": LABELS,
        }),
    );
    // A link carries traffic only once it is on the record (fail closed).
    if let Err(e) = audited {
        ops.close_accept(&from.run, &sock).await;
        ops.unlisten(&from.run, &box_sock).await;
        let _ = ledger(ctx).close_link(&id, "wicket", &format!("the audit record could not be written: {e}"));
        write_hosts(ctx, &*ops, &from.run).await;
        return Err(format!("link not opened: the audit record could not be written ({e})"));
    }
    ctx.emit(Event::Tool { name: "link".into(), detail: format!("opened {id}: {} → {address} ({}, port {port})", from.agent, to.agent) });
    let carried = match incoming {
        Some(incoming) => {
            tokio::spawn(relay(ctx.clone(), ops, row, incoming));
            "Relayed by wicket"
        }
        None => {
            tokio::spawn(watch_direct(ctx.clone(), ops, row));
            "Carried by your node, so it holds while wicket's control host is unreachable"
        }
    };
    let who = if from.run == ctx.run.0 { "this box".to_string() } else { format!("box {} ({})", from.agent, from.run) };
    Ok(format!(
        "linked {id}: {who} reaches port {port} of box {} ({}) at {address} ({basis}). {carried}; it closes when either box ends or is revoked, or on unlink {id}.",
        to.agent, to.run
    ))
}

/// Why the link must close now, if it must.
fn must_close(ctx: &RunCtx, row: &LinkRow) -> Option<String> {
    let l = ctx.ledger.lock().ok()?;
    match l.link(&row.id) {
        Ok(Some(r)) if r.status == "open" => {}
        Ok(Some(r)) => return Some(r.close_reason.unwrap_or_else(|| "closed".into())),
        _ => return Some("no longer in the ledger".into()),
    }
    for run in [&row.from_run, &row.to_run, &row.by_run] {
        if l.run_status(run).ok().flatten().as_deref() != Some("running") {
            return Some(format!("run {run} ended"));
        }
        if let Ok(Some((r, _, by, reason))) = l.revoked_in_chain(run) {
            return Some(format!("identity of {r} revoked by {by} ({reason})"));
        }
    }
    None
}

/// A link its node carries (#164): this host keeps its record and closes it (unlink, revocation, a
/// run ending), telling the node once it can be reached; the node itself closes it when either
/// box's authority ends there.
async fn watch_direct(ctx: RunCtx, ops: Arc<dyn BoxOps>, row: LinkRow) {
    let mut tick = tokio::time::interval(POLL);
    let reason = loop {
        tick.tick().await;
        if let Some(r) = must_close(&ctx, &row) {
            break r;
        }
    };
    let closed_now = ctx.ledger.lock().ok().and_then(|l| l.close_link(&row.id, "wicket", &reason).ok()).unwrap_or(false);
    // The node may be out of reach: told when it is back, unless the box is gone by then.
    for _ in 0..900 {
        if ops.reachable(&row.from_run).await.is_ok() {
            break;
        }
        if ctx.ledger.lock().ok().and_then(|l| l.run_status(&row.from_run).ok().flatten()).as_deref() != Some("running") {
            break;
        }
        tick.tick().await;
    }
    ops.close_accept(&row.from_run, &format!("link-{}.sock", row.id)).await;
    write_hosts(&ctx, &*ops, &row.from_run).await;
    ops.unlisten(&row.from_run, &format!("/wicket/sock/link-{}.sock", row.id)).await;
    if let Ok(l) = ctx.ledger.lock() {
        let _ = l.audit(
            &ctx.tenant,
            Some(&ctx.run),
            "link.close",
            &serde_json::json!({ "id": row.id, "reason": reason, "carried_by_node": true, "closed_by_relay": closed_now }),
        );
    }
    ctx.emit(Event::Tool { name: "link".into(), detail: format!("closed {}: {reason}", row.id) });
}

async fn relay(ctx: RunCtx, ops: Arc<dyn BoxOps>, row: LinkRow, mut incoming: tokio::sync::mpsc::UnboundedReceiver<Stream>) {
    let mut conns = tokio::task::JoinSet::new();
    let mut tick = tokio::time::interval(POLL);
    let mut served = 0u64;
    let reason = loop {
        tokio::select! {
            a = incoming.recv() => match a {
                Some(s) => {
                    if let Some(r) = must_close(&ctx, &row) {
                        break r;
                    }
                    match ops.dial(&row.to_run, row.port).await {
                        Ok(st) => {
                            served += 1;
                            conns.spawn(pipe(s, st));
                        }
                        Err(e) => tracing::warn!("link {}: dialing {} failed: {e}", row.id, row.to_run),
                    }
                }
                None => break "the relay socket's node channel was lost".to_string(),
            },
            _ = tick.tick() => if let Some(r) = must_close(&ctx, &row) {
                break r;
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    };
    conns.abort_all();
    drop(incoming);
    ops.close_accept(&row.from_run, &format!("link-{}.sock", row.id)).await;
    let closed_now = ctx.ledger.lock().ok().and_then(|l| l.close_link(&row.id, "wicket", &reason).ok()).unwrap_or(false);
    write_hosts(&ctx, &*ops, &row.from_run).await;
    ops.unlisten(&row.from_run, &format!("/wicket/sock/link-{}.sock", row.id)).await;
    if let Ok(l) = ctx.ledger.lock() {
        let _ = l.audit(
            &ctx.tenant,
            Some(&ctx.run),
            "link.close",
            &serde_json::json!({ "id": row.id, "reason": reason, "connections": served, "closed_by_relay": closed_now }),
        );
    }
    ctx.emit(Event::Tool { name: "link".into(), detail: format!("closed {}: {reason}", row.id) });
}

/// Copies bytes both ways until both sides are done.
async fn pipe(s: Stream, st: Stream) {
    let Stream { read: mut r, write: mut w, guard: g1 } = s;
    let Stream { mut read, mut write, guard } = st;
    let up = async {
        let _ = tokio::io::copy(&mut r, &mut write).await;
        let _ = write.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut read, &mut w).await;
        let _ = w.shutdown().await;
    };
    tokio::join!(up, down);
    drop(guard);
    drop(g1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// #579's review: a box is linked only to the instance wicket started for the service, on the
    /// box's node, for its tenant (the shared one only for a shared service), and only once the
    /// instance's identity says it is the service (its snapshot's zone and program).
    #[test]
    fn a_service_instance_is_found_by_the_ledger_and_checked_to_be_the_service() {
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        let svc = ServiceRef { name: "npm-cache", port: 4873, shared: false, zone: "npm-cache", program: "npm-cache" };
        let t = wicket_core::TenantId::single();
        let id = |run: &str, zone: &str, agent: &str| wicket_store::IdentityRow {
            run: run.into(),
            tenant: "t0".into(),
            spiffe_id: format!("spiffe://x/{run}"),
            zone: zone.into(),
            agent: agent.into(),
            parent_run: None,
            accept_from: vec![],
            jws: "x".into(),
            issued_at: 1,
        };
        assert_eq!(instance_for(&l, &svc, "n1", "t0"), Ok(None), "no instance");
        l.record_service_instance("run_svc", "npm-cache", "n1", "t0", "aa", wicket_store::now()).unwrap();
        assert_eq!(instance_for(&l, &svc, "n1", "t0"), Ok(None), "recorded, not registered yet: wait");
        l.run_started(&t, &wicket_core::RunId("run_svc".into()), "npm-cache", "npm-cache").unwrap();
        l.put_identity(&id("run_svc", "npm-cache", "npm-cache")).unwrap();
        assert_eq!(instance_for(&l, &svc, "n1", "t0"), Ok(Some("run_svc".into())));
        assert_eq!(instance_for(&l, &svc, "n2", "t0"), Ok(None), "another node's box");
        assert_eq!(instance_for(&l, &svc, "n1", "t1"), Ok(None), "another tenant's box");
        // A shared instance serves only a shared service.
        l.record_service_instance("run_shared", "npm-cache", "n2", wicket_store::SHARED_TENANT, "aa", wicket_store::now()).unwrap();
        l.run_started(&t, &wicket_core::RunId("run_shared".into()), "npm-cache", "npm-cache").unwrap();
        l.put_identity(&id("run_shared", "npm-cache", "npm-cache")).unwrap();
        assert_eq!(instance_for(&l, &svc, "n2", "t0"), Ok(None), "per tenant: the shared one isn't it");
        let shared = ServiceRef { shared: true, ..svc.clone() };
        assert_eq!(instance_for(&l, &shared, "n2", "t0"), Ok(Some("run_shared".into())));
        // A recorded instance whose identity is another zone's isn't the service.
        l.record_service_instance("run_odd", "npm-cache", "n3", "t0", "aa", wicket_store::now()).unwrap();
        l.run_started(&t, &wicket_core::RunId("run_odd".into()), "build", "build").unwrap();
        l.put_identity(&id("run_odd", "build", "build")).unwrap();
        assert!(instance_for(&l, &svc, "n3", "t0").unwrap_err().contains("not the service's"));
    }
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use wicket_core::{Manifest, RunId, TenantId};
    use wicket_identity::{AgentKey, Issuer};
    use wicket_proxy::link::Fut;
    use wicket_proxy::{IdentityCell, RunIdentity};
    use wicket_store::{IdentityRow, Ledger};

    /// Boxes as directories, and each box's "port" an in-process echo server that prefixes replies
    /// with the box's run id.
    struct FakeBoxes {
        root: PathBuf,
        zones: HashMap<String, ZoneSpec>,
        listening: Mutex<Vec<(String, Ipv4Addr, u16, String)>>,
        accepting: Mutex<HashMap<PathBuf, tokio::task::JoinHandle<()>>>,
    }

    impl BoxOps for FakeBoxes {
        fn reachable<'a>(&'a self, run: &'a str) -> Fut<'a, Result<(), String>> {
            let r = match self.root.join(run).join("hosts").exists() {
                true => Ok(()),
                false => Err(format!("box {run} is not on a node wicket reaches")),
            };
            Box::pin(async move { r })
        }
        fn child_zone(&self, run: &str) -> Option<ZoneSpec> {
            self.zones.get(run).cloned()
        }
        fn set_hosts<'a>(&'a self, run: &'a str, text: String) -> Fut<'a, Result<(), String>> {
            Box::pin(async move { std::fs::write(self.root.join(run).join("hosts"), text).map_err(|e| e.to_string()) })
        }
        fn accept<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, Result<tokio::sync::mpsc::UnboundedReceiver<Stream>, String>> {
            Box::pin(async move {
                let path = self.root.join(run).join("sock").join(sock);
                let l = wicket_proxy::sockpath::bind(&path).map_err(|e| e.to_string())?;
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                let t = tokio::spawn(async move {
                    while let Ok((s, _)) = l.accept().await {
                        let (r, w) = s.into_split();
                        if tx.send(Stream { read: Box::new(r), write: Box::new(w), guard: Box::new(()) }).is_err() {
                            break;
                        }
                    }
                });
                self.accepting.lock().unwrap().insert(path, t);
                Ok(rx)
            })
        }
        fn close_accept<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, ()> {
            Box::pin(async move {
                let path = self.root.join(run).join("sock").join(sock);
                if let Some(t) = self.accepting.lock().unwrap().remove(&path) {
                    t.abort();
                }
                let _ = std::fs::remove_file(path);
            })
        }
        fn listen<'a>(&'a self, run: &'a str, addr: Ipv4Addr, port: u16, sock: &'a str) -> Fut<'a, Result<(), String>> {
            self.listening.lock().unwrap().push((run.into(), addr, port, sock.into()));
            Box::pin(async { Ok(()) })
        }
        fn unlisten<'a>(&'a self, _run: &'a str, sock: &'a str) -> Fut<'a, ()> {
            self.listening.lock().unwrap().retain(|l| l.3 != sock);
            Box::pin(async {})
        }
        fn dial<'a>(&'a self, run: &'a str, _port: u16) -> Fut<'a, Result<Stream, String>> {
            Box::pin(async move { self.dial_now(run) })
        }
    }

    impl FakeBoxes {
        fn dial_now(&self, run: &str) -> Result<Stream, String> {
            let (a, b) = tokio::io::duplex(4096);
            let tag = run.to_string();
            let echo = tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(b);
                let mut buf = [0u8; 1024];
                while let Ok(n) = r.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = w.write_all(format!("{tag}:").as_bytes()).await;
                    let _ = w.write_all(&buf[..n]).await;
                }
            });
            struct Abort(tokio::task::JoinHandle<()>);
            impl Drop for Abort {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            let (r, w) = tokio::io::split(a);
            Ok(Stream { read: Box::new(r), write: Box::new(w), guard: Box::new(Abort(echo)) })
        }
    }

    struct World {
        issuer: Issuer,
        ledger: Arc<Mutex<Ledger>>,
        root: PathBuf,
    }

    impl Drop for World {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl World {
        fn new() -> World {
            let root = std::env::temp_dir().join(format!("wicket-link-test-{}", wicket_core::new_ulid()));
            World { issuer: Issuer::generate("test.local"), ledger: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())), root }
        }

        fn zone(&self, name: &str, accept_from: &[&str]) -> ZoneSpec {
            let y = format!("task: t\nprogram: {{ name: p, command: [x] }}\nzone: {{ name: {name}, accept_from: {accept_from:?} }}\n");
            Manifest::from_yaml(&y).unwrap().zone
        }

        fn boxed(&self, zone: ZoneSpec, name: &str, run: &str, parent: Option<&str>, kids: &[(&str, ZoneSpec)]) -> RunCtx {
            let dir = self.root.join(run);
            std::fs::create_dir_all(dir.join("sock")).unwrap();
            std::fs::write(dir.join("hosts"), policy::hosts_file(&[])).unwrap();
            let key = AgentKey::generate();
            let spec = wicket_identity::IdentitySpec {
                tenant: "t0".into(),
                zone: zone.name.clone(),
                agent: name.into(),
                run: run.into(),
                parent_run: parent.map(String::from),
                manifest_sha256: "m".into(),
                image: "img".into(),
                node: "local".into(),
                principal: serde_json::json!({"type": "human", "id": "alice", "via": "cli", "assurance": "unix-user"}),
                act: None,
                kind: None,
            };
            let jws = self.issuer.issue(&spec, wicket_store::now(), 3600, &key.public());
            let claims = wicket_identity::verify_identity(&jws, &self.issuer.verifying_key(), wicket_store::now()).unwrap();
            {
                let l = self.ledger.lock().unwrap();
                l.run_started(&TenantId::single(), &RunId(run.into()), &zone.name, name).unwrap();
                l.put_identity(&IdentityRow {
                    run: run.into(),
                    tenant: "t0".into(),
                    spiffe_id: claims.sub.clone(),
                    zone: zone.name.clone(),
                    agent: name.into(),
                    parent_run: parent.map(String::from),
                    accept_from: zone.accept_from.clone(),
                    jws: jws.clone(),
                    issued_at: claims.iat,
                })
                .unwrap();
            }
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let boxes = FakeBoxes {
                root: self.root.clone(),
                zones: kids.iter().map(|(r, z)| (r.to_string(), z.clone())).collect(),
                listening: Mutex::new(vec![]),
                accepting: Mutex::new(HashMap::new()),
            };
            RunCtx {
                tenant: TenantId::single(),
                run: RunId(run.into()),
                zone: Arc::new(wicket_core::CompiledZone::new(zone).unwrap()),
                org: None,
                ledger: self.ledger.clone(),
                vault: wicket_proxy::vault::Vault::new(std::env::temp_dir()),
                events: tx,
                escalate: true,
                attribute: None,
                identity: Some(Arc::new(IdentityCell::new(RunIdentity { jws, claims, key, issuer: self.issuer.verifying_key() }))),
                swaps: vec![],
                boxes: Some(Arc::new(boxes)),
                capacity: None,
                decisions: None,
                fence: None,
                waker: None,
                lifecycle: None,
                names: Some(Arc::new(names_settings())),
            }
        }
    }

    /// The installation's names settings these tests run under: public names in a boxes domain,
    /// with the operator's reserved label `status`.
    pub(crate) fn names_settings() -> wicket_names::NamesConfig {
        serde_json::from_value(serde_json::json!({
            "public": { "provider": "noop", "zone": "boxes.example.com", "owner": "a1b2c3d4", "reserved": ["status"], "console_host": "ops.example.com" }
        }))
        .unwrap()
    }

    fn link_id(text: &str) -> String {
        text.split_whitespace().nth(1).unwrap().trim_end_matches(':').to_string()
    }

    async fn roundtrip(sock: &Path) -> std::io::Result<String> {
        let mut s = UnixStream::connect(sock).await?;
        s.write_all(b"ping").await?;
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
        Ok(String::from_utf8_lossy(&buf[..n]).into())
    }

    async fn wait_closed(w: &World, id: &str) -> LinkRow {
        for _ in 0..40 {
            let r = w.ledger.lock().unwrap().link(id).unwrap().unwrap();
            let sock = w.root.join(&r.from_run).join("sock").join(format!("link-{id}.sock"));
            if r.status == "closed" && !sock.exists() {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("link {id} did not close");
    }

    /// #575: a box names its port; a box its accept_from lists reaches it by that name, which
    /// resolves in the connecting box (its hosts line); any other box needs a human; the name ends
    /// with the run that holds it.
    #[tokio::test]
    async fn an_internal_name_is_reached_by_connect_and_ends_with_its_run() {
        let w = World::new();
        let api = w.boxed(w.zone("build", &["web"]), "api", "run_api", None, &[]);
        let web = w.boxed(w.zone("web", &[]), "web", "run_web", None, &[]);
        let other = w.boxed(w.zone("other", &[]), "other", "run_other", None, &[]);

        let (text, err) = crate::names::request_name(&api, &serde_json::json!({ "name": "api", "port": 3000, "reason": "the API" }));
        assert!(!err && text.contains("api.build.wicket.internal"), "{text}");
        // Taken in the zone (by another agent of it); refused shapes and kinds.
        let api2 = w.boxed(w.zone("build", &[]), "api2", "run_api2", None, &[]);
        let (text, err) = crate::names::request_name(&api2, &serde_json::json!({ "name": "api", "port": 3001 }));
        assert!(err && text.contains("taken"), "{text}");
        let (text, err) = crate::names::request_name(&web, &serde_json::json!({ "name": "Bad.Name", "port": 1 }));
        assert!(err && text.contains("a-z"), "{text}");
        let (text, err) = crate::names::request_name(&web, &serde_json::json!({ "name": "x", "port": 1, "kind": "global" }));
        assert!(err && text.contains("internal or public"), "{text}");

        // web is in api's accept_from: linked by the name, at the name's port, and it resolves there.
        let (text, err) = connect_name(&web, "api.build.wicket.internal", None).await;
        assert!(!err && text.contains("api.build.wicket.internal:3000") && text.contains("accept_from"), "{text}");
        let hosts = std::fs::read_to_string(w.root.join("run_web/hosts")).unwrap();
        assert!(hosts.contains("\tapi.build.wicket.internal\n"), "{hosts}");
        let id = link_id(&text);
        assert_eq!(roundtrip(&w.root.join("run_web/sock").join(format!("link-{id}.sock"))).await.unwrap(), "run_api:ping");
        let (text, err) = connect_name(&web, "api.build", Some(4000)).await;
        assert!(err && text.contains("names port 3000"), "{text}");

        // other isn't: a human decides exactly that link.
        let (text, err) = connect_name(&other, "api.build", None).await;
        assert!(!err && text.contains("needs approval"), "{text}");
        let audit = w.ledger.lock().unwrap().audit_tail(30).unwrap();
        assert!(audit.iter().any(|a| a.2 == "name.registered" && a.4.contains("api.build.wicket.internal")));

        // The run ends: so does the name, and the label is free.
        w.ledger.lock().unwrap().run_ended(&RunId("run_api".into()), "succeeded", "").unwrap();
        let (text, err) = connect_name(&other, "api.build", None).await;
        assert!(err && text.contains("no box holds"), "{text}");
        assert!(w.ledger.lock().unwrap().internal_name(&TenantId::single(), "build", "api").unwrap().is_none());
    }

    /// #575 review and #668: only a zone already in DNS form holds names (a dotted one like a
    /// spawned zone's included), and is looked up in any case; a zone that would share its DNS form
    /// with another (`Build`, `web_api`) is refused; a name asked again moves to the new port; and
    /// after the holder's run ends and another takes the name, a box reconnects under exactly the
    /// same name (never a suffixed one), to the new holder.
    #[tokio::test]
    async fn a_name_keeps_its_exact_form_across_zones_ports_and_holders() {
        let w = World::new();
        let zone = "lead.fetch-er.01x";
        let a = w.boxed(w.zone(zone, &["web"]), "api", "run_a", None, &[]);
        let web = w.boxed(w.zone("web", &[]), "web", "run_web", None, &[]);
        for odd in ["Build", "web_api"] {
            let b = w.boxed(w.zone(odd, &[]), "odd", &format!("run_{}", odd.to_ascii_lowercase()), None, &[]);
            let (text, err) = crate::names::request_name(&b, &serde_json::json!({ "name": "api", "port": 3000 }));
            assert!(err && text.contains("can't be part of a DNS name"), "{odd}: {text}");
        }

        let (text, err) = crate::names::request_name(&a, &serde_json::json!({ "name": "api", "port": 3000 }));
        assert!(!err && text.contains("api.lead.fetch-er.01x.wicket.internal"), "{text}");
        // Asked again with another port: the name moves, the old port is no longer offered.
        let (text, err) = crate::names::request_name(&a, &serde_json::json!({ "name": "api", "port": 3001 }));
        assert!(!err && text.contains("port 3001"), "{text}");
        assert!(w.ledger.lock().unwrap().exposed("run_a", 3000).unwrap().is_none());
        assert!(w.ledger.lock().unwrap().exposed("run_a", 3001).unwrap().is_some());

        // Looked up in any case or spelling of the zone that has the same DNS form.
        let (text, err) = connect_name(&web, "api.Lead.Fetch-ER.01X", None).await;
        assert!(!err && text.contains("api.lead.fetch-er.01x.wicket.internal:3001"), "{text}");
        let first = link_id(&text);

        // A's run ends; B, another run of the same agent in the same zone, takes the name.
        w.ledger.lock().unwrap().run_ended(&RunId("run_a".into()), "succeeded", "").unwrap();
        wait_closed(&w, &first).await;
        let b = w.boxed(w.zone(zone, &["web"]), "api", "run_b", None, &[]);
        assert!(!crate::names::request_name(&b, &serde_json::json!({ "name": "api", "port": 3001 })).1);
        let (text, err) = connect_name(&web, "api.lead.fetch-er.01x", None).await;
        assert!(!err, "{text}");
        assert!(text.contains("api.lead.fetch-er.01x.wicket.internal:3001") && !text.contains("-2."), "{text}");
        let hosts = std::fs::read_to_string(w.root.join("run_web/hosts")).unwrap();
        assert_eq!(hosts.matches("api.lead.fetch-er.01x.wicket.internal").count(), 1, "{hosts}");
        assert_eq!(roundtrip(&w.root.join("run_web/sock").join(format!("link-{}.sock", link_id(&text)))).await.unwrap(), "run_b:ping");
    }

    /// #668 review: two names of one box from one connector share its address and each keeps its
    /// own hosts line; unlinking one leaves the other working; connect(box:) to the same box takes
    /// its own label, never a by-name link's; a port the box exposed itself keeps that exposure; a
    /// zone named like wicket's domain holds no names; and a request_name whose audit record can't
    /// be written leaves things as they were.
    #[tokio::test]
    async fn two_names_of_one_box_and_the_edges_around_them() {
        let w = World::new();
        let api = w.boxed(w.zone("build", &["web"]), "api", "run_api", None, &[]);
        let web = w.boxed(w.zone("web", &[]), "web", "run_web", None, &[]);
        let req = |name: &str, port: u16| crate::names::request_name(&api, &serde_json::json!({ "name": name, "port": port }));
        assert!(!req("one", 3000).1);
        assert!(!req("two", 3001).1);

        let (t1, err) = connect_name(&web, "one.build", None).await;
        assert!(!err, "{t1}");
        let (t2, err) = connect_name(&web, "two.build", None).await;
        assert!(!err, "{t2}");
        let hosts = std::fs::read_to_string(w.root.join("run_web/hosts")).unwrap();
        assert!(
            hosts.contains("198.18.1.1\tone.build.wicket.internal") && hosts.contains("198.18.1.1\ttwo.build.wicket.internal"),
            "{hosts}"
        );
        let (id1, id2) = (link_id(&t1), link_id(&t2));
        assert!(!unlink(&web, &id1).1);
        wait_closed(&w, &id1).await;
        let hosts = std::fs::read_to_string(w.root.join("run_web/hosts")).unwrap();
        assert!(!hosts.contains("one.build") && hosts.contains("two.build.wicket.internal"), "{hosts}");
        assert_eq!(roundtrip(&w.root.join("run_web/sock").join(format!("link-{id2}.sock"))).await.unwrap(), "run_api:ping");

        // connect(box:) to the same box, another port: its own label, at the box's address.
        w.ledger
            .lock()
            .unwrap()
            .expose(&TenantId::single(), "run_api", 3002, None, &serde_json::to_string(api.zone.spec()).unwrap())
            .unwrap();
        let (t3, err) = connect(&web, "run_api", Some(3002)).await;
        assert!(!err && t3.contains("api.wicket.internal:3002") && !t3.contains("build"), "{t3}");
        // ...and a later name still links by its exact name.
        assert!(!req("three", 3003).1);
        let (t4, err) = connect_name(&web, "three.build", None).await;
        assert!(!err && t4.contains("three.build.wicket.internal:3003"), "{t4}");

        // A port the box exposed itself (3002, no name) keeps that exposure when named.
        let (text, err) = crate::names::request_name(&api, &serde_json::json!({ "name": "one", "port": 3002 }));
        assert!(!err, "{text}");
        assert_eq!(w.ledger.lock().unwrap().exposed("run_api", 3002).unwrap().unwrap().name, None);

        // A zone named like wicket's domain holds no names.
        let odd = w.boxed(w.zone("build.wicket.internal", &[]), "odd", "run_odd", None, &[]);
        let (text, err) = crate::names::request_name(&odd, &serde_json::json!({ "name": "svc", "port": 1 }));
        assert!(err && text.contains("can't be part of a DNS name"), "{text}");

        // The audit record can't be written: a name asked again keeps its old port, and the box's
        // own exposure stays as it was...
        w.ledger.lock().unwrap().fail_audit_inserts_for_tests().unwrap();
        let (text, err) = req("one", 3005);
        assert!(err && text.contains("audit record"), "{text}");
        {
            let l = w.ledger.lock().unwrap();
            assert_eq!(l.internal_name(&TenantId::single(), "build", "one").unwrap().unwrap().port, 3002);
            assert!(l.exposed("run_api", 3005).unwrap().is_none());
            assert_eq!(l.exposed("run_api", 3002).unwrap().unwrap().name, None);
            // (room under the limit of 3 for a new one)
            let three = l.internal_name(&TenantId::single(), "build", "three").unwrap().unwrap();
            l.revoke_name(&three.id, "test").unwrap();
        }
        // ...and a new name is undone, its port left unexposed.
        let (text, err) = req("four", 3004);
        assert!(err && text.contains("audit record"), "{text}");
        let l = w.ledger.lock().unwrap();
        assert!(l.internal_name(&TenantId::single(), "build", "four").unwrap().is_none());
        assert!(l.exposed("run_api", 3004).unwrap().is_none());
    }

    /// #668 review, F1 and F2: two names on one port keep it offered while either is there, in
    /// whichever order they move away; and a port the box exposed itself stays exposed when a name
    /// on it moves.
    #[tokio::test]
    async fn a_port_stays_offered_while_a_name_or_the_box_offers_it() {
        let w = World::new();
        let api = w.boxed(w.zone("build", &["web"]), "api", "run_api", None, &[]);
        let web = w.boxed(w.zone("web", &[]), "web", "run_web", None, &[]);
        let req = |name: &str, port: u16| {
            let (text, err) = crate::names::request_name(&api, &serde_json::json!({ "name": name, "port": port }));
            assert!(!err, "{name}@{port}: {text}");
        };
        let offered = |port: u16| w.ledger.lock().unwrap().exposed("run_api", port).unwrap().is_some();
        for (first, second) in [("one", "two"), ("two", "one")] {
            req("one", 3000);
            req("two", 3000);
            // The first moves away: the second still names 3000, so it stays offered.
            req(first, 3005);
            assert!(offered(3000), "after moving {first}");
            let (text, err) = connect_name(&web, &format!("{second}.build"), None).await;
            assert!(!err, "{text}");
            assert!(!unlink(&web, &link_id(&text)).1);
            wait_closed(&w, &link_id(&text)).await;
            // The second moves too: nothing names 3000, which a name exposed, so it goes.
            req(second, 3006);
            assert!(!offered(3000), "after moving {second}");
            // Back for the next round.
            req("one", 3000);
            req("two", 3000);
            assert!(offered(3000));
        }
        // F2: the box exposes 4000 itself, under the same label; a name on it moves away.
        assert!(!expose(&api, 4000, Some("one")).1);
        req("one", 4000);
        req("one", 4001);
        assert!(offered(4000), "the box's own exposure stays");
        // And a port a name exposed that the box then exposes itself is the box's.
        req("two", 4002);
        assert!(!expose(&api, 4002, Some("mine")).1);
        req("two", 4003);
        assert!(offered(4002));
    }

    /// #575 step 4a: a public name is an ask a human decides, never the box: request_name files it
    /// (n-…), refuses reserved labels and their lookalikes, and await_grant follows the decision.
    #[tokio::test]
    async fn a_public_name_is_asked_for_and_awaited() {
        let w = World::new();
        let api = w.boxed(w.zone("build", &[]), "api", "run_api", None, &[]);
        let gw = crate::Gateway::new(api.clone());
        let ask = |name: &str| {
            crate::names::request_name(&api, &serde_json::json!({ "name": name, "port": 3000, "kind": "public", "reason": "the demo" }))
        };
        // wicket's reserved labels, the operator's, and the console's first label.
        for reserved in ["console", "c0nsole", "www", "status", "5tatus", "ops"] {
            let (text, err) = ask(reserved);
            assert!(err && text.contains("reserved"), "{reserved}: {text}");
        }
        let (text, err) = ask("demo");
        assert!(!err && text.contains("needs approval") && text.contains("demo.boxes.example.com"), "{text}");
        let id = text.split_whitespace().find(|w| w.starts_with("n-")).unwrap().to_string();
        assert_eq!(ask("demo").0, text, "the same ask is the same request");
        let (text, _) = gw.call_tool("await_grant", serde_json::json!({ "request_id": id, "timeout_seconds": 5 })).await;
        assert!(text.starts_with("pending"), "{text}");
        let terms = wicket_store::NameTerms { bound: wicket_store::StandingBound::Agent, ttl_secs: None };
        let public = names_settings().public.unwrap();
        w.ledger.lock().unwrap().approve_name(&id, &terms, "ann", None, &public).unwrap();
        let (text, err) = gw.call_tool("await_grant", serde_json::json!({ "request_id": id, "timeout_seconds": 5 })).await;
        assert!(!err && text.starts_with("granted") && text.contains("this run holds it"), "{text}");
        // Another agent can't wait on it.
        let other = w.boxed(w.zone("build", &[]), "other", "run_other", None, &[]);
        let (text, err) = crate::Gateway::new(other).call_tool("await_grant", serde_json::json!({ "request_id": id })).await;
        assert!(err && text.contains("not this agent's"), "{text}");
        let audit = w.ledger.lock().unwrap().audit_tail(30).unwrap();
        assert!(audit.iter().any(|a| a.2 == "name.requested" && a.4.contains(&id)));
        // No agent decides it, its own parent's included (#680 review, L4).
        let (text, err) = gw.call_tool("decide", serde_json::json!({ "decision": "approve", "request_id": id })).await;
        assert!(err && text.contains("decided by a human"), "{text}");
        // The reason is marked as the agent's (#680 review, L3).
        assert!(w.ledger.lock().unwrap().name(&id).unwrap().reason.starts_with(wicket_store::AGENT_ASKS_PREFIX));
        // An internal name takes neither scope standing nor a service.
        let (text, err) = crate::names::request_name(&api, &serde_json::json!({ "name": "x", "port": 1, "scope": "standing" }));
        assert!(err && text.contains("`scope` is for public names"), "{text}");
        let (text, err) = crate::names::request_name(&api, &serde_json::json!({ "name": "x", "port": 1, "service": "http" }));
        assert!(err && text.contains("`service` is for public names"), "{text}");
        // It holds one public name, this installation's limit: another ask is refused up front.
        let (text, err) = ask("second");
        assert!(err && text.contains("already hold 1 public name"), "{text}");
        // An installation without names.public takes no asks.
        let mut bare = w.boxed(w.zone("build", &[]), "bare", "run_bare", None, &[]);
        bare.names = None;
        let (text, err) = crate::names::request_name(&bare, &serde_json::json!({ "name": "demo2", "port": 3000, "kind": "public" }));
        assert!(err && text.contains("publishes no public names"), "{text}");
    }

    #[tokio::test]
    async fn a_parent_reaches_its_child_and_the_link_closes_when_cut() {
        let w = World::new();
        let child_zone = w.zone("lead.svc", &[]);
        let lead = w.boxed(w.zone("lead", &[]), "lead", "run_lead", None, &[("run_svc", child_zone.clone())]);
        let _svc = w.boxed(child_zone, "svc", "run_svc", Some("run_lead"), &[]);

        // By name, without the child exposing anything.
        let (text, err) = connect(&lead, "svc", Some(8000)).await;
        assert!(!err, "{text}");
        assert!(text.contains("svc.wicket.internal:8000") && text.contains("(child)"), "{text}");
        let id = link_id(&text);
        let hosts = std::fs::read_to_string(w.root.join("run_lead/hosts")).unwrap();
        assert!(hosts.contains("198.18.1.1\tsvc.wicket.internal"), "{hosts}");
        let sock = w.root.join("run_lead/sock").join(format!("link-{id}.sock"));
        assert_eq!(roundtrip(&sock).await.unwrap(), "run_svc:ping");
        // Connecting again is idempotent.
        assert!(connect(&lead, "svc", Some(8000)).await.0.contains("already linked"));
        let audit = w.ledger.lock().unwrap().audit_tail(20).unwrap();
        assert!(audit.iter().any(|a| a.2 == "link.open" && a.4.contains("not propagated")), "the link is audited, labels noted");

        // Cut: the relay closes it, removes the socket and the name.
        assert!(!unlink(&lead, &id).1);
        let r = wait_closed(&w, &id).await;
        assert_eq!(r.closed_by.as_deref(), Some("run_lead"));
        assert!(roundtrip(&sock).await.is_err());
        assert!(!std::fs::read_to_string(w.root.join("run_lead/hosts")).unwrap().contains("svc.wicket.internal"));
        assert!(w.ledger.lock().unwrap().audit_tail(20).unwrap().iter().any(|a| a.2 == "link.close"));
    }

    #[tokio::test]
    async fn revoking_either_end_or_ending_its_run_closes_the_link() {
        let w = World::new();
        let (za, zb) = (w.zone("lead.a", &[]), w.zone("lead.b", &[]));
        let lead = w.boxed(w.zone("lead", &[]), "lead", "run_lead", None, &[("run_a", za.clone()), ("run_b", zb.clone())]);
        let _a = w.boxed(za, "a", "run_a", Some("run_lead"), &[]);
        let _b = w.boxed(zb, "b", "run_b", Some("run_lead"), &[]);

        // The parent links its two children: a reaches b.
        let (text, err) = link(&lead, "a", "b", Some(9222)).await;
        assert!(!err && text.contains("b.wicket.internal:9222"), "{text}");
        let id = link_id(&text);
        assert!(std::fs::read_to_string(w.root.join("run_a/hosts")).unwrap().contains("b.wicket.internal"));
        assert_eq!(roundtrip(&w.root.join("run_a/sock").join(format!("link-{id}.sock"))).await.unwrap(), "run_b:ping");
        w.ledger.lock().unwrap().revoke("run_b", "owner", "test").unwrap();
        assert!(wait_closed(&w, &id).await.close_reason.unwrap().contains("revoked"));

        // A fresh link, then the connecting box's run ends.
        let (text, err) = link(&lead, "b", "a", Some(80)).await;
        assert!(err && text.contains("revoked"), "b is revoked, so it can't link: {text}");
        let (text, err) = connect(&lead, "a", Some(80)).await;
        assert!(!err, "{text}");
        let id = link_id(&text);
        w.ledger.lock().unwrap().run_ended(&RunId("run_a".into()), "succeeded", "{}").unwrap();
        assert!(wait_closed(&w, &id).await.close_reason.unwrap().contains("ended"));
        let (text, err) = connect(&lead, "run_a", Some(80)).await;
        assert!(err && text.contains("not running"), "{text}");
    }

    #[tokio::test]
    async fn strangers_need_expose_and_accept_from_or_a_human() {
        let w = World::new();
        let alice = w.boxed(w.zone("alice", &[]), "alice", "run_alice", None, &[]);
        let bob = w.boxed(w.zone("bob", &["alice"]), "bob", "run_bob", None, &[]);
        let carol = w.boxed(w.zone("carol", &[]), "carol", "run_carol", None, &[]);

        // Not exposed: refused, no human can override the target's consent.
        let (text, err) = connect(&alice, "run_bob", Some(5432)).await;
        assert!(err && text.contains("has not exposed"), "{text}");
        assert!(!expose(&bob, 5432, Some("db")).1);
        let (text, err) = connect(&alice, "run_bob", Some(5432)).await;
        assert!(!err && text.contains("db.wicket.internal:5432") && text.contains("accept_from"), "{text}");

        // carol exposes, but doesn't accept alice's zone: pending a human, then allowed once.
        expose(&carol, 6379, None);
        let (text, err) = connect(&alice, "run_carol", Some(6379)).await;
        assert!(!err && text.starts_with("needs approval"), "{text}");
        let rid = text.split_whitespace().nth(3).unwrap().to_string();
        {
            let mut l = w.ledger.lock().unwrap();
            let a = wicket_store::Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() };
            l.approve(&rid, &a).unwrap();
        }
        // #369: approved under the name it was asked under; carol renaming it after the approval
        // is refused and audited, and doesn't use the grant up.
        assert!(!expose(&carol, 6379, Some("github")).1);
        let (text, err) = connect(&alice, "run_carol", Some(6379)).await;
        assert!(err && text.contains("name changed after the approval"), "{text}");
        assert!(w.ledger.lock().unwrap().audit_tail(20).unwrap().iter().any(|a| a.2 == "effect.refused"));
        assert!(!expose(&carol, 6379, None).1);
        let (text, err) = connect(&alice, "run_carol", Some(6379)).await;
        assert!(!err && text.contains("carol.wicket.internal:6379") && text.contains("approved"), "{text}");
        // Another tenant's or nobody's box: no such box.
        assert!(connect(&alice, "run_nobody", Some(1)).await.0.contains("no box"));
        // A box that can't link (no local box dir) is refused.
        let mut nowhere = alice.clone();
        nowhere.boxes = None;
        assert!(connect(&nowhere, "run_bob", Some(5432)).await.0.contains("links need a box"));
    }

    /// #250, #253: an `accept_from` principal entry lets that principal connect, as it lets it send
    /// messages; another box in the same zone still needs a human.
    #[tokio::test]
    async fn accept_from_may_name_one_principal() {
        let w = World::new();
        let alice = w.boxed(w.zone("team", &[]), "alice", "run_alice", None, &[]);
        let eve = w.boxed(w.zone("team", &[]), "eve", "run_eve", None, &[]);
        let alice_id = w.ledger.lock().unwrap().identity("run_alice").unwrap().unwrap().spiffe_id;
        let dave = w.boxed(w.zone("db", &[alice_id.as_str()]), "dave", "run_dave", None, &[]);
        let (text, err) = expose(&dave, 5432, Some("db"));
        assert!(!err && text.contains(&alice_id), "{text}");
        let (text, err) = connect(&alice, "run_dave", Some(5432)).await;
        assert!(!err && text.contains("db.wicket.internal:5432") && text.contains("accept_from"), "{text}");
        let (text, err) = connect(&eve, "run_dave", Some(5432)).await;
        assert!(!err && text.starts_with("needs approval"), "{text}");
    }
}

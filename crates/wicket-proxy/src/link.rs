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

use crate::{Event, RunCtx};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use wicket_core::link::{self as policy, Decision, End, Named};
use wicket_core::{Op, ZoneSpec};
use wicket_store::LinkRow;

/// How often a relay checks that its link may stay open.
pub const POLL: Duration = Duration::from_secs(2);
/// What labels do across a link (recorded with every link).
pub const LABELS: &str = "not propagated: wicket has no data-label mechanism yet (design §4.2); deferred";

/// A byte stream into a box. Dropping `guard` ends whatever carries it (e.g. a `docker exec`).
pub struct Stream {
    pub read: Box<dyn AsyncRead + Unpin + Send>,
    pub write: Box<dyn AsyncWrite + Unpin + Send>,
    pub guard: Box<dyn std::any::Any + Send>,
}

type Fut<'a, T> = futures_util::future::BoxFuture<'a, T>;

/// What links need from the boxes themselves, supplied by whoever runs them (`wicket run`): each box
/// is reached on its own node.
pub trait BoxOps: Send + Sync {
    /// Whether wicket can link `run`'s box (running, on a node it reaches), and if not, why.
    fn reachable<'a>(&'a self, run: &'a str) -> Fut<'a, Result<(), String>>;
    /// The zone of one of this run's own children, from the record of its spawn.
    fn child_zone(&self, child_run: &str) -> Option<ZoneSpec>;
    /// Rewrites `run`'s box's /etc/hosts.
    fn set_hosts<'a>(&'a self, run: &'a str, text: String) -> Fut<'a, Result<(), String>>;
    /// Listens on the unix socket `sock` in `run`'s box's socket directory (the box sees it as
    /// `/wicket/sock/<sock>`): its connections, as they come.
    fn accept<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, Result<tokio::sync::mpsc::UnboundedReceiver<Stream>, String>>;
    /// Stops that (best effort).
    fn close_accept<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, ()>;
    /// Starts, inside `run`'s box, a listener on `addr:port` that forwards each connection to the
    /// in-box unix socket `sock`.
    fn listen<'a>(&'a self, run: &'a str, addr: Ipv4Addr, port: u16, sock: &'a str) -> Fut<'a, Result<(), String>>;
    /// Stops that listener (best effort; the box may be gone).
    fn unlisten<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, ()>;
    /// A byte stream to 127.0.0.1:`port` inside `run`'s box.
    fn dial<'a>(&'a self, run: &'a str, port: u16) -> Fut<'a, Result<Stream, String>>;
    /// Listens on `sock` in `run`'s box with the node itself dialing `to`'s `port` for each
    /// connection, when both boxes are on one node that does (#164): the bytes never leave it, and
    /// the link outlives the control connection. Ok(false): relay it here instead.
    fn accept_direct<'a>(&'a self, _run: &'a str, _sock: &'a str, _to: &'a str, _port: u16) -> Fut<'a, Result<bool, String>> {
        Box::pin(async { Ok(false) })
    }
}

type Reply = (String, bool);

fn ledger(ctx: &RunCtx) -> std::sync::MutexGuard<'_, wicket_store::Ledger> {
    ctx.ledger.lock().expect("ledger")
}

/// `expose(port, name?)`: this box offers `port` to boxes whose zones its `accept_from` lists (and to
/// others a human approves). Its parent doesn't need it.
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
    // On the record before it takes effect (fail closed).
    if let Err(e) = l.audit(&ctx.tenant, Some(&ctx.run), "link.expose", &serde_json::json!({ "port": port, "name": name })) {
        let _ = l.unexpose(&ctx.run.0, port);
        return (format!("not exposed: the audit record could not be written ({e})"), true);
    }
    let who = if ctx.zone.accept_from.is_empty() {
        "your parent (always), and boxes a human approves".to_string()
    } else {
        format!("your parent, boxes in zones {} (your accept_from), and boxes a human approves", ctx.zone.accept_from.join(", "))
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
    accept_from: Vec<String>,
    zone: Option<ZoneSpec>,
}

impl EndInfo {
    fn end(&self) -> End<'_> {
        End {
            run: &self.run,
            parent_run: self.parent_run.as_deref(),
            zone_name: &self.zone_name,
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
        EndInfo { run: run.into(), agent: rec.agent, parent_run: rec.parent_run, zone_name: rec.zone, accept_from: rec.accept_from, zone },
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
    open(ctx, ops, &me, &t, port, d, &wanted).await
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
        open(ctx, ops, &f, &t, port, d, &wanted).await
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

async fn open(
    ctx: &RunCtx,
    ops: Arc<dyn BoxOps>,
    from: &EndInfo,
    to: &EndInfo,
    port: u16,
    d: Decision,
    wanted: &str,
) -> Result<String, String> {
    ops.reachable(&from.run).await?;
    ops.reachable(&to.run).await?;
    let existing = ledger(ctx).open_link(&from.run, &to.run, port).map_err(|e| e.to_string())?;
    if let Some(r) = existing {
        return Ok(format!("already linked ({}): {}.{}:{port}", r.id, r.name, policy::DOMAIN));
    }
    // Beyond the default policy: a human approves exactly this link.
    let mut basis = d.basis.map(|b| b.as_str().to_string());
    let mut grant = None;
    if !d.allowed() {
        let op =
            Op::egress(&ctx.tenant, &ctx.run, &ctx.zone.name, "LINK", policy::DOMAIN, &format!("/links/{}/{}/{port}", from.run, to.run));
        let mut l = ledger(ctx);
        match l.consume_grant(&op).map_err(|e| e.to_string())? {
            Some(g) => {
                basis = Some(format!("approved ({g})"));
                grant = Some(g);
            }
            None => {
                if let Ok(Some(rid)) = l.denied_recently(&op) {
                    return Err(format!("a human denied exactly this link ({rid}) a few minutes ago; don't ask again"));
                }
                let reason = format!(
                    "link box {} ({}) to port {port} of box {} ({}): {}",
                    from.agent,
                    from.zone_name,
                    to.agent,
                    to.zone_name,
                    d.needs_human.join("; ")
                );
                let (rid, _) = l.pending_for(&op, &reason, None).map_err(|e| e.to_string())?;
                return Ok(format!(
                    "needs human approval: request {rid} ({}). Call await_grant with {rid}; once granted, make the same call again.",
                    d.needs_human.join("; ")
                ));
            }
        }
    }
    let basis = basis.unwrap_or_else(|| "approved".into());

    let used: Vec<Named> = ledger(ctx)
        .links_from(&from.run)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|r| Some(Named { name: r.name, addr: r.addr.parse().ok()?, to_run: r.to_run }))
        .collect();
    let (name, addr) = policy::allocate(&used, &to.run, wanted)?;
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
    use crate::{IdentityCell, RunIdentity};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use wicket_core::{Manifest, RunId, TenantId};
    use wicket_identity::{AgentKey, Issuer};
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
                let l = crate::sockpath::bind(&path).map_err(|e| e.to_string())?;
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
            let root = std::env::temp_dir().join(format!("wicket-link-test-{}", ulid::Ulid::new()));
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
                vault: crate::vault::Vault::new(std::env::temp_dir()),
                events: tx,
                escalate: true,
                attribute: None,
                identity: Some(Arc::new(IdentityCell::new(RunIdentity { jws, claims, key, issuer: self.issuer.verifying_key() }))),
                spawner: None,
                swaps: vec![],
                boxes: Some(Arc::new(boxes)),
                capacity: None,
                decisions: None,
                fence: None,
                waker: None,
                lifecycle: None,
            }
        }
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
        assert!(!err && text.starts_with("needs human approval"), "{text}");
        let rid = text.split_whitespace().nth(4).unwrap().to_string();
        {
            let mut l = w.ledger.lock().unwrap();
            let a = wicket_store::Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() };
            l.approve(&rid, &a).unwrap();
        }
        let (text, err) = connect(&alice, "run_carol", Some(6379)).await;
        assert!(!err && text.contains("carol.wicket.internal:6379") && text.contains("approved"), "{text}");
        // Another tenant's or nobody's box: no such box.
        assert!(connect(&alice, "run_nobody", Some(1)).await.0.contains("no box"));
        // A box that can't link (no local box dir) is refused.
        let mut nowhere = alice.clone();
        nowhere.boxes = None;
        assert!(connect(&nowhere, "run_bob", Some(5432)).await.0.contains("links need a box"));
    }
}

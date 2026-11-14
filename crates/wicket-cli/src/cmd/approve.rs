//! `wicket pending`, `approve`, `deny`, `grant`, `links` and `unlink`: human decisions.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Pending => {
            let l = Ledger::open(&ledger_path())?;
            let p = l.pending(&TenantId::single())?;
            if p.is_empty() {
                println!("no pending requests");
            }
            for r in p {
                print!("{}", show_request(&l, &r));
            }
            Ok(())
        }
        Cmd::Approve { id, uses, unlimited, ttl, prefix, yes, zone_wide } => {
            let ttl = humantime::parse_duration(&ttl).context("bad --ttl")?;
            if ttl > Duration::from_secs(24 * 3600) {
                bail!("grants are capped at 24h in the PoC");
            }
            let mut l = Ledger::open(&ledger_path())?;
            let req = l.request(&id)?;
            // What is approved is what wicket recorded, shown before the grant exists: a hint printed
            // from a node's or an agent's text can name the wrong request (#121).
            print!("{}", show_request(&l, &req));
            if !yes && std::io::stdin().is_terminal() && !confirm(&format!("approve {id} as shown above?"))? {
                bail!("not approved");
            }
            let d = Decide { by: operator(), uses: if unlimited { None } else { Some(uses) }, ttl, prefix: prefix.clone(), zone_wide };
            let Approved { grant: gid, lease, .. } = approve_request(&mut l, &id, &d, serde_json::json!({}))?;
            println!(
                "approved {id} → grant {gid}: {} {}{} ({}, {}, {})",
                wicket_agent::clip(&req.method, 16),
                wicket_agent::clip(&req.host, 255),
                wicket_agent::clip(&prefix.as_deref().map(|p| format!("{p}* [prefix]")).unwrap_or(req.path), 400),
                if unlimited { "unlimited uses".into() } else { format!("{uses} use(s)") },
                humantime::format_duration(ttl),
                if zone_wide { format!("any run in zone {}", wicket_agent::clip(&req.zone, 64)) } else { format!("run {} only", req.run) }
            );
            if let Some(lease) = lease.as_deref() {
                // A capacity ask: provision now rather than at the next pass of a running reconciler.
                drop(l);
                println!("provisioning lease {lease} (one reconcile pass)");
                reconcile::print(&reconcile::pass(false).await?, false);
                if let Some(x) = Ledger::open(&ledger_path())?.lease(lease)? {
                    println!("lease {lease}: {} {}", x.status, x.node_name.or(x.detail).unwrap_or_default());
                }
            }
            Ok(())
        }
        Cmd::Links { tail } => {
            let l = Ledger::open(&ledger_path())?;
            let rows = l.links(&TenantId::single(), tail)?;
            if rows.is_empty() {
                println!("no links");
            }
            for r in rows {
                println!(
                    "{}  {:6}  {} → {}.{}:{} ({})  opened by {} ({}){}",
                    r.id,
                    r.status,
                    r.from_run,
                    r.name,
                    wicket_core::link::DOMAIN,
                    r.port,
                    r.to_run,
                    r.by_run,
                    r.basis,
                    r.close_reason.map(|c| format!("; closed: {c}")).unwrap_or_default()
                );
            }
            Ok(())
        }
        Cmd::Unlink { id } => {
            let l = Ledger::open(&ledger_path())?;
            let r = l.link(&id)?.with_context(|| format!("no link {id}"))?;
            if l.close_link(&id, &operator(), "cut by the operator")? {
                l.audit(
                    &TenantId::single(),
                    None,
                    "link.cut",
                    &serde_json::json!({ "id": id, "by": operator(), "from": r.from_run, "to": r.to_run, "port": r.port }),
                )?;
                println!("cut {id}; its relay closes it within a few seconds");
            } else {
                println!("{id} was already closed");
            }
            Ok(())
        }
        Cmd::Deny { id } => {
            let l = Ledger::open(&ledger_path())?;
            if let Some(lease) = deny_request(&l, &id, &operator(), serde_json::json!({}))? {
                println!("lease {lease} denied: its reservation is released");
            }
            println!("denied {id}");
            Ok(())
        }
        Cmd::Grant { cmd: GrantCmd::Revoke { id } } => {
            let l = Ledger::open(&ledger_path())?;
            let g = l.grant(&id)?.with_context(|| format!("no grant {id}"))?;
            l.revoke_grant(&id)?;
            l.audit(&TenantId::single(), None, "grant.revoked", &serde_json::json!({ "grant": id, "by": operator(), "node": g.node }))?;
            match &g.node {
                Some(n) => println!("revoked {id}; its run pushes the revocation to node {n}"),
                None => println!("revoked {id}"),
            }
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

/// A human's approval of a pending request, as `wicket approve` and the console both make it.
pub struct Decide {
    /// Who decided: `$USER`-style on the CLI, `passkey:<name>` on the console.
    pub by: String,
    /// None: unlimited uses until it expires.
    pub uses: Option<u32>,
    pub ttl: Duration,
    /// Grant every path under this prefix: one that covers the asked path, or (for a prefix ask)
    /// lies within the asked prefix.
    pub prefix: Option<String>,
    /// Usable by any run in the request's zone, not only the one that asked.
    pub zone_wide: bool,
}

/// What [`approve_request`] made.
pub struct Approved {
    pub grant: String,
    /// The capacity lease the request asked for, if it is a capacity ask: provisioned by the next
    /// reconcile pass (`wicket approve` runs one at once).
    pub lease: Option<String>,
}

/// Approves a pending request: one grant, which exists only if its approval is on the audit record
/// (otherwise it is revoked again: fail closed). `extra` is merged into the record (the console's
/// signed decision).
pub fn approve_request(l: &mut Ledger, id: &str, d: &Decide, extra: serde_json::Value) -> Result<Approved> {
    let req = l.request(id)?;
    if let Some(p) = &d.prefix {
        check_prefix(&req, p).map_err(anyhow::Error::msg)?;
    }
    let lease = capacity::lease_of_request(l, &req)?;
    let a = Approval { uses: d.uses, ttl: d.ttl, path_prefix: d.prefix.clone(), decided_by: d.by.clone() };
    let gid = if d.zone_wide { l.approve_zone_wide(id, &a)? } else { l.approve(id, &a)? };
    let mut record = serde_json::json!({
        "request": id, "decision": "approve", "grant": gid, "by": d.by,
        "method": req.method, "host": req.host, "path": req.path,
        "requested_by": req.attribution.iter().flat_map(wicket_proxy::attributed_agents).collect::<Vec<_>>(),
        "agent_identity": verified_identity(l, &req.run, None),
        "uses": d.uses, "ttl_secs": d.ttl.as_secs(), "prefix": d.prefix, "scope_prefix": req.scope_prefix,
        "scope": if d.zone_wide { "zone" } else { "run" }, "run": req.run, "zone": req.zone, "lease": lease,
    });
    merge(&mut record, extra);
    if let Err(e) = l.audit(&TenantId::single(), None, "decision", &record) {
        let _ = l.revoke_grant(&gid);
        return Err(anyhow::Error::from(e).context("the approval could not be recorded in the audit log, so its grant was revoked"));
    }
    Ok(Approved { grant: gid, lease })
}

/// Denies a pending request and records it; a capacity ask's reservation is released at once.
/// Returns that lease, if any.
pub fn deny_request(l: &Ledger, id: &str, by: &str, extra: serde_json::Value) -> Result<Option<String>> {
    l.deny(id, by)?;
    let mut record = serde_json::json!({ "request": id, "decision": "deny", "by": by });
    merge(&mut record, extra);
    l.audit(&TenantId::single(), None, "decision", &record)?;
    let req = l.request(id)?;
    let lease = capacity::lease_of_request(l, &req)?;
    if let Some(lease) = lease.as_deref() {
        l.lease_ended(lease, "denied", &format!("request {id} denied by {by}"), None)?;
    }
    Ok(lease)
}

/// Whether a human's prefix may be granted for `req`: it covers the asked path, or (for a prefix ask)
/// lies within the asked prefix. What the grant covers is what the human named, never a silent
/// fall-back to the exact path.
pub fn check_prefix(req: &wicket_store::Request, p: &str) -> std::result::Result<(), String> {
    let within = req.scope_prefix && wicket_core::prefix_covers(&req.path, p);
    if wicket_core::prefix_covers(p, &req.path) || within {
        return Ok(());
    }
    Err(format!("prefix {p} doesn't cover {}'s path {}{}", req.id, req.path, if req.scope_prefix { ", nor lie within it" } else { "" }))
}

fn merge(record: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(r), serde_json::Value::Object(x)) = (record.as_object_mut(), extra) {
        r.extend(x);
    }
}

#[derive(Subcommand)]
pub enum GrantCmd {
    /// Revoke a grant. A grant handed to a node is revoked there through its feed by the run that
    /// published it (at once if the node is reachable).
    Revoke { id: String },
}

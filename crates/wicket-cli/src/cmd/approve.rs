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
            let lease = capacity::lease_of_request(&l, &req)?;
            let a = Approval { uses: if unlimited { None } else { Some(uses) }, ttl, path_prefix: prefix.clone(), decided_by: operator() };
            let gid = if zone_wide { l.approve_zone_wide(&id, &a)? } else { l.approve(&id, &a)? };
            // What the grant is made with: a push gets its window, whatever was picked (#26).
            let (uses, ttl) = match prefix.is_some() || req.scope_prefix {
                true => (a.uses, ttl.as_secs()),
                false => wicket_core::git::grant_terms(&req.method, &req.path, a.uses, ttl.as_secs()),
            };
            let (unlimited, uses, ttl) = (uses.is_none(), uses.unwrap_or(0), Duration::from_secs(ttl));
            // A grant exists only if its approval is on the record (fail closed).
            if let Err(e) = l.audit(
                &TenantId::single(),
                None,
                "decision",
                &serde_json::json!({
                    "request": id, "decision": "approve", "grant": gid, "by": operator(),
                    "method": req.method, "host": req.host, "path": req.path,
                    "requested_by": req.attribution.iter().flat_map(wicket_proxy::attributed_agents).collect::<Vec<_>>(),
                    "agent_identity": verified_identity(&l, &req.run, None),
                    "uses": if unlimited { None } else { Some(uses) }, "ttl_secs": ttl.as_secs(), "prefix": prefix,
                    "scope": if zone_wide { "zone" } else { "run" }, "run": req.run, "zone": req.zone,
                }),
            ) {
                let _ = l.revoke_grant(&gid);
                return Err(anyhow::Error::from(e).context("the approval could not be recorded in the audit log, so its grant was revoked"));
            }
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
            l.deny(&id, &operator())?;
            l.audit(&TenantId::single(), None, "decision", &serde_json::json!({ "request": id, "decision": "deny", "by": operator() }))?;
            let req = l.request(&id)?;
            if let Some(lease) = capacity::lease_of_request(&l, &req)?.as_deref() {
                l.lease_ended(lease, "denied", &format!("request {id} denied by {}", operator()), None)?;
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

#[derive(Subcommand)]
pub enum GrantCmd {
    /// Revoke a grant. A grant handed to a node is revoked there through its feed by the run that
    /// published it (at once if the node is reachable).
    Revoke { id: String },
}

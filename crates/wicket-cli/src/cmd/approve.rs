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
            let mut l = Ledger::open(&ledger_path())?;
            let req = l.request(&id)?;
            let t = grant::Terms { uses: if unlimited { None } else { Some(uses) }, ttl, prefix: prefix.clone(), zone_wide };
            grant::check_terms(&req, &t)?;
            // What is approved is what wicket recorded, shown before the grant exists: a hint printed
            // from a node's or an agent's text can name the wrong request (#121).
            print!("{}", show_request(&l, &req));
            if !yes && std::io::stdin().is_terminal() && !confirm(&format!("approve {id} as shown above?"))? {
                bail!("not approved");
            }
            let grant::Decided::Approved { grant: gid, lease } =
                grant::decide(&mut l, &grant::Granter::Human(operator()), &id, &grant::Verdict::Approve(t), serde_json::json!({}))?
            else {
                unreachable!("an approval approves")
            };
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
            let mut l = Ledger::open(&ledger_path())?;
            if let grant::Decided::Denied { lease: Some(lease) } =
                grant::decide(&mut l, &grant::Granter::Human(operator()), &id, &grant::Verdict::Deny, serde_json::json!({}))?
            {
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

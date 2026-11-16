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
            let grant::Decided::Approved { grant: gid, lease, uses: made_uses, ttl } = grant::decide(
                &mut l,
                &grant::Granter::Human(crate::operators::Operator::cli(&TenantId::single().0)?),
                &id,
                &grant::Verdict::Approve(t),
                serde_json::json!({}),
            )?
            else {
                unreachable!("an approval approves")
            };
            // What the grant was made with: a push gets its window, whatever was picked (#26).
            let (unlimited, uses) = (made_uses.is_none(), made_uses.unwrap_or(0));
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
            if let grant::Decided::Denied { lease: Some(lease) } = grant::decide(
                &mut l,
                &grant::Granter::Human(crate::operators::Operator::cli(&TenantId::single().0)?),
                &id,
                &grant::Verdict::Deny,
                serde_json::json!({}),
            )? {
                println!("lease {lease} denied: its reservation is released");
            }
            println!("denied {id}");
            Ok(())
        }
        Cmd::Grant { cmd: GrantCmd::List { all, tail } } => {
            let l = Ledger::open(&ledger_path())?;
            let rows = l.grants(&TenantId::single(), all, tail)?;
            if rows.is_empty() {
                println!("no {}grants", if all { "" } else { "live " });
            }
            let now = wicket_store::now();
            for r in rows {
                println!("{}", show_grant(&r, now));
            }
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
        Cmd::Grant { cmd: GrantCmd::Renew { id, ttl } } => {
            let ttl = humantime::parse_duration(&ttl).context("bad --ttl")?;
            let mut l = Ledger::open(&ledger_path())?;
            let grant::Decided::Renewed { what, until } = grant::decide(
                &mut l,
                &grant::Granter::Human(crate::operators::Operator::cli(&TenantId::single().0)?),
                &id,
                &grant::Verdict::Renew(ttl),
                serde_json::json!({}),
            )?
            else {
                unreachable!("a renewal renews")
            };
            let left = humantime::format_duration(std::time::Duration::from_secs(u64::try_from(until - wicket_store::now()).unwrap_or(0)));
            match what {
                grant::Renewed::Grant(g) => match l.grant(&g)?.and_then(|g| g.node) {
                    Some(n) => println!("renewed grant {g} for {left}; its run republishes it to node {n}"),
                    None => println!("renewed grant {g} for {left}"),
                },
                grant::Renewed::Authority(r) => {
                    println!("renewed box {r}'s authority for {left}; its run re-mints the box's token on its node")
                }
            }
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

/// One line of `wicket grant list`: what it grants (a quota's resource and amount, or an approval's
/// method, host and path), to whom, how much is left, when it ends, and who made it.
fn show_grant(r: &wicket_store::GrantListing, now: i64) -> String {
    let g = &r.grant;
    let what = match (g.quota(), g.amount) {
        // A lease's money (#256): micro-USD, and the lease it is for.
        (Some(res @ (wicket_store::MONEY_HOURLY | wicket_store::MONEY_RESERVED)), Some(n)) => {
            let lease = g.path.rsplit('/').next().unwrap_or_default();
            let unit = if res == wicket_store::MONEY_HOURLY { "/h" } else { "" };
            format!("quota {res} = ${}.{:06}{unit} (lease {})", n / 1_000_000, n % 1_000_000, wicket_agent::clip(lease, 64))
        }
        // A standing capacity grant (#256): its daily money; its whole terms are on the console's
        // Capacity card and in its `decision` record.
        (Some("capacity"), Some(n)) if g.path == wicket_store::CAPACITY_GRANT_PATH => {
            format!("capacity grant, at most ${}.{:06} a day", n / 1_000_000, n % 1_000_000)
        }
        (Some(res), Some(n)) => format!("quota {res} = {n}"),
        _ => format!(
            "{} {}{}",
            wicket_agent::clip(&g.method, 16),
            wicket_agent::clip(&g.host, 255),
            wicket_agent::clip(&if g.prefix { format!("{}* [prefix]", g.path) } else { g.path.clone() }, 400)
        ),
    };
    let to = match &g.run {
        Some(run) => format!("run {run}"),
        None if g.path == wicket_store::CAPACITY_GRANT_PATH && g.amount.is_some() => {
            "a principal (the console's Capacity card)".to_string()
        }
        None => format!("any run in zone {}", wicket_agent::clip(&g.zone, 64)),
    };
    let uses = match (g.amount, g.uses_left) {
        (Some(_), _) => String::new(),
        (None, Some(n)) => format!(", {n} use(s) left"),
        (None, None) => ", unlimited uses".into(),
    };
    let state = if g.revoked {
        "revoked".to_string()
    } else if g.expires_at <= now {
        "expired".to_string()
    } else {
        format!("ends in {}", humantime::format_duration(std::time::Duration::from_secs(u64::try_from(g.expires_at - now).unwrap_or(0))))
    };
    let node = g.node.as_deref().map(|n| format!(", on node {n}")).unwrap_or_default();
    format!("{}  {what}  {to}{uses}, {state}{node}  by {}", g.id, wicket_agent::clip(&r.decided_by, 80))
}

#[derive(Subcommand)]
pub enum GrantCmd {
    /// List grants, newest first: approvals, and runs' quotas (#256): model budget, children and
    /// bytes (a root run's own zone budget, or what its parent carved for a child: the limits its
    /// run enforces), and money (a capacity lease's hourly cap and reservation, micro-USD shown as
    /// USD). Every grant has a lifetime; only live ones unless --all.
    List {
        /// Also revoked and expired grants.
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = 40)]
        tail: usize,
    },
    /// Revoke a grant. A grant handed to a node is revoked there through its feed by the run that
    /// published it (at once if the node is reachable).
    Revoke { id: String },
    /// Renew a live grant, or a running box's authority, so it lasts --ttl from now (#56): a grant
    /// by its id (or the request it answers), a box's authority by its run id. Every grant keeps a
    /// lifetime: at most 24h, and a box's authority never past its run's timeout. Audited as a
    /// decision; the run publishes it to the box's node.
    Renew {
        /// A grant id (`g-…`), a request id (`r-…`: the grant made for it), or a running box's run id.
        id: String,
        /// The new lifetime, from now.
        #[arg(long, default_value = "10m")]
        ttl: String,
    },
}

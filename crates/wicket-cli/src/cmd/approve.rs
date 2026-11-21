//! `wicket pending`, `approve`, `deny`, `grant`, `links` and `unlink`: human decisions.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Pending { json } => {
            let l = Ledger::open(&ledger_path())?;
            if json {
                return crate::cmd::print_json(&pending_json(&l)?);
            }
            print!("{}", pending_text(&l)?);
            Ok(())
        }
        Cmd::Approve { id, uses, unlimited, ttl, prefix, yes, zone_wide } => {
            if let Some(e) = elsewhere(&id, "approve") {
                return Err(e);
            }
            let mut l = Ledger::open(&ledger_path())?;
            let req = l.request(&id)?;
            let t = grant::Terms { uses: if unlimited { None } else { Some(uses) }, ttl, prefix: prefix.clone(), zone_wide };
            // Terms the request doesn't allow are refused (exit 3, #574).
            grant::check_terms(&req, &t).map_err(|e| wicket_home::exit::refused(format!("{e:#}")))?;
            // What is approved is what wicket recorded, shown before the grant exists: a hint printed
            // from a node's or an agent's text can name the wrong request (#121).
            print!("{}", show_request(&l, &req));
            // The effect the grant will be for (#369), and what else it would allow if it widens.
            let shown = crate::effect::descriptor(&req, Some(&t));
            let shown_sha = shown.sha256();
            println!("effect {shown_sha}: {}", wicket_core::text::clip(&shown.canonical(), 2000));
            let zone = crate::effect::zone_of_run(&l, &data_dir(), &req.run);
            if let Some(b) = crate::effect::blast_radius(&l, zone.as_ref(), &req, &t)? {
                print!("{}", crate::effect::render(&b));
            }
            if !yes && std::io::stdin().is_terminal() && !confirm(&format!("approve {id} as shown above?"))? {
                return Err(wicket_home::exit::refused("not approved: declined at the confirmation"));
            }
            let grant::Decided::Approved { grant: gid, lease, uses: made_uses, ttl } = grant::decide(
                &mut l,
                &grant::Granter::Human(crate::operators::Operator::cli(&TenantId::single().0)?),
                &id,
                &grant::Verdict::Approve(t),
                serde_json::json!({ crate::effect::SHOWN_EFFECT: shown_sha }),
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
                wicket_core::time::format_duration(ttl),
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
        Cmd::Links { tail, json } => {
            let l = Ledger::open(&ledger_path())?;
            let rows = l.links(&TenantId::single(), tail)?;
            if json {
                return crate::cmd::print_json(&links_json(&rows));
            }
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
            cut_link(&l, &TenantId::single(), &id, &operator(), serde_json::json!({ "via": "cli" }))?;
            println!("cut {id}; its relay closes it within a few seconds");
            Ok(())
        }
        Cmd::Deny { id } => {
            if let Some(e) = elsewhere(&id, "deny") {
                return Err(e);
            }
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
        Cmd::Grant { cmd: GrantCmd::List { all, tail, json } } => {
            let l = Ledger::open(&ledger_path())?;
            let rows = l.grants(&TenantId::single(), all, tail)?;
            if json {
                let now = wicket_store::now();
                return crate::cmd::print_json(&grants_json(&rows, now));
            }
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
            println!("{}", revoke_grant(&l, &TenantId::single(), &id, &operator(), serde_json::json!({ "via": "cli" }))?);
            Ok(())
        }
        Cmd::Grant { cmd: GrantCmd::Renew { id, ttl } } => {
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
            let left =
                wicket_core::time::format_duration(std::time::Duration::from_secs(u64::try_from(until - wicket_store::now()).unwrap_or(0)));
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

/// `wicket pending` as text: the pending requests, then standing asks (#572, decided with `wicket
/// standing`), then asks for public names (#575, decided with `wicket names`).
pub(crate) fn pending_text(l: &Ledger) -> Result<String> {
    use std::fmt::Write;
    let t = TenantId::single();
    let mut out = String::new();
    let p = l.pending(&t)?;
    let standing = l.standing_with_status(&t, "pending")?;
    let names = l.names_with_status(&t, "pending")?;
    if p.is_empty() && standing.is_empty() && names.is_empty() {
        out.push_str("no pending requests\n");
    }
    for r in p {
        out.push_str(&show_request(l, &r));
    }
    let now = wicket_store::now();
    for s in standing {
        let _ = writeln!(
            out,
            "{}\n  decide: wicket standing show {id}; wicket standing approve {id} [--narrow] [--for zone]; wicket standing deny {id}",
            crate::cmd::standing::line(&s, now),
            id = s.id
        );
    }
    for n in names {
        let _ = writeln!(
            out,
            "{}\n  decide: wicket names show {id}; wicket names approve {id}; wicket names deny {id}",
            crate::cmd::names::line(&n, now),
            id = n.id
        );
    }
    Ok(out)
}

/// A usage error for `wicket approve|deny` (`verb`) on an id another command decides: a standing
/// request (`s-…`, `wicket standing`) or an ask for a public name (`n-…`, `wicket names`).
pub(crate) fn elsewhere(id: &str, verb: &str) -> Option<anyhow::Error> {
    let (what, cmd) = match id {
        i if i.starts_with("s-") => ("a standing request", "standing"),
        i if i.starts_with("n-") => ("an ask for a public name", "names"),
        _ => return None,
    };
    let how = match verb {
        "approve" => format!("wicket {cmd} show {id}, then wicket {cmd} approve {id}"),
        v => format!("wicket {cmd} {v} {id}"),
    };
    Some(wicket_home::exit::usage(format!("{id} is {what}: {how}")))
}

/// `wicket pending --json`: the pending requests (`"kind": "request"`), then the pending standing
/// asks (`"kind": "standing"`), then asks for public names (`"kind": "name"`), as `wicket pending`
/// lists them.
pub(crate) fn pending_json(l: &Ledger) -> Result<serde_json::Value> {
    let t = TenantId::single();
    let mut out: Vec<serde_json::Value> = l
        .pending(&t)?
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "kind": "request", "id": r.id, "run": r.run, "zone": r.zone, "method": r.method, "host": r.host,
                "path": r.path, "prefix": r.scope_prefix, "risk": r.risk, "reason": r.reason, "created_at": r.created_at,
                "attribution": r.attribution,
            })
        })
        .collect();
    for s in l.standing_with_status(&t, "pending")? {
        out.push(serde_json::json!({
            "kind": "standing", "id": s.id, "run": s.run, "zone": s.zone, "principal": s.principal,
            "rule": crate::cmd::standing::rule_json(&s.rule), "reason": s.reason, "created_at": s.created_at,
        }));
    }
    for n in l.names_with_status(&t, "pending")? {
        out.push(serde_json::json!({
            "kind": "name", "id": n.id, "run": n.asked_run, "zone": n.zone, "principal": n.principal, "label": n.label,
            "port": n.port, "service": n.service, "scope": n.scope.as_str(), "reason": n.reason, "created_at": n.created_at,
        }));
    }
    Ok(serde_json::Value::Array(out))
}

/// Revokes grant `id` of `tenant` as `by` (#713: `wicket grant revoke`, and the console's
/// `/api/grants/revoke`): a capacity grant as `wicket capacity revoke` does (audited as a decision),
/// any other audited as `grant.revoked`, with `extra` (`via`). Another tenant's grant is not found,
/// as one that doesn't exist. What was done, in words.
pub(crate) fn revoke_grant(l: &Ledger, tenant: &TenantId, id: &str, by: &str, extra: serde_json::Value) -> Result<String> {
    let g = l.grant(id)?.filter(|g| g.tenant == tenant.0).ok_or_else(|| wicket_home::exit::not_found(format!("no grant {id}")))?;
    if l.capacity_grant(id)?.is_some() {
        grant::revoke_capacity_grant(l, by, tenant, id, extra)?;
        return Ok(format!("revoked capacity grant {id}: nothing more is approved under it"));
    }
    if g.revoked {
        return Err(wicket_home::exit::refused(format!("grant {id} is already revoked")));
    }
    l.revoke_grant(id)?;
    let mut record = serde_json::json!({ "grant": id, "by": by, "node": g.node });
    if let (Some(r), serde_json::Value::Object(x)) = (record.as_object_mut(), extra) {
        r.extend(x);
    }
    l.audit(tenant, None, "grant.revoked", &record)?;
    Ok(match &g.node {
        Some(n) => format!("revoked {id}; its run pushes the revocation to node {n}"),
        None => format!("revoked {id}"),
    })
}

/// Cuts link `id` of `tenant` as `by` (#713: `wicket unlink`, and the console's `/api/links/cut`),
/// audited as `link.cut` with `extra` (`via`). Another tenant's link is not found, as one that
/// doesn't exist; one already closed is refused, as a revoked grant is.
pub(crate) fn cut_link(l: &Ledger, tenant: &TenantId, id: &str, by: &str, extra: serde_json::Value) -> Result<()> {
    let r = l.link(id)?.filter(|r| r.tenant == tenant.0).ok_or_else(|| wicket_home::exit::not_found(format!("no link {id}")))?;
    if !l.close_link(id, by, "cut by the operator")? {
        return Err(wicket_home::exit::refused(format!("{id} is already closed")));
    }
    let mut record = serde_json::json!({ "id": id, "by": by, "from": r.from_run, "to": r.to_run, "port": r.port });
    if let (Some(rec), serde_json::Value::Object(x)) = (record.as_object_mut(), extra) {
        rec.extend(x);
    }
    l.audit(tenant, None, "link.cut", &record)?;
    Ok(())
}

/// `wicket links --json`.
pub(crate) fn links_json(rows: &[wicket_store::LinkRow]) -> serde_json::Value {
    serde_json::Value::Array(rows.iter().map(link_json).collect())
}

/// `wicket grant list --json`.
pub(crate) fn grants_json(rows: &[wicket_store::GrantListing], now: i64) -> serde_json::Value {
    serde_json::Value::Array(rows.iter().map(|r| grant_json(r, now)).collect())
}

/// One link of `wicket links --json`.
fn link_json(r: &wicket_store::LinkRow) -> serde_json::Value {
    serde_json::json!({
        "id": r.id, "status": r.status, "from_run": r.from_run, "to_run": r.to_run, "name": r.name,
        "host": format!("{}.{}", r.name, wicket_core::link::DOMAIN), "port": r.port, "by_run": r.by_run, "basis": r.basis,
        "created_at": r.created_at, "closed_at": r.closed_at, "close_reason": r.close_reason,
    })
}

/// One grant of `wicket grant list --json`. `quota` is set for a quota grant (its resource and
/// amount: micro-USD for money), else null; `uses_left` null is unlimited (and for a quota).
fn grant_json(r: &wicket_store::GrantListing, now: i64) -> serde_json::Value {
    let g = &r.grant;
    let quota = match (g.quota(), g.amount) {
        (Some(res), Some(n)) => serde_json::json!({ "resource": res, "amount": n }),
        _ => serde_json::Value::Null,
    };
    let state = if g.revoked {
        "revoked"
    } else if g.expires_at <= now {
        "expired"
    } else {
        "live"
    };
    serde_json::json!({
        "id": g.id, "state": state, "zone": g.zone, "run": g.run, "method": g.method, "host": g.host, "path": g.path,
        "prefix": g.prefix, "quota": quota, "uses_left": if g.amount.is_some() { None } else { g.uses_left },
        "expires_at": g.expires_at, "node": g.node, "request": g.request_id, "decided_by": r.decided_by,
        "created_at": r.created_at,
    })
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
        format!(
            "ends in {}",
            wicket_core::time::format_duration(std::time::Duration::from_secs(u64::try_from(g.expires_at - now).unwrap_or(0)))
        )
    };
    let node = g.node.as_deref().map(|n| format!(", on node {n}")).unwrap_or_default();
    format!("{}  {what}  {to}{uses}, {state}{node}  by {}", g.id, wicket_agent::clip(&r.decided_by, 80))
}

/// `wicket request`: the requests `wicket pending` lists, named as `grant list` names grants (#654).
#[derive(Subcommand)]
pub enum RequestCmd {
    /// List pending requests: the same as `wicket pending`.
    List {
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
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
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
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
        #[arg(long, default_value = "10m", value_parser = wicket_core::time::duration_arg)]
        ttl: std::time::Duration,
    },
}

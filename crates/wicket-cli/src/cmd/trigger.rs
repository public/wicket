//! `wicket trigger`: triggers (#578), an operator's standing intent ("when this happens, do that"),
//! kept in the ledger and fired by the reconciler's scheduler. This version keeps the ones that
//! tell time (`schedule` and `timer` sources) and their `wake` and `message` actions; a `start`
//! is queued for the engine, which comes later.

use crate::*;
use wicket_control::triggers as tr;

#[derive(Subcommand)]
pub enum TriggerCmd {
    /// Keep a trigger document (YAML) as yours. It fires with your authority, so it asks no one;
    /// it is audited (`trigger.created`). The agent it wakes or messages is resolved now (a live
    /// agent; a `wake` is kept as the agent's id).
    Create {
        #[arg(long)]
        file: PathBuf,
        /// How long it lasts, or `forever`: until removed. Renew it with `wicket trigger renew`.
        #[arg(long, default_value = tr::DEFAULT_LASTS)]
        lasts: String,
    },
    /// Triggers that aren't removed: each with its state, source, action and next firing.
    List,
    /// One trigger (its id, or its name): its document, agent, state, next firing and last firings.
    Show { trigger: String },
    /// Pause a trigger: it fires nothing until resumed (the time it was paused is not caught up).
    Pause { trigger: String },
    /// Resume a paused trigger: only its owner (or root), since it fires as its owner.
    Resume { trigger: String },
    /// Move a trigger's lapse to --lasts from now (or `forever`): only its owner (or root).
    Renew {
        trigger: String,
        #[arg(long, default_value = tr::DEFAULT_LASTS)]
        lasts: String,
    },
    /// Remove a trigger: it fires nothing again.
    Rm { trigger: String },
    /// Show what a trigger would do for an event, its templates filled in, changing nothing. The
    /// event is a JSON object of the source's fields (--event); without one, a time-told event now.
    Fire {
        trigger: String,
        /// A JSON file with the event's fields.
        #[arg(long)]
        event: Option<PathBuf>,
        /// Only show what would happen (the one mode this version has).
        #[arg(long, required = true)]
        dry_run: bool,
    },
}

fn when(t: i64) -> String {
    wicket_core::time::unix_rfc3339(t)
}

fn c(s: &str) -> String {
    wicket_agent::clip(s, 300)
}

/// A trigger's state in words: paused, waiting for approval, lapsed, or active.
fn state(t: &wicket_store::Trigger, now: i64) -> String {
    match (t.status.as_str(), t.approval.as_str(), t.until) {
        ("paused", _, _) => "paused".into(),
        (_, "pending", _) => "waiting for approval".into(),
        (_, _, Some(u)) if u <= now => format!("lapsed {}", when(u)),
        (_, _, Some(u)) => format!("active, until {}", when(u)),
        _ => "active".into(),
    }
}

/// One line for `wicket trigger list`.
pub fn line(t: &wicket_store::Trigger, now: i64) -> String {
    let next = match tr::next_due(t, now) {
        Some(n) if t.live(now) => format!("  next {}", when(n)),
        _ => String::new(),
    };
    format!("{}  {}  {}  {} → {}{next}", t.id, t.name, state(t, now), c(&tr::source_text(&t.spec)), c(&tr::action_text(&t.spec)))
}

/// An agent as a trigger reaches it.
fn agent_text(a: &wicket_store::AgentRow) -> String {
    format!("{} ({}, zone {}), {}", c(&a.name), a.id, c(&a.zone), a.state)
}

/// The whole trigger, with the agent it reaches (as found now, or why not) and its last firings.
pub fn show(
    t: &wicket_store::Trigger,
    agent: Option<&std::result::Result<wicket_store::AgentRow, String>>,
    firings: &[wicket_store::TriggerFiring],
    now: i64,
) -> String {
    let mut out = format!(
        "trigger {} ({}): {}\n  owner:    {} (made by {}, {})\n  source:   {}\n  action:   {}\n",
        t.name,
        t.id,
        state(t, now),
        c(&t.owner),
        c(&t.created_by),
        when(t.created_at),
        c(&tr::source_text(&t.spec)),
        c(&tr::action_text(&t.spec)),
    );
    match agent {
        Some(Ok(a)) => out.push_str(&format!("  agent:    {}\n", agent_text(a))),
        Some(Err(e)) => out.push_str(&format!("  agent:    {}\n", c(e))),
        None => {}
    }
    if !t.spec.filter.is_empty() {
        let f = serde_json::to_string(&t.spec.filter).unwrap_or_default();
        out.push_str(&format!("  filter:   {}\n", c(&f)));
    }
    if let Some(m) = &t.spec.action.message {
        out.push_str(&format!("  message:  {}\n", wicket_agent::clip(&m.body, 1000)));
    }
    let l = &t.spec.limits;
    out.push_str(&format!("  limits:   {} an hour, a queue of {}\n", l.per_hour, l.queue));
    if let (Some(n), true) = (tr::next_due(t, now), t.live(now)) {
        out.push_str(&format!("  next:     {}\n", when(n)));
    }
    if firings.is_empty() {
        out.push_str("  no firings yet\n");
    } else {
        out.push_str("  last firings:\n");
        for f in firings {
            let more = if f.status == "skipped" && f.attempts > 0 { format!(" (+{} more)", f.attempts) } else { String::new() };
            out.push_str(&format!("    {}  {}  {}{more}  {}\n", when(f.created_at), f.id, f.status, c(f.detail.as_deref().unwrap_or(""))));
        }
    }
    out
}

fn lasts(s: &str) -> Result<Option<i64>> {
    match s {
        "forever" => Ok(None),
        d => {
            let d = wicket_core::time::parse_duration(d).context("bad --lasts (a duration such as 30d, or forever)")?;
            Ok(Some(wicket_store::now() + d.as_secs() as i64))
        }
    }
}

/// The trigger `which` names: its id, or its name (the caller's own trigger of that name first,
/// else the only one of that name).
fn find(l: &Ledger, op: &operators::Operator, which: &str) -> Result<wicket_store::Trigger> {
    if let Some(t) = l.trigger(which)?.filter(|t| t.status != "deleted") {
        return Ok(t);
    }
    let named: Vec<wicket_store::Trigger> = l.triggers(&TenantId::single().0, None)?.into_iter().filter(|t| t.name == which).collect();
    if let Some(t) = named.iter().find(|t| t.owner == op.id) {
        return Ok(t.clone());
    }
    match named.len() {
        0 => bail!("no trigger {which}"),
        1 => Ok(named.into_iter().next().expect("one")),
        n => bail!("{n} triggers are named {which} (owners {}): name it by its id", {
            named.iter().map(|t| c(&t.owner)).collect::<Vec<_>>().join(", ")
        }),
    }
}

/// Whether the caller is root: root over wicketd's socket (its peer credentials), or root itself.
fn is_root() -> bool {
    let p = wicket_home::cli_principal();
    p["id"].as_str() == Some("root") && p["via"].as_str() == Some("cli")
}

pub async fn dispatch(c: TriggerCmd) -> Result<()> {
    let l = Ledger::open(&ledger_path())?;
    let now = wicket_store::now();
    let op = operators::Operator::cli(&TenantId::single().0)?;
    match c {
        TriggerCmd::Create { file, lasts: d } => {
            let raw = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let spec: wicket_core::trigger::TriggerSpec =
                wicket_core::yaml::from_str(&raw).with_context(|| format!("{}: not a trigger document", file.display()))?;
            let (id, agent) = tr::create(&l, &op, &spec, lasts(&d)?, "cli")?;
            let t = l.trigger(&id)?.context("the trigger just kept")?;
            println!("kept trigger {} as {id}", t.name);
            println!("{}", line(&t, now));
            if let Some(a) = agent {
                println!("  it reaches agent {}", agent_text(&a));
            }
            Ok(())
        }
        TriggerCmd::List => {
            let rows = l.triggers(&TenantId::single().0, None)?;
            if rows.is_empty() {
                println!("no triggers");
            }
            for t in rows {
                println!("{}", line(&t, now));
            }
            Ok(())
        }
        TriggerCmd::Show { trigger } => {
            let t = find(&l, &op, &trigger)?;
            let a = &t.spec.action;
            let agent = a
                .wake
                .as_deref()
                .or(a.message.as_ref().map(|m| m.to.as_str()))
                .map(|who| tr::target_agent(&l, &t, who).map_err(|e| format!("{e:#}")));
            print!("{}", show(&t, agent.as_ref(), &l.recent_firings(&t.id, tr::SHOWN_FIRINGS)?, now));
            Ok(())
        }
        TriggerCmd::Pause { trigger } => {
            let t = tr::set_status(&l, &op, &find(&l, &op, &trigger)?.id, "paused")?;
            println!("paused trigger {} ({}): it fires nothing until resumed", t.name, t.id);
            Ok(())
        }
        TriggerCmd::Resume { trigger } => {
            let t = tr::resume(&l, &op, is_root(), &find(&l, &op, &trigger)?.id)?;
            println!("resumed trigger {} ({}): it fires from its next due minute", t.name, t.id);
            Ok(())
        }
        TriggerCmd::Renew { trigger, lasts: d } => {
            let until = lasts(&d)?;
            let t = tr::renew(&l, &op, is_root(), &find(&l, &op, &trigger)?.id, until)?;
            match until {
                Some(u) => println!("renewed trigger {} ({}): until {}", t.name, t.id, when(u)),
                None => println!("renewed trigger {} ({}): until removed", t.name, t.id),
            }
            Ok(())
        }
        TriggerCmd::Rm { trigger } => {
            let t = tr::set_status(&l, &op, &find(&l, &op, &trigger)?.id, "deleted")?;
            println!("removed trigger {} ({})", t.name, t.id);
            Ok(())
        }
        TriggerCmd::Fire { trigger, event, dry_run: _ } => {
            let t = find(&l, &op, &trigger)?;
            let fields = match event {
                Some(p) => {
                    let raw = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
                    let v: serde_json::Value = serde_json::from_str(&raw).with_context(|| format!("{}: not JSON", p.display()))?;
                    anyhow::ensure!(v.is_object(), "{}: an event is a JSON object of its fields", p.display());
                    Some(v)
                }
                None => None,
            };
            print!("{}", tr::preview(&l, &t, fields, now)?);
            println!("(dry run: nothing fired)");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a list and a show print can't move the cursor, whatever the document holds.
    #[test]
    fn a_trigger_prints_clean() {
        let spec: wicket_core::trigger::TriggerSpec = wicket_core::yaml::from_str(
            "trigger: t\nsource: { timer: { after: 1h } }\naction: { message: { to: \"capt\\x1b[2Kain\", body: \"hi\\r\" } }\n",
        )
        .unwrap();
        let t = wicket_store::Trigger {
            id: "t-1".into(),
            tenant: "t0".into(),
            owner: "spiffe://w/t/t0/op/unix/alex\x1b]0;x\x07".into(),
            name: "t".into(),
            spec,
            status: "active".into(),
            approval: "none".into(),
            created_at: 0,
            created_by: "unix:alex".into(),
            until: None,
            decided_by: None,
            updated_at: 0,
        };
        let f = wicket_store::TriggerFiring {
            id: "f-1".into(),
            trigger: "t-1".into(),
            event: "e-1".into(),
            status: "failed".into(),
            detail: Some("no agent \x1b[2J".into()),
            run: None,
            attempts: 0,
            created_at: 0,
            updated_at: 0,
        };
        let bad: std::result::Result<wicket_store::AgentRow, String> = Err("no agent \x1b[2J".into());
        for out in [line(&t, 0), show(&t, Some(&bad), &[f], 0)] {
            assert!(!out.contains(['\r', '\x1b', '\x07']), "{out:?}");
        }
        assert!(show(&t, None, &[], 0).contains("next:     1970-01-01T01:00:00Z"));
    }
}

//! `wicket trigger`: triggers (#578), an operator's standing intent ("when this happens, do that"),
//! kept in the ledger and fired by the reconciler's scheduler. This version keeps the ones that
//! tell time (`schedule` and `timer` sources) and their `wake` and `message` actions; a `start`
//! is queued for the engine, which comes later.

use crate::*;
use wicket_control::triggers as tr;

#[derive(Subcommand)]
pub enum TriggerCmd {
    /// Keep a trigger document (YAML) as yours. It fires with your authority, so it asks no one;
    /// it is audited (`trigger.created`).
    Create {
        #[arg(long)]
        file: PathBuf,
        /// How long it lasts, or `forever`: until removed.
        #[arg(long, default_value = "forever")]
        lasts: String,
    },
    /// Triggers that aren't removed: each with its state, source, action and next firing.
    List,
    /// One trigger: its document, state, next firing and last firings.
    Show { id: String },
    /// Pause a trigger: it fires nothing until resumed (events while paused are not caught up).
    Pause { id: String },
    /// Resume a paused trigger.
    Resume { id: String },
    /// Remove a trigger: it fires nothing again.
    Rm { id: String },
    /// Show what a trigger would do for an event, its templates filled in, changing nothing. The
    /// event is a JSON object of the source's fields (--event); without one, a time-told event now.
    Fire {
        id: String,
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

/// The whole trigger, with its last firings.
pub fn show(t: &wicket_store::Trigger, firings: &[wicket_store::TriggerFiring], now: i64) -> String {
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
    if !t.spec.filter.is_empty() {
        let f = serde_json::to_string(&t.spec.filter).unwrap_or_default();
        out.push_str(&format!("  filter:   {}\n", c(&f)));
    }
    if let Some(m) = &t.spec.action.message {
        out.push_str(&format!("  message:  {}\n", wicket_agent::clip(&m.body, 1000)));
    }
    let l = &t.spec.limits;
    out.push_str(&format!("  limits:   {} an hour, {} at once, a queue of {}\n", l.per_hour, l.concurrency, l.queue));
    if let (Some(n), true) = (tr::next_due(t, now), t.live(now)) {
        out.push_str(&format!("  next:     {}\n", when(n)));
    }
    if firings.is_empty() {
        out.push_str("  no firings yet\n");
    } else {
        out.push_str("  last firings:\n");
        for f in firings {
            out.push_str(&format!("    {}  {}  {}  {}\n", when(f.created_at), f.id, f.status, c(f.detail.as_deref().unwrap_or(""))));
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

pub async fn dispatch(c: TriggerCmd) -> Result<()> {
    let l = Ledger::open(&ledger_path())?;
    let now = wicket_store::now();
    match c {
        TriggerCmd::Create { file, lasts: d } => {
            let raw = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let spec: wicket_core::trigger::TriggerSpec =
                wicket_core::yaml::from_str(&raw).with_context(|| format!("{}: not a trigger document", file.display()))?;
            let op = operators::Operator::cli(&TenantId::single().0)?;
            let id = tr::create(&l, &op, &spec, lasts(&d)?, "cli")?;
            let t = l.trigger(&id)?.context("the trigger just kept")?;
            println!("kept trigger {} as {id}", t.name);
            println!("{}", line(&t, now));
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
        TriggerCmd::Show { id } => {
            let t = l.trigger(&id)?.filter(|t| t.status != "deleted").with_context(|| format!("no trigger {id}"))?;
            print!("{}", show(&t, &l.recent_firings(&id, tr::SHOWN_FIRINGS)?, now));
            Ok(())
        }
        TriggerCmd::Pause { id } => {
            let t = tr::set_status(&l, &operator(), &id, "paused")?;
            println!("paused trigger {} ({id}): it fires nothing until resumed", t.name);
            Ok(())
        }
        TriggerCmd::Resume { id } => {
            let t = tr::set_status(&l, &operator(), &id, "active")?;
            println!("resumed trigger {} ({id}): it fires from its next due minute", t.name);
            Ok(())
        }
        TriggerCmd::Rm { id } => {
            let t = tr::set_status(&l, &operator(), &id, "deleted")?;
            println!("removed trigger {} ({id})", t.name);
            Ok(())
        }
        TriggerCmd::Fire { id, event, dry_run: _ } => {
            let t = l.trigger(&id)?.filter(|t| t.status != "deleted").with_context(|| format!("no trigger {id}"))?;
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
        for out in [line(&t, 0), show(&t, &[f], 0)] {
            assert!(!out.contains(['\r', '\x1b', '\x07']), "{out:?}");
        }
        assert!(show(&t, &[], 0).contains("next:     1970-01-01T01:00:00Z"));
    }
}

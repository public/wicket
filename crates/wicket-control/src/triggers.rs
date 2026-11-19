//! Triggers (#578), step 2: operators keep them (`wicket trigger`), and the reconciler's scheduler
//! fires the ones that tell time (`schedule` and `timer` sources).
//!
//! - **Keeping one:** an operator's trigger is its own standing intent and fires with its authority,
//!   so it needs no one else's approval. A trigger that waits for one (an agent's that widens,
//!   step 4's `request_trigger`) is approved by a human ([`approve`]). Pausing, resuming and
//!   deleting are audited, and a paused trigger fires nothing: the kill switch.
//! - **Firing one:** each reconcile pass ([`pass`]) turns the minutes a schedule matched (in its
//!   time zone, at most [`CATCH_UP_SECS`] back) and a timer that came due into events, once each
//!   (the ledger's delivery id is the trigger and the minute), and each admitted event into a
//!   firing, within the trigger's hourly limit.
//!   - `wake` and `message` reach a long-lived agent: the message (its template filled from the
//!     event) is queued as the agent's next turn, and a hibernated agent is woken to read it.
//!   - `start` is queued for the engine (step 5), within the trigger's queue: beyond it, the oldest
//!     waiting firing is dead-lettered.
//!
//! Every firing, skip and failure is audited (`trigger.fired`, `.skipped`, `.failed`).

use crate::grant::Granter;
use crate::operators::Operator;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use wicket_core::trigger::{render, Source, TriggerSpec};
use wicket_core::TenantId;
use wicket_store::{AgentRow, Ledger, Trigger};

/// How far back a pass looks for a schedule's minutes: a reconciler down longer than this skips
/// the minutes it missed (as cron does), rather than firing them all when it is back.
pub const CATCH_UP_SECS: i64 = 15 * 60;

/// How many of a trigger's firings `wicket trigger show` lists.
pub const SHOWN_FIRINGS: i64 = 20;

fn audit(l: &Ledger, kind: &str, body: &Value) -> Result<()> {
    l.audit(&TenantId::single(), None, kind, body)?;
    Ok(())
}

/// What a trigger does, in a few words: for lists and audit records.
pub fn action_text(s: &TriggerSpec) -> String {
    let a = &s.action;
    let mut parts = vec![];
    if let Some(st) = &a.start {
        parts.push(format!("start {} ({})", st.manifest, &st.sha256[..12.min(st.sha256.len())]));
    }
    if let Some(w) = &a.wake {
        parts.push(format!("wake {w}"));
    }
    if let Some(m) = &a.message {
        parts.push(format!("message {}", m.to));
    }
    parts.join(", ")
}

/// Where a trigger's events come from, in a few words.
pub fn source_text(s: &TriggerSpec) -> String {
    match &s.source {
        Source::Schedule { cron, tz } => format!("schedule {cron:?} ({tz})"),
        Source::Timer { at: Some(a), .. } => format!("timer at {a}"),
        Source::Timer { after, .. } => format!("timer after {}", after.as_deref().unwrap_or("?")),
        Source::Webhook { .. } => "webhook".into(),
        Source::Github { repo, events, .. } => format!("github {repo} ({})", events.join(", ")),
        Source::Wicket { kinds } => format!("wicket ({})", kinds.join(", ")),
    }
}

/// When a timer trigger made at `created_at` comes due.
fn timer_due(s: &TriggerSpec, created_at: i64) -> Result<Option<i64>> {
    let Source::Timer { at, after } = &s.source else { return Ok(None) };
    if let Some(a) = at {
        let t = wicket_core::time::parse_rfc3339_weak(a)?;
        let secs = t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        return Ok(Some(secs));
    }
    let d = wicket_core::time::parse_duration(after.as_deref().unwrap_or_default())?;
    Ok(Some(created_at + d.as_secs() as i64))
}

/// Refuses a document the scheduler couldn't keep: a time zone this host doesn't know, a timer
/// already past.
fn check_runnable(s: &TriggerSpec, now: i64) -> Result<()> {
    match &s.source {
        Source::Schedule { tz, .. } => {
            zone(tz)?;
        }
        Source::Timer { .. } if timer_due(s, now)?.is_some_and(|d| d <= now) => bail!("the timer's time has passed"),
        _ => {}
    }
    Ok(())
}

fn zone(tz: &str) -> Result<jiff::tz::TimeZone> {
    if tz == "UTC" {
        return Ok(jiff::tz::TimeZone::UTC);
    }
    jiff::tz::TimeZone::get(tz).with_context(|| format!("time zone {tz:?} isn't in this host's zoneinfo"))
}

/// Keeps `spec` as `op`'s trigger, until `until` if given. `via`: where it was made (`cli`).
pub fn create(l: &Ledger, op: &Operator, spec: &TriggerSpec, until: Option<i64>, via: &str) -> Result<String> {
    spec.check().map_err(anyhow::Error::msg)?;
    let now = wicket_store::now();
    check_runnable(spec, now)?;
    let t = TenantId::single();
    let id = l.create_trigger(&t.0, &op.id, spec, &op.label, false, until)?;
    let record = json!({
        "trigger": id, "name": spec.trigger, "owner": op.id, "by": op.label, "via": via,
        "source": source_text(spec), "action": action_text(spec), "until": until, "approval": "none",
    });
    if let Err(e) = audit(l, "trigger.created", &record) {
        // Not kept without its record.
        let _ = l.set_trigger_status(&id, "deleted");
        return Err(e.context("auditing the trigger"));
    }
    Ok(id)
}

fn get(l: &Ledger, id: &str) -> Result<Trigger> {
    l.trigger(id)?.filter(|t| t.status != "deleted").with_context(|| format!("no trigger {id}"))
}

/// A human's approval of a trigger that waits for one.
pub fn approve(l: &Ledger, by: &Granter, id: &str) -> Result<()> {
    let Granter::Human(o) = by else { bail!("a trigger is approved by a human operator, not {}", by.label()) };
    if matches!(o.authority, crate::operators::Authority::Nothing) {
        bail!("operator {} may decide nothing (operators.yaml)", o.id);
    }
    let t = get(l, id)?;
    l.approve_trigger(id, &o.label)?;
    let record =
        json!({ "trigger": id, "name": t.name, "owner": t.owner, "by": o.label, "granter_identity": o.id, "action": action_text(&t.spec) });
    audit(l, "trigger.approved", &record)
}

/// Pauses (`paused`), resumes (`active`) or deletes (`deleted`) a trigger, audited as
/// `trigger.paused`, `.resumed` or `.deleted`.
pub fn set_status(l: &Ledger, by: &str, id: &str, status: &str) -> Result<Trigger> {
    let t = get(l, id)?;
    let kind = match status {
        "paused" => "trigger.paused",
        "active" => "trigger.resumed",
        "deleted" => "trigger.deleted",
        s => bail!("a trigger is paused, resumed or deleted, not {s}"),
    };
    l.set_trigger_status(id, status)?;
    audit(l, kind, &json!({ "trigger": id, "name": t.name, "owner": t.owner, "by": by }))?;
    Ok(t)
}

/// What a pass did with one trigger's event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fired {
    pub trigger: String,
    pub name: String,
    /// `started`, `queued`, `skipped`, `failed` or `dead`; `due` in a dry run.
    pub status: String,
    pub detail: String,
}

/// The minutes in `(from, to]` a schedule matches, in its zone.
pub fn schedule_minutes(cron: &wicket_core::trigger::Cron, tz: &jiff::tz::TimeZone, from: i64, to: i64) -> Vec<i64> {
    let mut out = vec![];
    let mut m = (from.div_euclid(60) + 1) * 60;
    while m <= to {
        if let Ok(ts) = jiff::Timestamp::from_second(m) {
            let z = ts.to_zoned(tz.clone());
            if cron.matches(z.minute() as u8, z.hour() as u8, z.day() as u8, z.month() as u8, z.weekday().to_sunday_zero_offset() as u8) {
                out.push(m);
            }
        }
        m += 60;
    }
    out
}

/// When a trigger's next event may come, if it tells time: what `wicket trigger list` shows.
pub fn next_due(t: &Trigger, now: i64) -> Option<i64> {
    match &t.spec.source {
        Source::Schedule { cron, tz } => {
            let c = wicket_core::trigger::Cron::parse(cron).ok()?;
            let z = zone(tz).ok()?;
            // A week and a day is every weekday; a month's own days are found within the year.
            [8 * 86400, 366 * 86400].into_iter().find_map(|span| schedule_minutes(&c, &z, now, now + span).into_iter().next())
        }
        Source::Timer { .. } => timer_due(&t.spec, t.created_at).ok().flatten().filter(|d| *d > now),
        _ => None,
    }
}

/// How a pass reaches an agent: wakes it (`agent`, `by`). The reconciler's is
/// [`crate::hibernate::trigger_wake`]; tests record the wake instead.
pub type Waker<'a> = &'a dyn Fn(&str, &str);

/// One scheduler pass at `now`: every live trigger that tells time, for the minutes since
/// `now - CATCH_UP_SECS` (or since it was made). A dry run records and does nothing, and reports
/// what is due.
pub fn pass(l: &Ledger, now: i64, dry_run: bool, wake: Waker<'_>) -> Result<Vec<Fired>> {
    let tenant = TenantId::single();
    let mut out = vec![];
    for t in l.triggers(&tenant.0, None)? {
        if !t.live(now) {
            continue;
        }
        let slots = match &t.spec.source {
            Source::Schedule { cron, tz } => {
                let (Ok(c), Ok(z)) = (wicket_core::trigger::Cron::parse(cron), zone(tz)) else {
                    out.push(Fired {
                        trigger: t.id.clone(),
                        name: t.name.clone(),
                        status: "failed".into(),
                        detail: format!("its schedule {cron:?} in {tz:?} can't be read on this host"),
                    });
                    continue;
                };
                schedule_minutes(&c, &z, (now - CATCH_UP_SECS).max(t.created_at), now)
            }
            Source::Timer { .. } => timer_due(&t.spec, t.created_at)?.filter(|d| *d <= now).into_iter().collect(),
            // Their events come from intake (step 4) and wicket's own records (step 3).
            _ => continue,
        };
        for slot in slots {
            out.extend(fire(l, &t, slot, dry_run, wake)?);
        }
    }
    Ok(out)
}

/// The fields of a time-told event: the trigger's name, and the minute (RFC 3339 and Unix).
fn time_fields(t: &Trigger, slot: i64) -> Value {
    json!({ "trigger": t.name, "at": wicket_core::time::unix_rfc3339(slot), "slot": slot })
}

/// What firing `t` on an event with `fields` (None: a time-told event now) would do, changing
/// nothing: whether its filter admits the event, and the action with its templates filled in.
/// `wicket trigger fire --dry-run`.
pub fn preview(l: &Ledger, t: &Trigger, fields: Option<Value>, now: i64) -> Result<String> {
    let fields = fields.unwrap_or_else(|| time_fields(t, now));
    let mut out = format!("trigger {} ({}): {} → {}\n", t.name, t.id, source_text(&t.spec), action_text(&t.spec));
    if !t.live(now) {
        let why = match (t.status.as_str(), t.approval.as_str()) {
            ("paused", _) => "it is paused".to_string(),
            (_, "pending") => "it waits for a human's approval".to_string(),
            _ => "it has lapsed".to_string(),
        };
        out.push_str(&format!("  not live: {why}, so nothing would fire\n"));
    }
    if !t.spec.admits(&fields) {
        out.push_str("  filter:  the event doesn't pass it: nothing would fire\n");
        return Ok(out);
    }
    out.push_str("  filter:  passes\n");
    let a = &t.spec.action;
    if let Some(st) = &a.start {
        out.push_str(&format!("  start:   {} (sha256 {}), queued for the engine\n", st.manifest, st.sha256));
        if let Some(task) = &st.task {
            out.push_str(&format!("  task:\n{}\n", indent(&render(task, &fields))));
        }
    }
    if let Some(who) = a.wake.as_deref().or(a.message.as_ref().map(|m| m.to.as_str())) {
        match target_agent(l, t, who) {
            Ok(agent) => out.push_str(&format!("  agent:   {} ({}, zone {}), {}\n", agent.name, agent.id, agent.zone, agent.state)),
            Err(e) => out.push_str(&format!("  agent:   {e:#}: the firing would fail\n")),
        }
    }
    if let Some(m) = &a.message {
        out.push_str(&format!("  message:\n{}\n", indent(&message_text(t, &fields, &m.body))));
    }
    Ok(out)
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
}

/// The turn a message action gives its agent: a header naming the trigger, then the body filled
/// from the event.
fn message_text(t: &Trigger, fields: &Value, body: &str) -> String {
    format!("[wicket] Trigger {} fired ({}):\n{}", t.name, fields["at"].as_str().unwrap_or(""), render(body, fields))
}

/// One time-told event for `t` at `slot`: recorded once, and fired if it is new and admitted.
fn fire(l: &Ledger, t: &Trigger, slot: i64, dry_run: bool, wake: Waker<'_>) -> Result<Option<Fired>> {
    let (source, kind) = match t.spec.source {
        Source::Timer { .. } => ("timer", "timer"),
        _ => ("schedule", "tick"),
    };
    let fields = time_fields(t, slot);
    let delivery = format!("{}@{slot}", t.id);
    let done = |status: &str, detail: String| Fired { trigger: t.id.clone(), name: t.name.clone(), status: status.into(), detail };
    if dry_run {
        // Only what a real pass would fire now: a minute already recorded is done.
        if l.trigger_event_known(&t.tenant, source, &delivery)? || !t.spec.admits(&fields) {
            return Ok(None);
        }
        return Ok(Some(done("due", format!("{} at {} (dry run)", action_text(&t.spec), fields["at"].as_str().unwrap_or("")))));
    }
    let raw = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(fields.to_string().as_bytes()));
    let (event, fresh) = l.record_trigger_event(&t.tenant, source, kind, &delivery, &fields, &raw, "wicket")?;
    if !fresh || !t.spec.admits(&fields) {
        return Ok(None);
    }
    let record = |status: &str, detail: &str, firing: &str| {
        json!({
            "trigger": t.id, "name": t.name, "owner": t.owner, "event": event, "firing": firing,
            "source": source, "at": fields["at"], "status": status, "detail": detail,
        })
    };
    // The hourly limit counts what started, or was queued to (dead-lettered since or not).
    let hour_ago = slot - 3600;
    let mut started = 0;
    for st in ["started", "queued", "dead"] {
        started += l.count_firings(&t.id, st, hour_ago)?;
    }
    if started >= t.spec.limits.per_hour as i64 {
        let why = format!("its limit of {} firings an hour is reached", t.spec.limits.per_hour);
        let (f, _) = l.record_firing(&t.id, &event, "skipped", Some(&why))?;
        audit(l, "trigger.skipped", &record("skipped", &why, &f))?;
        return Ok(Some(done("skipped", why)));
    }
    if t.spec.action.start.is_some() {
        let (f, _) = l.record_firing(&t.id, &event, "queued", Some("waiting for the engine to start it"))?;
        audit(l, "trigger.fired", &record("queued", "a run to start, queued", &f))?;
        let mut detail = "queued: a run to start".to_string();
        let queued = l.firings(&t.id, Some("queued"))?;
        let over = queued.len().saturating_sub(t.spec.limits.queue as usize);
        for old in queued.iter().take(over) {
            let why = format!("its queue of {} was full", t.spec.limits.queue);
            l.update_firing(&old.id, "dead", Some(&why), None)?;
            audit(l, "trigger.failed", &record("dead", &why, &old.id))?;
            detail = format!("queued; the oldest waiting firing, {}, is dead-lettered ({why})", old.id);
        }
        return Ok(Some(done("queued", detail)));
    }
    let (f, _) = l.record_firing(&t.id, &event, "queued", None)?;
    match reach(l, t, &fields, wake) {
        Ok(detail) => {
            l.update_firing(&f, "started", Some(&detail), None)?;
            audit(l, "trigger.fired", &record("started", &detail, &f))?;
            Ok(Some(done("started", detail)))
        }
        Err(e) => {
            let why = format!("{e:#}");
            l.update_firing(&f, "failed", Some(&why), None)?;
            audit(l, "trigger.failed", &record("failed", &why, &f))?;
            Ok(Some(done("failed", why)))
        }
    }
}

/// The agent a trigger names: `self` (its owner, if an agent), a principal, an agent's id, or a
/// long-lived agent's name (one of that name).
pub fn target_agent(l: &Ledger, t: &Trigger, who: &str) -> Result<AgentRow> {
    let principal = match who {
        "self" => Some(t.owner.as_str()),
        p if p.starts_with("spiffe://") => Some(p),
        _ => None,
    };
    let agents = l.agents(&t.tenant)?;
    if let Some(p) = principal {
        let Some(wicket_identity::Principal::Agent { zone, agent, .. }) = wicket_identity::Principal::parse(p) else {
            bail!("{p} is not an agent's principal (an operator's trigger names the agent it wakes)");
        };
        return agents.into_iter().find(|a| a.zone == zone && a.name == agent).with_context(|| format!("no long-lived agent {p}"));
    }
    if wicket_store::valid_agent_id(who) {
        return l.agent(who)?.with_context(|| format!("no agent {who}"));
    }
    let mut named: Vec<AgentRow> = agents.into_iter().filter(|a| a.name == who).collect();
    match named.len() {
        0 => bail!("no long-lived agent named {who}"),
        1 => Ok(named.remove(0)),
        n => bail!("{n} agents are named {who} (in zones {}): name it by its principal", {
            named.iter().map(|a| a.zone.as_str()).collect::<Vec<_>>().join(", ")
        }),
    }
}

/// Wakes or messages the agent `t` names: the message, filled from the event, is its next turn;
/// a hibernated agent is woken for it. What happened.
fn reach(l: &Ledger, t: &Trigger, fields: &Value, wake: Waker<'_>) -> Result<String> {
    let a = &t.spec.action;
    let who = a.wake.as_deref().or(a.message.as_ref().map(|m| m.to.as_str())).context("the trigger wakes or messages no one")?;
    let agent = target_agent(l, t, who)?;
    let text = a.message.as_ref().map(|m| message_text(t, fields, &m.body));
    let label = format!("trigger:{}", t.name);
    match agent.state.as_str() {
        "active" | "waking" | "hibernating" => match &text {
            Some(text) => {
                // To the agent's id while it is being woken or put to sleep: the wake moves it on.
                let to = if agent.state == "active" { &agent.run } else { &agent.id };
                l.add_prompt(to, text, &label, &t.owner)?;
                Ok(format!("messaged agent {} ({})", agent.id, agent.state))
            }
            None => Ok(format!("agent {} is already {}", agent.id, agent.state)),
        },
        "hibernated" if agent.restorable => {
            if let Some(why) = crate::hibernate::exhausted(&agent) {
                bail!("agent {} can't be woken: {why}", agent.id);
            }
            if let Some(text) = &text {
                l.add_prompt(&agent.id, text, &label, &t.owner)?;
            }
            wake(&agent.id, &format!("trigger {}", t.name));
            Ok(format!("woke agent {}{}", agent.id, if text.is_some() { " with its message" } else { "" }))
        }
        s => bail!("agent {} is {s}: it can't be woken", agent.id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn spec(y: &str) -> TriggerSpec {
        wicket_core::yaml::from_str(y).unwrap()
    }

    /// A morning schedule's minutes, in its zone: 07:00 London on weekdays, which is 07:00 UTC in
    /// November and 06:00 UTC in June.
    #[test]
    fn a_schedule_tells_its_minutes_in_its_zone() {
        let c = wicket_core::trigger::Cron::parse("0 7 * * 1-5").unwrap();
        let utc = |s: &str| jiff::Timestamp::from_str_compat(s);
        let london = zone("Europe/London").unwrap();
        // Thu 2026-11-19 and Fri 20; then Mon 23 (the window ends at Tue 24 00:00).
        let from = utc("2026-11-19T00:00:00Z");
        let got = schedule_minutes(&c, &london, from, from + 5 * 86400);
        let want: Vec<i64> = ["2026-11-19T07:00:00Z", "2026-11-20T07:00:00Z", "2026-11-23T07:00:00Z"].iter().map(|s| utc(s)).collect();
        assert_eq!(got, want);
        let june = utc("2026-06-17T00:00:00Z");
        assert_eq!(schedule_minutes(&c, &london, june, june + 86400), [utc("2026-06-17T06:00:00Z")]);
        assert!(zone("Mars/Olympus").is_err());
    }

    trait FromStrCompat {
        fn from_str_compat(s: &str) -> i64;
    }
    impl FromStrCompat for jiff::Timestamp {
        fn from_str_compat(s: &str) -> i64 {
            s.parse::<jiff::Timestamp>().unwrap().as_second()
        }
    }

    fn operator() -> Operator {
        Operator { id: "spiffe://w/t/t0/op/unix/alex".into(), label: "unix:alex".into(), authority: crate::operators::Authority::Anything }
    }

    /// #578 step 2: an every-minute schedule fires once per minute it matched (a second pass over
    /// the same minutes is the same events), within its hourly limit; paused, it fires nothing.
    #[test]
    fn a_schedule_fires_once_a_minute_within_its_limit() {
        let l = Ledger::open_in_memory().unwrap();
        let s = spec("trigger: tick\nsource: { schedule: { cron: '* * * * *' } }\naction: { wake: nobody }\nlimits: { per_hour: 2 }\n");
        let id = create(&l, &operator(), &s, None, "test").unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        let woke = RefCell::new(vec![]);
        let w = |a: &str, b: &str| woke.borrow_mut().push((a.to_string(), b.to_string()));
        let at = t.created_at + 5 * 60;
        let first = pass(&l, at, false, &w).unwrap();
        let st: Vec<&str> = first.iter().map(|f| f.status.as_str()).collect();
        // No agent of that name: each fails; failed ones don't count against the hour.
        assert_eq!(st, ["failed"; 5], "{first:?}");
        assert!(first[0].detail.contains("no long-lived agent named nobody"));
        assert!(pass(&l, at, false, &w).unwrap().is_empty(), "the same minutes are the same events");
        assert!(pass(&l, at, true, &w).unwrap().is_empty(), "a dry run reports only minutes not yet recorded");
        let due = pass(&l, at + 60, true, &w).unwrap();
        assert_eq!(due.iter().map(|f| f.status.as_str()).collect::<Vec<_>>(), ["due"], "{due:?}");
        assert_eq!(pass(&l, at + 60, true, &w).unwrap().len(), 1, "a dry run records nothing");
        set_status(&l, "unix:alex", &id, "paused").unwrap();
        assert!(pass(&l, at + 120, false, &w).unwrap().is_empty(), "paused: nothing fires");
        assert!(woke.borrow().is_empty());
        let kinds: Vec<String> = l.audit_tail(20).unwrap().into_iter().map(|r| r.2).collect();
        assert!(kinds.contains(&"trigger.created".to_string()) && kinds.contains(&"trigger.paused".to_string()));
        assert_eq!(kinds.iter().filter(|k| *k == "trigger.failed").count(), 5);
    }

    /// #578's first "done when": a morning schedule wakes a hibernated agent with its message as
    /// the next turn, recorded as woken by the trigger; an awake agent gets the message in its run.
    /// The dry run shows the same, filled in, and changes nothing.
    #[test]
    fn a_schedule_wakes_an_agent_with_its_message() {
        let mut l = Ledger::open_in_memory().unwrap();
        let agent = wicket_store::new_agent_id();
        l.create_agent(&wicket_store::NewAgent {
            id: &agent,
            tenant: "t0",
            zone: "rel",
            name: "captain",
            run: "run_a",
            session_id: "s",
            manifest: "m",
            image: "i",
            workspace: None,
            claim_until: 0,
        })
        .unwrap();
        assert!(l.set_agent_state(&agent, 1, "hibernated", None).unwrap());
        let s = spec(
            "trigger: morning\nsource: { schedule: { cron: '* * * * *' } }\n\
             action: { wake: captain, message: { to: captain, body: 'Triage {{ event.trigger }} at {{ event.at }}' } }\n",
        );
        let id = create(&l, &operator(), &s, None, "test").unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        let shown = preview(&l, &t, None, t.created_at).unwrap();
        assert!(shown.contains("filter:  passes") && shown.contains("captain") && shown.contains("Triage morning at 20"), "{shown}");
        let woke = RefCell::new(vec![]);
        let w = |a: &str, b: &str| woke.borrow_mut().push((a.to_string(), b.to_string()));
        let at = (t.created_at.div_euclid(60) + 1) * 60;
        let got = pass(&l, at, false, &w).unwrap();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].status, "started", "{got:?}");
        assert_eq!(*woke.borrow(), [(agent.clone(), "trigger morning".to_string())]);
        let prompts = l.take_prompts(&agent).unwrap();
        assert_eq!(prompts.len(), 1);
        assert!(prompts[0].text.starts_with("[wicket] Trigger morning fired") && prompts[0].text.contains("Triage morning at "));
        // Awake: the message goes to its run, and nothing is woken.
        assert!(l.set_agent_state(&agent, 1, "active", None).unwrap());
        let got = pass(&l, at + 60, false, &w).unwrap();
        assert!(got[0].detail.contains("messaged agent"), "{got:?}");
        assert_eq!(l.take_prompts("run_a").unwrap().len(), 1);
        assert_eq!(woke.borrow().len(), 1);
        // A filter that doesn't pass: the preview says so.
        let quiet = spec("trigger: quiet\nsource: { schedule: { cron: '* * * * *' } }\nfilter: { trigger: other }\naction: { wake: captain }\n");
        let q = l.trigger(&create(&l, &operator(), &quiet, None, "test").unwrap()).unwrap().unwrap();
        assert!(preview(&l, &q, None, q.created_at).unwrap().contains("doesn't pass"));
    }

    /// `start` is queued for the engine, within the hourly limit and the queue: the oldest beyond
    /// the queue is dead-lettered.
    #[test]
    fn a_start_is_queued_within_its_limits() {
        let l = Ledger::open_in_memory().unwrap();
        let s = spec(&format!(
            "trigger: build\nsource: {{ schedule: {{ cron: '* * * * *' }} }}\naction: {{ start: {{ manifest: b.yaml, sha256: {} }} }}\nlimits: {{ per_hour: 3, queue: 2 }}\n",
            "a".repeat(64)
        ));
        let id = create(&l, &operator(), &s, None, "test").unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        let got = pass(&l, t.created_at + 4 * 60, false, &|_: &str, _: &str| {}).unwrap();
        let st: Vec<&str> = got.iter().map(|f| f.status.as_str()).collect();
        assert_eq!(st, ["queued", "queued", "queued", "skipped"], "{got:?}");
        assert!(got[2].detail.contains("dead-lettered"), "{got:?}");
        assert!(got[3].detail.contains("3 firings an hour"));
        assert_eq!(l.firings(&id, Some("dead")).unwrap().len(), 1);
        assert_eq!(l.firings(&id, Some("queued")).unwrap().len(), 2);
    }

    /// A timer fires once, when it comes due; one already past isn't kept.
    #[test]
    fn a_timer_fires_once_when_due() {
        let l = Ledger::open_in_memory().unwrap();
        let id = create(&l, &operator(), &spec("trigger: later\nsource: { timer: { after: 2h } }\naction: { wake: nobody }\n"), None, "t")
            .unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        let none = |_: &str, _: &str| {};
        assert!(pass(&l, t.created_at + 3600, false, &none).unwrap().is_empty());
        assert_eq!(next_due(&t, t.created_at), Some(t.created_at + 7200));
        assert_eq!(pass(&l, t.created_at + 7300, false, &none).unwrap().len(), 1);
        assert!(pass(&l, t.created_at + 9000, false, &none).unwrap().is_empty(), "once");
        let past = spec("trigger: past\nsource: { timer: { at: '2020-01-01T00:00:00Z' } }\naction: { wake: nobody }\n");
        assert!(create(&l, &operator(), &past, None, "t").unwrap_err().to_string().contains("passed"));
        let mars = spec("trigger: mars\nsource: { schedule: { cron: '0 7 * * *', tz: Mars/Olympus } }\naction: { wake: nobody }\n");
        assert!(create(&l, &operator(), &mars, None, "t").is_err());
    }

    /// Only a human approves, and only a trigger that waits for it.
    #[test]
    fn a_trigger_is_approved_by_a_human() {
        let l = Ledger::open_in_memory().unwrap();
        let s = spec("trigger: t\nsource: { timer: { after: 1h } }\naction: { wake: self }\n");
        let id = l.create_trigger("t0", "spiffe://w/t/t0/z/z/a/a", &s, "agent:run_x", true, None).unwrap();
        assert!(!l.trigger(&id).unwrap().unwrap().live(wicket_store::now()));
        let ask = wicket_store::CapacityAsk { node: "n".into(), plan: "p".into(), region: "r".into(), hourly: 0, worst: 0 };
        let agent = Granter::Capacity { grant: "g".into(), ask };
        assert!(approve(&l, &agent, &id).unwrap_err().to_string().contains("human"));
        approve(&l, &Granter::Human(operator()), &id).unwrap();
        assert!(l.trigger(&id).unwrap().unwrap().live(wicket_store::now()));
        assert!(approve(&l, &Granter::Human(operator()), &id).is_err(), "once");
    }
}

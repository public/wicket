//! Triggers (#578), step 2: operators keep them (`wicket trigger`), and the reconciler's scheduler
//! fires the ones that tell time (`schedule` and `timer` sources).
//!
//! - **Keeping one:** an operator's trigger is its own standing intent and fires with its authority,
//!   so it needs no one else's approval. The agent it wakes or messages is resolved when it is made
//!   (a live agent of this tenant; `wake` is pinned to the agent's id), so a namesake made later
//!   isn't reached. A trigger lasts [`DEFAULT_LASTS`] unless asked otherwise, and is renewed by its
//!   owner. A trigger that waits for an approval (an agent's that widens, step 6's
//!   `request_trigger`) is approved by a human ([`approve`]). Pausing, resuming, renewing and
//!   deleting are audited, and a paused trigger fires nothing: the kill switch. Only its owner (or
//!   root) resumes or renews one, since it fires as its owner.
//! - **Firing one:** each reconcile pass ([`pass`]) looks at a schedule's minutes since the last one
//!   it recorded, since it was last changed (made, approved, resumed), and at most
//!   [`CATCH_UP_SECS`] back, and fires once for the newest, saying how many it missed. A timer
//!   fires once when it comes due; one that came due while paused, or longer ago than
//!   [`CATCH_UP_SECS`], is recorded as skipped. Before a firing, the owner's authority is checked
//!   again ([`OwnerCheck`]): an owner who may no longer do what keeping it needed has it paused.
//!   - `wake` and `message` reach a long-lived agent: the message (its template filled from the
//!     event) is queued as the agent's next turn, through its current run (which wakes it again if
//!     it is hibernating), and a hibernated agent is woken to read it.
//!   - `start` is queued for the engine (step 5), within the trigger's queue: beyond it, the oldest
//!     waiting firing is dead-lettered.
//!   - The event, the firing, the message and its audit record are one ledger transaction; the wake
//!     comes after it commits.
//!   - Every firing counts toward the trigger's hourly limit, failed ones too. Over it, the hour's
//!     first skip is recorded and audited and the rest are counted on it. After
//!     [`FAILURES_TO_PAUSE`] failures in a row the trigger is paused.
//!
//! Every firing, skip, failure and pause is audited (`trigger.fired`, `.skipped`, `.failed`,
//! `.paused`).

use crate::grant::Granter;
use crate::operators::{Authority, Operator};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use wicket_core::trigger::{render, Source, TriggerSpec};
use wicket_core::TenantId;
use wicket_store::{AgentRow, Ledger, Trigger};

/// How far back a pass looks for a schedule's minutes and a timer's time: a reconciler down
/// longer than this skips what it missed (as cron does).
pub const CATCH_UP_SECS: i64 = 15 * 60;

/// How many of a trigger's firings `wicket trigger show` lists.
pub const SHOWN_FIRINGS: i64 = 20;

/// After this many firings of a trigger fail in a row, it is paused.
pub const FAILURES_TO_PAUSE: usize = 5;

/// How long an operator's trigger lasts unless asked otherwise (`--lasts`).
pub const DEFAULT_LASTS: &str = "30d";

/// The states of an agent a trigger may reach (not ended or failed ones).
const LIVE_AGENT: &[&str] = &["active", "waking", "hibernating", "hibernated"];

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
    match (&a.wake, &a.message) {
        (Some(w), Some(_)) => parts.push(format!("wake {w} with a message")),
        (Some(w), None) => parts.push(format!("wake {w}")),
        (None, Some(m)) => parts.push(format!("message {}", m.to)),
        (None, None) => {}
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

/// Refuses a document this version couldn't keep: a source it doesn't fire yet, a time zone this
/// host doesn't know, a timer already past, or a limit it doesn't enforce yet.
fn check_runnable(s: &TriggerSpec, now: i64) -> Result<()> {
    match &s.source {
        Source::Schedule { tz, .. } => {
            zone(tz)?;
        }
        Source::Timer { .. } if timer_due(s, now)?.is_some_and(|d| d <= now) => bail!("the timer's time has passed"),
        Source::Timer { .. } => {}
        _ => bail!("this version fires schedules and timers only: {} comes later (#578)", source_text(s)),
    }
    if s.limits.concurrency != 1 {
        bail!("limits.concurrency isn't enforced yet (#578): leave it out");
    }
    if s.limits.debounce.is_some() {
        bail!("limits.debounce isn't enforced yet (#578): leave it out");
    }
    Ok(())
}

fn zone(tz: &str) -> Result<jiff::tz::TimeZone> {
    if tz == "UTC" {
        return Ok(jiff::tz::TimeZone::UTC);
    }
    jiff::tz::TimeZone::get(tz).with_context(|| format!("time zone {tz:?} isn't in this host's zoneinfo"))
}

/// Whether `t`'s owner may still keep it, as `operators.yaml` says: an operator of its tenant and
/// this installation's trust domain, whose authority isn't `nothing`. (wicketd's policy is the
/// CLI's to add to it: the reconciler's [`OwnerCheck`].)
pub fn operator_may(t: &Trigger) -> std::result::Result<(), String> {
    let Some(wicket_identity::Principal::Operator { tenant, via, name, .. }) = wicket_identity::Principal::parse(&t.owner) else {
        return Err(format!("{} is not an operator's principal", t.owner));
    };
    if tenant != t.tenant {
        return Err(format!("{} is not an operator of tenant {}", t.owner, t.tenant));
    }
    let policy = crate::operators::Policy::load(&crate::operators::policy_path()).map_err(|e| format!("{e:#}"))?;
    let o = Operator::new(&t.tenant, &via, &name, String::new(), &policy);
    if o.id != t.owner {
        return Err(format!("{} is not this installation's operator (its trust domain is now that of {})", t.owner, o.id));
    }
    if matches!(o.authority, Authority::Nothing) {
        return Err(format!("operator {} may decide nothing (operators.yaml)", t.owner));
    }
    Ok(())
}

/// Whether a trigger's owner may still have it fire: checked before every firing. The reconciler's
/// adds wicketd's policy (the run class keeping one needed) to [`operator_may`].
pub type OwnerCheck<'a> = &'a dyn Fn(&Trigger) -> std::result::Result<(), String>;

/// The live agent `who` names in `tenant`: a principal (`spiffe://…`, the newest live agent of
/// that zone and name), an agent's id, or a long-lived agent's name (the only live one of that
/// name). Ended and failed agents aren't reached.
pub fn find_agent(l: &Ledger, tenant: &str, who: &str) -> Result<AgentRow> {
    let live = |a: &AgentRow| a.tenant == tenant && LIVE_AGENT.contains(&a.state.as_str());
    if who.starts_with("spiffe://") {
        let Some(wicket_identity::Principal::Agent { tenant: pt, zone, agent, .. }) = wicket_identity::Principal::parse(who) else {
            bail!("{who} is not an agent's principal");
        };
        if pt != tenant {
            bail!("{who} is not of tenant {tenant}");
        }
        let mut named: Vec<AgentRow> = l.agents(tenant)?.into_iter().filter(|a| live(a) && a.zone == zone && a.name == agent).collect();
        named.sort_by_key(|a| a.created_at);
        return named.pop().with_context(|| format!("no live long-lived agent {who}"));
    }
    if wicket_store::valid_agent_id(who) {
        let a = l.agent(who)?.filter(|a| a.tenant == tenant).with_context(|| format!("no agent {who}"))?;
        return Ok(a);
    }
    let mut named: Vec<AgentRow> = l.agents(tenant)?.into_iter().filter(|a| live(a) && a.name == who).collect();
    match named.len() {
        0 => bail!("no live long-lived agent named {who}"),
        1 => Ok(named.remove(0)),
        n => bail!("{n} live agents are named {who} (in zones {}): name it by its id (wicket agents)", {
            named.iter().map(|a| a.zone.as_str()).collect::<Vec<_>>().join(", ")
        }),
    }
}

/// The agent a trigger names: `self` (its owner, if an agent), or as [`find_agent`].
pub fn target_agent(l: &Ledger, t: &Trigger, who: &str) -> Result<AgentRow> {
    find_agent(l, &t.tenant, if who == "self" { &t.owner } else { who })
}

/// Resolves the agent `spec` wakes or messages, for `owner`, and pins a `wake` to its id. An
/// operator's trigger names its agent: `self` is an agent's own trigger's.
fn pin_target(l: &Ledger, tenant: &str, owner: &str, spec: &mut TriggerSpec) -> Result<Option<AgentRow>> {
    let a = &mut spec.action;
    let Some(who) = a.wake.clone().or(a.message.as_ref().map(|m| m.to.clone())) else { return Ok(None) };
    if who == "self" && matches!(wicket_identity::Principal::parse(owner), Some(wicket_identity::Principal::Operator { .. })) {
        bail!("an operator's trigger names the agent it wakes or messages: `self` is for an agent's own trigger");
    }
    let agent = find_agent(l, tenant, if who == "self" { owner } else { &who })?;
    if a.wake.is_some() {
        a.wake = Some(agent.id.clone());
    }
    Ok(Some(agent))
}

/// Keeps `spec` as `op`'s trigger, until `until` if given. `via`: where it was made (`cli`). The
/// trigger's id, and the agent it reaches (resolved now; a `wake` is kept as the agent's id).
pub fn create(l: &Ledger, op: &Operator, spec: &TriggerSpec, until: Option<i64>, via: &str) -> Result<(String, Option<AgentRow>)> {
    spec.check().map_err(anyhow::Error::msg)?;
    let now = wicket_store::now();
    check_runnable(spec, now)?;
    let t = TenantId::single();
    if l.triggers(&t.0, Some(&op.id))?.len() >= wicket_store::MAX_TRIGGERS_PER_OWNER {
        bail!("{} already keeps {} triggers, the most one owner may: remove one first", op.id, wicket_store::MAX_TRIGGERS_PER_OWNER);
    }
    let mut spec = spec.clone();
    let agent = pin_target(l, &t.0, &op.id, &mut spec)?;
    let id = l.create_trigger(&t.0, &op.id, &spec, &op.label, false, until)?;
    let record = json!({
        "trigger": id, "name": spec.trigger, "owner": op.id, "by": op.label, "via": via,
        "source": source_text(&spec), "action": action_text(&spec), "until": until, "approval": "none",
        "agent": agent.as_ref().map(|a| json!({ "id": a.id, "name": a.name, "zone": a.zone })),
    });
    if let Err(e) = audit(l, "trigger.created", &record) {
        // Not kept without its record.
        let _ = l.set_trigger_status(&id, "deleted");
        return Err(e.context("auditing the trigger"));
    }
    Ok((id, agent))
}

fn get(l: &Ledger, id: &str) -> Result<Trigger> {
    l.trigger(id)?.filter(|t| t.status != "deleted").with_context(|| format!("no trigger {id}"))
}

/// A human's approval of a trigger that waits for one.
pub fn approve(l: &Ledger, by: &Granter, id: &str) -> Result<()> {
    let Granter::Human(o) = by else { bail!("a trigger is approved by a human operator, not {}", by.label()) };
    if matches!(o.authority, Authority::Nothing) {
        bail!("operator {} may decide nothing (operators.yaml)", o.id);
    }
    let t = get(l, id)?;
    l.approve_trigger(id, &o.label)?;
    let record =
        json!({ "trigger": id, "name": t.name, "owner": t.owner, "by": o.label, "granter_identity": o.id, "action": action_text(&t.spec) });
    audit(l, "trigger.approved", &record)
}

/// Pauses (`paused`) or deletes (`deleted`) a trigger, by operator `by`: audited as
/// `trigger.paused` or `.deleted`. Anyone who may revoke may, since it only narrows.
pub fn set_status(l: &Ledger, by: &Operator, id: &str, status: &str) -> Result<Trigger> {
    let t = get(l, id)?;
    let kind = match status {
        "paused" => "trigger.paused",
        "deleted" => "trigger.deleted",
        s => bail!("a trigger is paused or deleted here, not {s}"),
    };
    l.set_trigger_status(id, status)?;
    audit(l, kind, &json!({ "trigger": id, "name": t.name, "owner": t.owner, "by": by.label, "principal": by.id }))?;
    Ok(t)
}

/// Refuses `by` acting on `t` as its owner unless it is, or is root: what resuming and renewing
/// need, since the trigger fires as its owner.
fn owner_or_root(t: &Trigger, by: &Operator, root: bool) -> Result<()> {
    if t.owner != by.id && !root {
        bail!("trigger {} fires as its owner {}: only they (or root) may resume or renew it", t.id, t.owner);
    }
    Ok(())
}

/// Resumes a paused trigger, by its owner (or root, `root`): audited as `trigger.resumed`. It
/// fires from the next due minute after now, not for the time it was paused.
pub fn resume(l: &Ledger, by: &Operator, root: bool, id: &str) -> Result<Trigger> {
    let t = get(l, id)?;
    owner_or_root(&t, by, root)?;
    l.set_trigger_status(id, "active")?;
    audit(l, "trigger.resumed", &json!({ "trigger": id, "name": t.name, "owner": t.owner, "by": by.label, "principal": by.id }))?;
    Ok(t)
}

/// Moves a trigger's lapse to `until` (None: until removed), by its owner (or root): audited as
/// `trigger.renewed`.
pub fn renew(l: &Ledger, by: &Operator, root: bool, id: &str, until: Option<i64>) -> Result<Trigger> {
    let t = get(l, id)?;
    owner_or_root(&t, by, root)?;
    l.renew_trigger(id, until)?;
    let record = json!({ "trigger": id, "name": t.name, "owner": t.owner, "by": by.label, "principal": by.id, "until": until });
    audit(l, "trigger.renewed", &record)?;
    Ok(t)
}

/// Pauses `t` on wicket's own account, saying why: audited as `trigger.paused` by `wicket`.
fn pause_for(l: &Ledger, t: &Trigger, why: &str) -> Result<Fired> {
    l.set_trigger_status(&t.id, "paused")?;
    audit(l, "trigger.paused", &json!({ "trigger": t.id, "name": t.name, "owner": t.owner, "by": "wicket", "why": why }))?;
    Ok(Fired { trigger: t.id.clone(), name: t.name.clone(), status: "paused".into(), detail: format!("paused: {why}") })
}

/// What a pass did with one trigger's event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fired {
    pub trigger: String,
    pub name: String,
    /// `started`, `queued`, `skipped`, `failed`, `dead` or `paused`; `due` in a dry run.
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

/// What a time-told trigger has due at a pass.
#[derive(Debug, PartialEq, Eq)]
enum Due {
    Nothing,
    /// Fire for this minute, saying how many earlier ones were missed.
    Fire {
        slot: i64,
        missed: usize,
    },
    /// A timer that came due while paused or longer ago than [`CATCH_UP_SECS`]: recorded as
    /// skipped, once.
    Stale {
        slot: i64,
    },
}

/// What `t` has due at `now`: a schedule's minutes after its floor (its last recorded minute,
/// when it was last changed, and `now - CATCH_UP_SECS`, whichever is latest), or its timer.
fn due(l: &Ledger, t: &Trigger, now: i64) -> Result<Due> {
    let last = l.last_trigger_slot(&t.tenant, &t.id)?;
    let floor = (now - CATCH_UP_SECS).max(t.updated_at);
    match &t.spec.source {
        Source::Schedule { cron, tz } => {
            let c = wicket_core::trigger::Cron::parse(cron).map_err(anyhow::Error::msg)?;
            let z = zone(tz)?;
            let slots = schedule_minutes(&c, &z, floor.max(last.unwrap_or(i64::MIN)), now);
            Ok(match slots.last() {
                Some(s) => Due::Fire { slot: *s, missed: slots.len() - 1 },
                None => Due::Nothing,
            })
        }
        Source::Timer { .. } => match timer_due(&t.spec, t.created_at)? {
            Some(d) if d <= now && last.is_none() => Ok(if d > floor { Due::Fire { slot: d, missed: 0 } } else { Due::Stale { slot: d } }),
            _ => Ok(Due::Nothing),
        },
        _ => Ok(Due::Nothing),
    }
}

/// One scheduler pass at `now`: every live trigger that tells time. A trigger whose owner may no
/// longer have it fire (`owner`) is paused instead. A dry run records and does nothing, and
/// reports what is due. One trigger's failure is its result, not the pass's.
pub fn pass(l: &Ledger, now: i64, dry_run: bool, wake: Waker<'_>, owner: OwnerCheck<'_>) -> Result<Vec<Fired>> {
    let tenant = TenantId::single();
    let mut out = vec![];
    for t in l.triggers(&tenant.0, None)? {
        if !t.live(now) {
            continue;
        }
        match one(l, &t, now, dry_run, wake, owner) {
            Ok(f) => out.extend(f),
            Err(e) => out.push(Fired { trigger: t.id.clone(), name: t.name.clone(), status: "failed".into(), detail: format!("{e:#}") }),
        }
    }
    Ok(out)
}

fn one(l: &Ledger, t: &Trigger, now: i64, dry_run: bool, wake: Waker<'_>, owner: OwnerCheck<'_>) -> Result<Option<Fired>> {
    let d = due(l, t, now)?;
    if d == Due::Nothing {
        return Ok(None);
    }
    let done = |status: &str, detail: String| Fired { trigger: t.id.clone(), name: t.name.clone(), status: status.into(), detail };
    if dry_run {
        return Ok(Some(match d {
            Due::Fire { slot, missed } => done(
                "due",
                format!(
                    "{} at {}{} (dry run)",
                    action_text(&t.spec),
                    wicket_core::time::unix_rfc3339(slot),
                    if missed > 0 { format!(", {missed} earlier missed") } else { String::new() }
                ),
            ),
            _ => done("due", "its timer's time passed: skipped (dry run)".into()),
        }));
    }
    if let Err(why) = owner(t) {
        return pause_for(l, t, &format!("its owner may no longer have it fire: {why}")).map(Some);
    }
    match d {
        Due::Fire { slot, missed } => fire(l, t, slot, missed, wake),
        Due::Stale { slot } => stale(l, t, slot),
        Due::Nothing => Ok(None),
    }
}

/// The fields of a time-told event: the trigger's name, the minute (RFC 3339 and Unix), and how
/// many earlier minutes it stands for (missed while the reconciler was down).
fn time_fields(t: &Trigger, slot: i64, missed: usize) -> Value {
    json!({ "trigger": t.name, "at": wicket_core::time::unix_rfc3339(slot), "slot": slot, "missed": missed })
}

fn source_kind(t: &Trigger) -> (&'static str, &'static str) {
    match t.spec.source {
        Source::Timer { .. } => ("timer", "timer"),
        _ => ("schedule", "tick"),
    }
}

/// What firing `t` on an event with `fields` (None: a time-told event now) would do, changing
/// nothing: whether its filter admits the event, and the action with its templates filled in.
/// `wicket trigger fire --dry-run`.
pub fn preview(l: &Ledger, t: &Trigger, fields: Option<Value>, now: i64) -> Result<String> {
    let fields = fields.unwrap_or_else(|| time_fields(t, now, 0));
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

/// The turn a message action gives its agent: a header naming the trigger (and the minutes it
/// missed, if any), then the body filled from the event.
fn message_text(t: &Trigger, fields: &Value, body: &str) -> String {
    let missed = match fields["missed"].as_u64() {
        Some(n) if n > 0 => format!(", standing for {n} earlier time(s) missed"),
        _ => String::new(),
    };
    format!("[wicket] Trigger {} fired ({}{missed}):\n{}", t.name, fields["at"].as_str().unwrap_or(""), render(body, fields))
}

/// Fires `t` for `slot`: its event, firing, message and audit record in one transaction, then the
/// wake. A trigger whose last [`FAILURES_TO_PAUSE`] firings failed is paused.
fn fire(l: &Ledger, t: &Trigger, slot: i64, missed: usize, wake: Waker<'_>) -> Result<Option<Fired>> {
    let (source, kind) = source_kind(t);
    let fields = time_fields(t, slot, missed);
    let delivery = format!("{}@{slot}", t.id);
    let raw = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(fields.to_string().as_bytes()));
    let (fired, woken) = l.immediate(|l| -> Result<(Option<Fired>, Option<String>)> {
        let (event, fresh) = l.record_trigger_event(&t.tenant, source, kind, &delivery, &fields, &raw, "wicket")?;
        if !fresh {
            return Ok((None, None));
        }
        fire_event(l, t, &Ev { id: event, source, at: slot, fields: fields.clone() })
    })?;
    if let Some(agent) = woken {
        wake(&agent, &format!("trigger {}", t.name));
    }
    if fired.as_ref().is_some_and(|f| f.status == "failed") {
        let recent = l.recent_firings(&t.id, FAILURES_TO_PAUSE as i64)?;
        if recent.len() == FAILURES_TO_PAUSE && recent.iter().all(|f| f.status == "failed") {
            let last = recent[0].detail.clone().unwrap_or_default();
            pause_for(l, t, &format!("its last {FAILURES_TO_PAUSE} firings failed (the last: {last})"))?;
        }
    }
    Ok(fired)
}

/// A timer whose time passed while it was paused, or while the reconciler was down longer than
/// [`CATCH_UP_SECS`]: recorded as skipped, once.
fn stale(l: &Ledger, t: &Trigger, slot: i64) -> Result<Option<Fired>> {
    let (source, kind) = source_kind(t);
    let fields = time_fields(t, slot, 0);
    let delivery = format!("{}@{slot}", t.id);
    let raw = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(fields.to_string().as_bytes()));
    l.immediate(|l| -> Result<Option<Fired>> {
        let (event, fresh) = l.record_trigger_event(&t.tenant, source, kind, &delivery, &fields, &raw, "wicket")?;
        if !fresh {
            return Ok(None);
        }
        let why = format!("its time, {}, passed while it was paused or wicket's reconciler was down", fields["at"].as_str().unwrap_or(""));
        let (f, _) = l.record_firing(&t.id, &event, "skipped", Some(&why))?;
        let record = json!({ "trigger": t.id, "name": t.name, "owner": t.owner, "event": event, "firing": f, "source": source, "status": "skipped", "detail": why });
        audit(l, "trigger.skipped", &record)?;
        Ok(Some(Fired { trigger: t.id.clone(), name: t.name.clone(), status: "skipped".into(), detail: why }))
    })
}

/// An event a trigger may fire on, once recorded: its id, its source, when it happened, and its
/// fields.
struct Ev<'a> {
    id: String,
    source: &'a str,
    at: i64,
    fields: Value,
}

/// Fires `t` on `ev`, inside the caller's transaction, if its filter admits it and `t` hasn't
/// fired on it before (one firing per trigger and event): within the hourly limit, and for
/// `start`, the queue. What it did, and the agent to wake once the transaction commits.
fn fire_event(l: &Ledger, t: &Trigger, ev: &Ev<'_>) -> Result<(Option<Fired>, Option<String>)> {
    if !t.spec.admits(&ev.fields) {
        return Ok((None, None));
    }
    let (event, source, fields) = (&ev.id, ev.source, &ev.fields);
    let done = |status: &str, detail: String| Some(Fired { trigger: t.id.clone(), name: t.name.clone(), status: status.into(), detail });
    let record = |status: &str, detail: &str, firing: &str| {
        json!({
            "trigger": t.id, "name": t.name, "owner": t.owner, "event": event, "firing": firing,
            "source": source, "at": fields["at"], "status": status, "detail": detail,
        })
    };
    // The hourly limit counts every firing that went ahead: started, queued (dead-lettered since or
    // not), and failed.
    let hour_ago = ev.at - 3600;
    let mut fired = 0;
    for st in ["started", "queued", "dead", "failed"] {
        fired += l.count_firings(&t.id, st, hour_ago)?;
    }
    if fired >= t.spec.limits.per_hour as i64 {
        let limit = t.spec.limits.per_hour;
        // The hour's first skip is recorded and audited; the rest are counted on it.
        if let Some(f) = l.last_firing(&t.id, "skipped", hour_ago)? {
            let why = format!("its limit of {limit} firings an hour is reached ({} more skipped since)", f.attempts + 1);
            l.count_skip(&f.id, &why)?;
            return Ok((done("skipped", why), None));
        }
        let why = format!("its limit of {limit} firings an hour is reached (further skips this hour are counted here)");
        let (f, fresh) = l.record_firing(&t.id, event, "skipped", Some(&why))?;
        if !fresh {
            return Ok((None, None));
        }
        audit(l, "trigger.skipped", &record("skipped", &why, &f))?;
        return Ok((done("skipped", why), None));
    }
    if t.spec.action.start.is_some() {
        let (f, fresh) = l.record_firing(&t.id, event, "queued", Some("waiting for the engine to start it"))?;
        if !fresh {
            return Ok((None, None));
        }
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
        return Ok((done("queued", detail), None));
    }
    let (f, fresh) = l.record_firing(&t.id, event, "queued", None)?;
    if !fresh {
        return Ok((None, None));
    }
    match deliver(l, t, fields) {
        Ok(d) => {
            l.update_firing(&f, "started", Some(&d.detail), None)?;
            let mut r = record("started", &d.detail, &f);
            r["agent"] = json!(d.agent);
            if let Some((id, text)) = &d.prompt {
                r["prompt"] = json!(id);
                r["text_sha256"] = json!(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(text.as_bytes())));
                r["text_bytes"] = json!(text.len());
            }
            audit(l, "trigger.fired", &r)?;
            Ok((done("started", d.detail), d.wake))
        }
        Err(e) => {
            let why = format!("{e:#}");
            l.update_firing(&f, "failed", Some(&why), None)?;
            audit(l, "trigger.failed", &record("failed", &why, &f))?;
            Ok((done("failed", why), None))
        }
    }
}

/// What a firing did for its agent.
struct Delivered {
    detail: String,
    agent: String,
    /// The turn queued: its message id and text.
    prompt: Option<(String, String)>,
    /// The agent to wake once the firing commits.
    wake: Option<String>,
}

/// Wakes or messages the agent `t` names, inside the firing's transaction. The message, filled
/// from the event, is its next turn: through its current run while it is active, waking or
/// hibernating (a run that hibernates with a turn waiting wakes it again, so a wake on its own
/// queues a short turn saying so); to the agent itself when it is hibernated, which is woken for
/// it after the transaction.
fn deliver(l: &Ledger, t: &Trigger, fields: &Value) -> Result<Delivered> {
    let a = &t.spec.action;
    let who = a.wake.as_deref().or(a.message.as_ref().map(|m| m.to.as_str())).context("the trigger wakes or messages no one")?;
    let agent = target_agent(l, t, who)?;
    let label = format!("trigger:{}", t.name);
    let text = a.message.as_ref().map(|m| message_text(t, fields, &m.body));
    let mut d = Delivered { detail: String::new(), agent: agent.id.clone(), prompt: None, wake: None };
    match agent.state.as_str() {
        "active" | "waking" | "hibernating" => {
            let text = match (text, agent.state.as_str()) {
                (Some(t), _) => Some(t),
                (None, "hibernating") => {
                    Some(format!("[wicket] Trigger {} fired ({}): it wakes you.", t.name, fields["at"].as_str().unwrap_or("")))
                }
                (None, _) => None,
            };
            d.detail = match &text {
                Some(_) => format!("messaged agent {} ({}) through its run {}", agent.id, agent.state, agent.run),
                None => format!("agent {} is already {}", agent.id, agent.state),
            };
            if let Some(text) = text {
                d.prompt = Some((l.add_prompt(&agent.run, &text, &label, &t.owner)?, text));
            }
        }
        "hibernated" if agent.restorable => {
            if let Some(why) = crate::hibernate::exhausted(&agent) {
                bail!("agent {} can't be woken: {why}", agent.id);
            }
            if let Some(text) = text {
                d.prompt = Some((l.add_prompt(&agent.id, &text, &label, &t.owner)?, text));
            }
            d.detail = format!("woke agent {}{}", agent.id, if d.prompt.is_some() { " with its message" } else { "" });
            d.wake = Some(agent.id.clone());
        }
        s => bail!("agent {} is {s}: it can't be woken", agent.id),
    }
    Ok(d)
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
        let utc = |s: &str| s.parse::<jiff::Timestamp>().unwrap().as_second();
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

    fn operator() -> Operator {
        Operator { id: "spiffe://local/t/t0/op/unix/alex".into(), label: "unix:alex".into(), authority: Authority::Anything }
    }

    fn other() -> Operator {
        Operator { id: "spiffe://local/t/t0/op/unix/bob".into(), label: "unix:bob".into(), authority: Authority::Anything }
    }

    fn anyone(_: &Trigger) -> std::result::Result<(), String> {
        Ok(())
    }

    fn no_wake(_: &str, _: &str) {}

    /// A long-lived agent named `name`, in zone rel, hibernated; its run was run_<name>.
    fn hibernated_agent(l: &mut Ledger, name: &str) -> String {
        hibernated_agent_in(l, name, &format!("run_{name}"))
    }

    fn hibernated_agent_in(l: &mut Ledger, name: &str, run: &str) -> String {
        let agent = wicket_store::new_agent_id();
        l.create_agent(&wicket_store::NewAgent {
            id: &agent,
            tenant: "t0",
            zone: "rel",
            name,
            run,
            session_id: "s",
            manifest: "agent:\n  name: captain\ntask: triage\nzone:\n  name: rel\n  llm: {}\n",
            image: "i",
            workspace: None,
            claim_until: 0,
        })
        .unwrap();
        assert!(l.set_agent_state(&agent, 1, "hibernated", None).unwrap());
        agent
    }

    /// The minute after `at`, on the minute.
    fn next_minute(at: i64) -> i64 {
        (at.div_euclid(60) + 1) * 60
    }

    fn kinds(l: &Ledger) -> Vec<String> {
        l.audit_tail(200).unwrap().into_iter().map(|r| r.2).collect()
    }

    /// #578's first "done when": a morning schedule wakes a hibernated agent with its message as
    /// the next turn, recorded as woken by the trigger; an awake or hibernating agent gets the
    /// message through its run. The dry run shows the same, filled in, and changes nothing.
    #[test]
    fn a_schedule_wakes_an_agent_with_its_message() {
        let mut l = Ledger::open_in_memory().unwrap();
        let agent = hibernated_agent(&mut l, "captain");
        let s = spec(
            "trigger: morning\nsource: { schedule: { cron: '* * * * *' } }\n\
             action: { wake: captain, message: { body: 'Triage {{ event.trigger }} at {{ event.at }}' } }\n",
        );
        let (id, pinned) = create(&l, &operator(), &s, None, "test").unwrap();
        assert_eq!(pinned.unwrap().id, agent);
        let t = l.trigger(&id).unwrap().unwrap();
        assert_eq!(t.spec.action.wake.as_deref(), Some(agent.as_str()), "pinned to the agent's id");
        let shown = preview(&l, &t, None, t.created_at).unwrap();
        assert!(shown.contains("filter:  passes") && shown.contains("captain") && shown.contains("Triage morning at 20"), "{shown}");
        let woke = RefCell::new(vec![]);
        let w = |a: &str, b: &str| woke.borrow_mut().push((a.to_string(), b.to_string()));
        let at = next_minute(t.created_at);
        let got = pass(&l, at, false, &w, &anyone).unwrap();
        assert_eq!(got.iter().map(|f| f.status.as_str()).collect::<Vec<_>>(), ["started"], "{got:?}");
        assert_eq!(*woke.borrow(), [(agent.clone(), "trigger morning".to_string())]);
        let prompts = l.take_prompts(&agent).unwrap();
        assert_eq!(prompts.len(), 1);
        assert!(prompts[0].text.starts_with("[wicket] Trigger morning fired") && prompts[0].text.contains("Triage morning at "));
        let fired = l.audit_tail(5).unwrap().into_iter().find(|r| r.2 == "trigger.fired").unwrap();
        assert!(fired.4.contains(&agent) && fired.4.contains("text_sha256") && fired.4.contains("prompt-"), "{}", fired.4);
        assert!(pass(&l, at, false, &w, &anyone).unwrap().is_empty(), "the same minute is the same event");
        // Awake, waking or hibernating: through its run, and nothing is woken.
        for (n, state) in ["active", "waking", "hibernating"].into_iter().enumerate() {
            assert!(l.set_agent_state(&agent, 1, state, None).unwrap());
            let got = pass(&l, at + 60 * (n as i64 + 1), false, &w, &anyone).unwrap();
            assert!(got[0].detail.contains("through its run run_captain"), "{state}: {got:?}");
            assert_eq!(l.take_prompts("run_captain").unwrap().len(), 1, "{state}");
        }
        assert_eq!(woke.borrow().len(), 1);
        // A dry run reports only what isn't recorded, and records nothing.
        assert!(pass(&l, at + 180, true, &w, &anyone).unwrap().is_empty());
        let due = pass(&l, at + 240, true, &w, &anyone).unwrap();
        assert_eq!(due.iter().map(|f| f.status.as_str()).collect::<Vec<_>>(), ["due"], "{due:?}");
        assert_eq!(pass(&l, at + 240, true, &w, &anyone).unwrap().len(), 1, "a dry run records nothing");
        // A filter that doesn't pass: the preview says so.
        let quiet =
            spec("trigger: quiet\nsource: { schedule: { cron: '* * * * *' } }\nfilter: { trigger: other }\naction: { wake: captain }\n");
        let q = l.trigger(&create(&l, &operator(), &quiet, None, "test").unwrap().0).unwrap().unwrap();
        assert!(preview(&l, &q, None, q.created_at).unwrap().contains("doesn't pass"));
    }

    /// A wake on its own reaches a hibernating agent as a short turn through its run, which wakes
    /// it again once it has hibernated, rather than being lost.
    #[test]
    fn a_wake_reaches_a_hibernating_agent() {
        let mut l = Ledger::open_in_memory().unwrap();
        let agent = hibernated_agent(&mut l, "captain");
        assert!(l.set_agent_state(&agent, 1, "hibernating", None).unwrap());
        let (id, _) = create(
            &l,
            &operator(),
            &spec("trigger: w\nsource: { schedule: { cron: '* * * * *' } }\naction: { wake: captain }\n"),
            None,
            "t",
        )
        .unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        let got = pass(&l, next_minute(t.created_at), false, &no_wake, &anyone).unwrap();
        assert_eq!(got[0].status, "started", "{got:?}");
        let p = l.take_prompts("run_captain").unwrap();
        assert!(p[0].text.contains("it wakes you"), "{p:?}");
    }

    /// Catch-up: a pass fires once for the newest due minute, saying how many it missed; a paused
    /// trigger, once resumed, fires only for minutes after the resume.
    #[test]
    fn a_schedule_fires_once_for_what_it_missed_and_not_while_paused() {
        let mut l = Ledger::open_in_memory().unwrap();
        hibernated_agent(&mut l, "captain");
        let s = spec("trigger: tick\nsource: { schedule: { cron: '* * * * *' } }\naction: { wake: captain, message: { body: hi } }\nlimits: { per_hour: 60 }\n");
        let (id, _) = create(&l, &operator(), &s, None, "test").unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        let at = next_minute(t.created_at) + 4 * 60;
        let got = pass(&l, at, false, &no_wake, &anyone).unwrap();
        assert_eq!(got.len(), 1, "once, for five minutes: {got:?}");
        let fired = l.firings(&id, None).unwrap();
        let ev = l.trigger_event(&fired[0].event).unwrap().unwrap();
        assert_eq!((ev.fields["slot"].as_i64(), ev.fields["missed"].as_u64()), (Some(at), Some(4)));
        assert_eq!(pass(&l, at + 60, false, &no_wake, &anyone).unwrap().len(), 1, "the next minute");
        set_status(&l, &operator(), &id, "paused").unwrap();
        assert!(pass(&l, at + 300, false, &no_wake, &anyone).unwrap().is_empty(), "paused: nothing fires");
        resume(&l, &operator(), false, &id).unwrap();
        // Resumed ten minutes after its last firing: the minutes before the resume aren't due, the
        // one after it is.
        let mut r = l.trigger(&id).unwrap().unwrap();
        r.updated_at = at + 660;
        assert_eq!(due(&l, &r, at + 690).unwrap(), Due::Nothing);
        assert_eq!(due(&l, &r, at + 720).unwrap(), Due::Fire { slot: at + 720, missed: 0 });
        // Approved (or made) a minute ago with nothing recorded: that minute only.
        r.id = "t-other".into();
        r.updated_at = at;
        assert_eq!(due(&l, &r, at + 120).unwrap(), Due::Fire { slot: at + 120, missed: 1 });
        let k = kinds(&l);
        assert!(k.contains(&"trigger.paused".into()) && k.contains(&"trigger.resumed".into()));
    }

    /// H1: before each firing the owner is checked again; one who may no longer have it fire has
    /// it paused, audited, and it fires nothing. Only its owner (or root) resumes or renews it.
    #[test]
    fn a_trigger_stops_with_its_owners_authority() {
        let mut l = Ledger::open_in_memory().unwrap();
        hibernated_agent(&mut l, "captain");
        let s = spec("trigger: t\nsource: { schedule: { cron: '* * * * *' } }\naction: { wake: captain }\n");
        let (id, _) = create(&l, &operator(), &s, None, "test").unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        let gone = |_: &Trigger| -> std::result::Result<(), String> { Err("alex is no longer in wicket-operators".into()) };
        let got = pass(&l, next_minute(t.created_at), false, &no_wake, &gone).unwrap();
        assert_eq!(got[0].status, "paused", "{got:?}");
        assert!(got[0].detail.contains("no longer in wicket-operators"));
        assert_eq!(l.trigger(&id).unwrap().unwrap().status, "paused");
        assert!(l.firings(&id, None).unwrap().is_empty(), "nothing fired");
        assert!(resume(&l, &other(), false, &id).unwrap_err().to_string().contains("only they (or root)"));
        assert!(renew(&l, &other(), false, &id, None).is_err());
        resume(&l, &other(), true, &id).unwrap();
        renew(&l, &operator(), false, &id, Some(t.created_at + 86400)).unwrap();
        assert_eq!(l.trigger(&id).unwrap().unwrap().until, Some(t.created_at + 86400));
        assert!(kinds(&l).contains(&"trigger.renewed".into()));
        // operators.yaml's part: an operator of another tenant isn't one.
        let mut foreign = l.trigger(&id).unwrap().unwrap();
        foreign.owner = "spiffe://local/t/t9/op/unix/alex".into();
        assert!(operator_may(&foreign).unwrap_err().contains("tenant"));
        foreign.owner = "spiffe://local/t/t0/z/z/a/a".into();
        assert!(operator_may(&foreign).is_err());
    }

    /// M4 and M5: the agent is resolved when the trigger is made: an unknown name, `self` for an
    /// operator, or a name two live agents share is refused; an ended namesake isn't counted.
    /// Firings that keep failing pause the trigger; failures count toward the hourly limit.
    #[test]
    fn targets_are_resolved_when_made_and_failures_pause() {
        let mut l = Ledger::open_in_memory().unwrap();
        let mk = |y: &str| {
            spec(&format!("trigger: t\nsource: {{ schedule: {{ cron: '* * * * *' }} }}\naction: {y}\nlimits: {{ per_hour: 60 }}\n"))
        };
        assert!(create(&l, &operator(), &mk("{ wake: captian }"), None, "t")
            .unwrap_err()
            .to_string()
            .contains("no live long-lived agent named captian"));
        assert!(create(&l, &operator(), &mk("{ wake: self }"), None, "t").unwrap_err().to_string().contains("`self` is for an agent"));
        let old = hibernated_agent_in(&mut l, "captain", "run_1");
        assert!(l.set_agent_state(&old, 1, "ended", None).unwrap());
        let new = hibernated_agent_in(&mut l, "captain", "run_2");
        let (id, a) = create(&l, &operator(), &mk("{ wake: captain }"), None, "t").unwrap();
        assert_eq!(a.unwrap().id, new, "the ended one isn't counted");
        hibernated_agent_in(&mut l, "captain", "run_3");
        let dup = spec("trigger: d\nsource: { schedule: { cron: '* * * * *' } }\naction: { wake: captain }\n");
        assert!(create(&l, &operator(), &dup, None, "t").unwrap_err().to_string().contains("name it by its id"));
        // The pinned agent ends: each firing fails, and after FAILURES_TO_PAUSE the trigger pauses.
        assert!(l.set_agent_state(&new, 1, "ended", None).unwrap());
        let t = l.trigger(&id).unwrap().unwrap();
        let mut at = next_minute(t.created_at);
        let mut statuses = vec![];
        for _ in 0..FAILURES_TO_PAUSE {
            statuses.extend(pass(&l, at, false, &no_wake, &anyone).unwrap().into_iter().map(|f| f.status));
            at += 60;
        }
        assert_eq!(statuses.last().map(String::as_str), Some("failed"), "{statuses:?}");
        assert_eq!(l.trigger(&id).unwrap().unwrap().status, "paused", "{statuses:?}");
        assert!(pass(&l, at, false, &no_wake, &anyone).unwrap().is_empty());
        assert_eq!(l.count_firings(&id, "failed", 0).unwrap(), FAILURES_TO_PAUSE as i64);
    }

    /// Over the hourly limit, the hour's first skip is recorded and audited; the rest are counted
    /// on it, not written as records of their own.
    #[test]
    fn skips_over_the_limit_are_one_record_an_hour() {
        let l = Ledger::open_in_memory().unwrap();
        let s = spec(&format!(
            "trigger: build\nsource: {{ schedule: {{ cron: '* * * * *' }} }}\naction: {{ start: {{ manifest: b.yaml, sha256: {} }} }}\nlimits: {{ per_hour: 2, queue: 1 }}\n",
            "a".repeat(64)
        ));
        let (id, _) = create(&l, &operator(), &s, None, "test").unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        let mut at = next_minute(t.created_at);
        let mut got = vec![];
        for _ in 0..5 {
            got.extend(pass(&l, at, false, &no_wake, &anyone).unwrap());
            at += 60;
        }
        let st: Vec<&str> = got.iter().map(|f| f.status.as_str()).collect();
        assert_eq!(st, ["queued", "queued", "skipped", "skipped", "skipped"], "{got:?}");
        assert!(got[1].detail.contains("dead-lettered"), "a queue of one: {got:?}");
        assert_eq!(l.firings(&id, Some("skipped")).unwrap().len(), 1);
        assert_eq!(l.firings(&id, Some("skipped")).unwrap()[0].attempts, 2);
        assert_eq!(kinds(&l).iter().filter(|k| *k == "trigger.skipped").count(), 1);
    }

    /// A timer fires once, when it comes due; one already past isn't kept; one whose time passed
    /// while it was paused is recorded as skipped, once.
    #[test]
    fn a_timer_fires_once_when_due() {
        let mut l = Ledger::open_in_memory().unwrap();
        hibernated_agent(&mut l, "captain");
        let (id, _) =
            create(&l, &operator(), &spec("trigger: later\nsource: { timer: { after: 2h } }\naction: { wake: captain }\n"), None, "t")
                .unwrap();
        let t = l.trigger(&id).unwrap().unwrap();
        assert!(pass(&l, t.created_at + 3600, false, &no_wake, &anyone).unwrap().is_empty());
        assert_eq!(next_due(&t, t.created_at), Some(t.created_at + 7200));
        assert_eq!(pass(&l, t.created_at + 7300, false, &no_wake, &anyone).unwrap().len(), 1);
        assert!(pass(&l, t.created_at + 9000, false, &no_wake, &anyone).unwrap().is_empty(), "once");
        let past = spec("trigger: past\nsource: { timer: { at: '2020-01-01T00:00:00Z' } }\naction: { wake: captain }\n");
        assert!(create(&l, &operator(), &past, None, "t").unwrap_err().to_string().contains("passed"));
        let mars = spec("trigger: mars\nsource: { schedule: { cron: '0 7 * * *', tz: Mars/Olympus } }\naction: { wake: captain }\n");
        assert!(create(&l, &operator(), &mars, None, "t").is_err());
        let (late, _) =
            create(&l, &operator(), &spec("trigger: late\nsource: { timer: { after: 1h } }\naction: { wake: captain }\n"), None, "t")
                .unwrap();
        let lt = l.trigger(&late).unwrap().unwrap();
        // Down for two hours: its time is long past.
        let got = pass(&l, lt.created_at + 3 * 3600, false, &no_wake, &anyone).unwrap();
        assert_eq!(got.iter().map(|f| f.status.as_str()).collect::<Vec<_>>(), ["skipped"], "{got:?}");
        assert!(pass(&l, lt.created_at + 4 * 3600, false, &no_wake, &anyone).unwrap().is_empty(), "once");
    }

    /// Sources and limits this version doesn't fire or enforce are refused, not kept silently.
    #[test]
    fn what_isnt_built_yet_is_refused() {
        let mut l = Ledger::open_in_memory().unwrap();
        hibernated_agent(&mut l, "captain");
        for (y, why) in [
            ("source: { wicket: { kinds: [run.end] } }\naction: { wake: captain }\n", "schedules and timers only"),
            ("source: { schedule: { cron: '* * * * *' } }\naction: { wake: captain }\nlimits: { concurrency: 2 }\n", "concurrency"),
            ("source: { schedule: { cron: '* * * * *' } }\naction: { wake: captain }\nlimits: { debounce: 10m }\n", "debounce"),
        ] {
            let e = create(&l, &operator(), &spec(&format!("trigger: t\n{y}")), None, "t").unwrap_err().to_string();
            assert!(e.contains(why), "{y}: {e}");
        }
    }

    /// One trigger that can't be fired is its own failure: the others in the pass still fire.
    #[test]
    fn one_triggers_error_doesnt_stop_the_pass() {
        let mut l = Ledger::open_in_memory().unwrap();
        hibernated_agent(&mut l, "captain");
        // Kept before this host lost its zone (the store holds to shape, not to zoneinfo).
        let bad = spec("trigger: bad\nsource: { schedule: { cron: '* * * * *', tz: Mars/Olympus } }\naction: { wake: captain }\n");
        l.create_trigger("t0", &operator().id, &bad, "unix:alex", false, None).unwrap();
        let (good, _) = create(
            &l,
            &operator(),
            &spec("trigger: good\nsource: { schedule: { cron: '* * * * *' } }\naction: { wake: captain }\n"),
            None,
            "t",
        )
        .unwrap();
        let t = l.trigger(&good).unwrap().unwrap();
        let got = pass(&l, next_minute(t.created_at), false, &no_wake, &anyone).unwrap();
        let mut by: Vec<(&str, &str)> = got.iter().map(|f| (f.name.as_str(), f.status.as_str())).collect();
        by.sort();
        assert_eq!(by, [("bad", "failed"), ("good", "started")], "{got:?}");
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

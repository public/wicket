//! Triggers (#578): a principal's standing intent, "when an event of source S matching filter F
//! happens, do A, with inputs from the event by template T, within limits L". This module is the
//! trigger document and its validation; the ledger keeps it (`wicket-store`'s `triggers`), and the
//! scheduler and the engine that fire it come later (the design note's plan, steps 2 to 5).
//!
//! Three rules hold whatever the document says, and are the engine's to enforce:
//! - a firing never has more authority than the trigger's owner;
//! - an agent's trigger may only wake or message the agent itself, unless a human approves more;
//! - event content reaches the work only through the template, as quoted, tainted text in a task
//!   or a message, never in a manifest's fields.
//!
//! What this module holds to is the document's shape: a source it knows, a filter over that
//! source's fields, a template that names only event fields, and limits within bounds.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A trigger document, as an operator writes it (`wicket trigger create --file T.yaml`) or an
/// agent asks for it (`request_trigger`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerSpec {
    /// Its name, unique per owner: `[a-z0-9-]`, 1 to 64.
    pub trigger: String,
    pub source: Source,
    /// Per source, over its fields (§3 of the design): each field equals one value, is one of a
    /// list, or matches a glob (`*`, and a leading `!` for "not").
    #[serde(default)]
    pub filter: BTreeMap<String, FilterValue>,
    pub action: Action,
    #[serde(default)]
    pub limits: Limits,
}

/// Where events come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    /// A cron schedule (five fields: minute, hour, day of month, month, day of week), in a time
    /// zone (`UTC` by default).
    Schedule {
        cron: String,
        #[serde(default = "utc")]
        tz: String,
    },
    /// Once: at an instant (RFC 3339), or a while after the trigger is created (`2h`).
    Timer {
        #[serde(default)]
        at: Option<String>,
        #[serde(default)]
        after: Option<String>,
    },
    /// A generic webhook, verified with an HMAC-SHA256 of the body under a vault secret (a
    /// `verify` secret: never sent anywhere).
    Webhook { verify: Verify },
    /// GitHub deliveries for a repository, verified as GitHub signs them (`X-Hub-Signature-256`).
    Github { repo: String, events: Vec<String>, verify: Verify },
    /// wicket's own events, read from the audit chain: these kinds of record.
    Wicket { kinds: Vec<String> },
}

fn utc() -> String {
    "UTC".into()
}

/// How a webhook's deliveries are verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verify {
    /// The vault secret holding the HMAC key.
    pub hmac_sha256: String,
}

/// One filter condition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterValue {
    Number(i64),
    Bool(bool),
    One(String),
    Any(Vec<String>),
}

/// What a firing does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// Start a run of a manifest, pinned by its sha256: an edit to the file doesn't change what
    /// starts.
    #[serde(default)]
    pub start: Option<Start>,
    /// Wake a long-lived agent (its name, or `self` for the trigger's owner).
    #[serde(default)]
    pub wake: Option<String>,
    /// Send a message: to a principal (or `self`), with a body that may name event fields.
    #[serde(default)]
    pub message: Option<Message>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub manifest: String,
    pub sha256: String,
    /// The run's task, which may name event fields.
    #[serde(default)]
    pub task: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    #[serde(default = "self_")]
    pub to: String,
    pub body: String,
}

fn self_() -> String {
    "self".into()
}

/// Flow limits (§4 of the design).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// At most this many firings running at once.
    #[serde(default = "one")]
    pub concurrency: u32,
    /// Coalesce a key's events within this window (`10m`; none by default).
    #[serde(default)]
    pub debounce: Option<String>,
    /// At most this many firings an hour.
    #[serde(default = "six")]
    pub per_hour: u32,
    /// At most this many firings waiting; beyond it, the oldest is dropped and recorded.
    #[serde(default = "ten")]
    pub queue: u32,
}

fn one() -> u32 {
    1
}
fn six() -> u32 {
    6
}
fn ten() -> u32 {
    10
}

impl Default for Limits {
    fn default() -> Self {
        Limits { concurrency: 1, debounce: None, per_hour: 6, queue: 10 }
    }
}

/// The most firings an hour any trigger may have, and the most waiting.
pub const MAX_PER_HOUR: u32 = 60;
pub const MAX_QUEUE: u32 = 100;
pub const MAX_CONCURRENCY: u32 = 10;
/// The longest a template's text may be, before event fields are filled in.
pub const MAX_TEMPLATE: usize = 4000;

/// wicket's own record kinds a trigger may listen to (the audit chain's; `docs/reference/audit.md`).
pub const WICKET_KINDS: &[&str] =
    &["run.end", "run.lost", "box.exited", "box.memory_pressure", "agent.wake", "agent.hibernate", "message.refused", "decision"];

/// The GitHub events a trigger may listen to.
pub const GITHUB_EVENTS: &[&str] = &[
    "issues",
    "issue_comment",
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
    "check_suite",
    "check_run",
    "push",
    "workflow_run",
];

/// Whether `name` is a trigger's or a template field's name: `[a-z0-9_-]`, 1 to 64, starting with
/// a letter or digit.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.')
        && name.as_bytes()[0].is_ascii_alphanumeric()
}

impl TriggerSpec {
    /// Why this document can't be kept, if it can't: everything the ledger and the engine rely on
    /// about its shape. (Whether its owner may have it is the engine's and the approval's.)
    pub fn check(&self) -> Result<(), String> {
        if !plain(&self.trigger) || self.trigger.contains(['_', '.']) {
            return Err(format!("trigger name {:?}: 1 to 64 of a-z, 0-9 and -", crate::text::strip(&self.trigger)));
        }
        match &self.source {
            Source::Schedule { cron, tz } => {
                Cron::parse(cron)?;
                if tz != "UTC"
                    && !tz.split('/').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"_+-".contains(&b)))
                {
                    return Err(format!("time zone {:?} is not a zone name (UTC, or Area/City)", crate::text::strip(tz)));
                }
            }
            Source::Timer { at, after } => match (at, after) {
                (Some(a), None) => {
                    crate::time::parse_rfc3339_weak(a).map_err(|e| format!("timer at {:?}: {e}", crate::text::strip(a)))?;
                }
                (None, Some(d)) => {
                    crate::time::parse_duration(d).map_err(|e| format!("timer after {:?}: {e}", crate::text::strip(d)))?;
                }
                _ => return Err("a timer has exactly one of at and after".into()),
            },
            Source::Webhook { verify } => check_secret(&verify.hmac_sha256)?,
            Source::Github { repo, events, verify } => {
                let ok = repo.split_once('/').is_some_and(|(o, r)| {
                    [o, r].iter().all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
                });
                if !ok {
                    return Err(format!("repo {:?} is not owner/name", crate::text::strip(repo)));
                }
                if events.is_empty() {
                    return Err("a GitHub trigger names at least one event".into());
                }
                if let Some(e) = events.iter().find(|e| !GITHUB_EVENTS.contains(&e.as_str())) {
                    return Err(format!("GitHub event {:?} is not one of {}", crate::text::strip(e), GITHUB_EVENTS.join(", ")));
                }
                check_secret(&verify.hmac_sha256)?;
            }
            Source::Wicket { kinds } => {
                if kinds.is_empty() {
                    return Err("a wicket trigger names at least one record kind".into());
                }
                if let Some(k) = kinds.iter().find(|k| !WICKET_KINDS.contains(&k.as_str())) {
                    return Err(format!("record kind {:?} is not one of {}", crate::text::strip(k), WICKET_KINDS.join(", ")));
                }
            }
        }
        for (field, v) in &self.filter {
            if !plain(field) {
                return Err(format!("filter field {:?} is not a field name", crate::text::strip(field)));
            }
            let texts: Vec<&str> = match v {
                FilterValue::One(s) => vec![s.as_str()],
                FilterValue::Any(v) if v.is_empty() => return Err(format!("filter field {field}: an empty list matches nothing")),
                FilterValue::Any(v) => v.iter().map(String::as_str).collect(),
                _ => vec![],
            };
            if let Some(t) = texts.iter().find(|t| t.chars().any(crate::text::is_unsafe) || t.len() > 256) {
                return Err(format!("filter field {field}: value {:?} is too long or has a control character", crate::text::strip(t)));
            }
        }
        let a = &self.action;
        if a.start.is_none() && a.wake.is_none() && a.message.is_none() {
            return Err("an action starts a manifest, wakes an agent, or sends a message".into());
        }
        if a.start.is_some() && a.wake.is_some() {
            return Err("an action starts a run or wakes an agent, not both".into());
        }
        if let Some(s) = &a.start {
            if s.sha256.len() != 64 || !s.sha256.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                return Err("start.sha256 is the manifest's sha256, 64 lower-case hex digits".into());
            }
            if s.manifest.is_empty() || s.manifest.contains("..") || s.manifest.starts_with('/') {
                return Err(format!("start.manifest {:?}: a path in a manifests root, relative", crate::text::strip(&s.manifest)));
            }
            if let Some(t) = &s.task {
                template(t)?;
            }
        }
        if let Some(w) = &a.wake {
            if w != "self" && !plain(w) {
                return Err(format!("wake {:?}: self, or a long-lived agent's name", crate::text::strip(w)));
            }
        }
        if let Some(m) = &a.message {
            if m.to != "self" && !m.to.starts_with("spiffe://") {
                return Err(format!("message.to {:?}: self, or a principal (spiffe://…)", crate::text::strip(&m.to)));
            }
            // Waking and messaging are one action: the message is the woken agent's next turn.
            if a.wake.is_some() && m.to != "self" {
                return Err("with wake, the message goes to the agent woken: leave message.to out".into());
            }
            template(&m.body)?;
        }
        let l = &self.limits;
        if l.concurrency == 0 || l.concurrency > MAX_CONCURRENCY {
            return Err(format!("limits.concurrency is 1 to {MAX_CONCURRENCY}"));
        }
        if l.per_hour == 0 || l.per_hour > MAX_PER_HOUR {
            return Err(format!("limits.per_hour is 1 to {MAX_PER_HOUR}"));
        }
        if l.queue > MAX_QUEUE {
            return Err(format!("limits.queue is at most {MAX_QUEUE}"));
        }
        if let Some(d) = &l.debounce {
            crate::time::parse_duration(d).map_err(|e| format!("limits.debounce {:?}: {e}", crate::text::strip(d)))?;
        }
        Ok(())
    }

    /// Whether the action stays within the owner itself: it wakes or messages only `self`. An
    /// agent's trigger that does anything else is a widening, for a human to approve.
    pub fn only_self(&self) -> bool {
        let a = &self.action;
        a.start.is_none() && a.wake.as_deref().is_none_or(|w| w == "self") && a.message.as_ref().is_none_or(|m| m.to == "self")
    }
}

fn check_secret(name: &str) -> Result<(), String> {
    if !plain(name) {
        return Err(format!("verify secret {:?} is not a secret name", crate::text::strip(name)));
    }
    Ok(())
}

/// The event fields a template names, if it is one: text with `{{ event.<field> }}` placeholders
/// and nothing else between braces, at most [`MAX_TEMPLATE`] long, no control characters.
pub fn template(t: &str) -> Result<Vec<String>, String> {
    if t.len() > MAX_TEMPLATE {
        return Err(format!("a template is at most {MAX_TEMPLATE} bytes"));
    }
    if t.chars().any(|c| c != '\n' && crate::text::is_unsafe(c)) {
        return Err("a template has a control character".into());
    }
    let mut fields = vec![];
    let mut rest = t;
    while let Some(i) = rest.find("{{") {
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else { return Err("a template has an unclosed {{".into()) };
        let inner = after[..j].trim();
        let Some(f) = inner.strip_prefix("event.").filter(|f| plain(f)) else {
            return Err(format!(
                "a template names only event fields, {{{{ event.<field> }}}}, not {{{{ {} }}}}",
                crate::text::strip(inner)
            ));
        };
        fields.push(f.to_string());
        rest = &after[j + 2..];
    }
    if rest.contains("}}") {
        return Err("a template has a }} with no {{".into());
    }
    Ok(fields)
}

/// An event's field by its dotted path (`pr.number`), if it has it.
pub fn field<'a>(fields: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.').try_fold(fields, |v, k| v.get(k))
}

/// The longest a field's text may be in a filled-in template: longer is cut, and marked.
pub const MAX_FIELD_TEXT: usize = 1000;

/// A field's value as a filter and a template read it: a string as itself, a number or a bool as
/// written, anything else (an object, a list, null) as nothing.
fn text_of(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Whether `text` matches `pattern`: `*` is any run of characters, everything else is itself.
fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // The classic two-pointer match, with the last `*` to fall back to.
    let (mut i, mut j, mut star, mut mark) = (0, 0, None, 0);
    while j < t.len() {
        if i < p.len() && p[i] != '*' && p[i] == t[j] {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            mark = j;
            i += 1;
        } else if let Some(s) = star {
            i = s + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == '*')
}

/// Whether one string condition holds for `text`: a glob, or with a leading `!`, not.
fn holds(cond: &str, text: Option<&str>) -> bool {
    match cond.strip_prefix('!') {
        Some(c) => text.is_none_or(|t| !glob(c, t)),
        None => text.is_some_and(|t| glob(cond, t)),
    }
}

impl FilterValue {
    /// Whether a field's value (None: the event hasn't it) meets this condition. A list matches
    /// when any of its conditions does; a `!` condition matches a missing field.
    pub fn matches(&self, v: Option<&serde_json::Value>) -> bool {
        match self {
            FilterValue::Number(n) => v.and_then(serde_json::Value::as_i64) == Some(*n),
            FilterValue::Bool(b) => v.and_then(serde_json::Value::as_bool) == Some(*b),
            FilterValue::One(c) => holds(c, v.and_then(text_of).as_deref()),
            FilterValue::Any(cs) => {
                let t = v.and_then(text_of);
                cs.iter().any(|c| holds(c, t.as_deref()))
            }
        }
    }
}

impl TriggerSpec {
    /// Whether an event with these fields passes the filter: every condition holds.
    pub fn admits(&self, fields: &serde_json::Value) -> bool {
        self.filter.iter().all(|(k, c)| c.matches(field(fields, k)))
    }
}

/// A template filled in from an event's fields: each `{{ event.<field> }}` becomes the field's
/// text, stripped of control characters and cut at [`MAX_FIELD_TEXT`], or nothing if the event
/// hasn't it. The result is text to quote to the work, never anything wicket reads as authority.
/// A template [`template`] refuses is returned as it is (`check` refused it before it was kept).
pub fn render(t: &str, fields: &serde_json::Value) -> String {
    if template(t).is_err() {
        return t.to_string();
    }
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let j = after.find("}}").unwrap_or(after.len());
        let name = after[..j].trim().trim_start_matches("event.");
        let mut v = field(fields, name).and_then(text_of).map(|s| crate::text::strip(&s)).unwrap_or_default();
        if v.len() > MAX_FIELD_TEXT {
            let mut cut = MAX_FIELD_TEXT;
            while !v.is_char_boundary(cut) {
                cut -= 1;
            }
            v.truncate(cut);
            v.push('…');
        }
        out.push_str(&v);
        rest = after.get(j + 2..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

/// A five-field cron schedule, each field the set of values it matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cron {
    pub minutes: Vec<u8>,
    pub hours: Vec<u8>,
    pub days: Vec<u8>,
    pub months: Vec<u8>,
    /// 0 to 6, Sunday 0 (7 is read as 0).
    pub weekdays: Vec<u8>,
}

impl Cron {
    /// Parses `m h dom mon dow`: each field `*`, a number, a range `a-b`, a step `*/n` or `a-b/n`,
    /// or a comma list of those.
    pub fn parse(s: &str) -> Result<Cron, String> {
        let f: Vec<&str> = s.split_whitespace().collect();
        if f.len() != 5 {
            return Err(format!("cron {:?}: five fields (minute hour day month weekday)", crate::text::strip(s)));
        }
        let field = |i: usize, lo: u8, hi: u8, name: &str| -> Result<Vec<u8>, String> {
            let mut out = std::collections::BTreeSet::new();
            for part in f[i].split(',') {
                let (range, step) = match part.split_once('/') {
                    Some((r, st)) => {
                        (r, st.parse::<u8>().ok().filter(|n| *n > 0).ok_or_else(|| format!("cron {name}: bad step in {part:?}"))?)
                    }
                    None => (part, 1),
                };
                let (a, b) = match range {
                    "*" => (lo, hi),
                    r => match r.split_once('-') {
                        Some((a, b)) => (
                            a.parse().map_err(|_| format!("cron {name}: {part:?}"))?,
                            b.parse().map_err(|_| format!("cron {name}: {part:?}"))?,
                        ),
                        None => {
                            let n: u8 = r.parse().map_err(|_| format!("cron {name}: {part:?}"))?;
                            (n, if part.contains('/') { hi } else { n })
                        }
                    },
                };
                if a < lo || b > hi || a > b {
                    return Err(format!("cron {name}: {part:?} is outside {lo}-{hi}"));
                }
                out.extend((a..=b).step_by(step as usize));
            }
            Ok(out.into_iter().collect())
        };
        let mut weekdays = field(4, 0, 7, "weekday")?;
        if weekdays.contains(&7) {
            weekdays.retain(|d| *d != 7);
            if !weekdays.contains(&0) {
                weekdays.insert(0, 0);
            }
        }
        Ok(Cron {
            minutes: field(0, 0, 59, "minute")?,
            hours: field(1, 0, 23, "hour")?,
            days: field(2, 1, 31, "day")?,
            months: field(3, 1, 12, "month")?,
            weekdays,
        })
    }

    /// Whether the schedule fires at this minute (local time in its zone): minute, hour and month
    /// match, and the day of month or the weekday does (cron's rule: when both are restricted,
    /// either matches).
    pub fn matches(&self, minute: u8, hour: u8, day: u8, month: u8, weekday: u8) -> bool {
        let all_days = self.days.len() == 31;
        let all_weekdays = self.weekdays.len() == 7;
        let day_ok = match (all_days, all_weekdays) {
            (true, true) => true,
            (true, false) => self.weekdays.contains(&weekday),
            (false, true) => self.days.contains(&day),
            (false, false) => self.days.contains(&day) || self.weekdays.contains(&weekday),
        };
        self.minutes.contains(&minute) && self.hours.contains(&hour) && self.months.contains(&month) && day_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(y: &str) -> Result<TriggerSpec, String> {
        let s: TriggerSpec = crate::yaml::from_str(y).map_err(|e| e.to_string())?;
        s.check().map(|_| s)
    }

    /// #578: the design's two done-when cases are documents this accepts.
    #[test]
    fn a_morning_schedule_and_a_ci_failure_are_triggers() {
        let morning = spec("trigger: morning\nsource: { schedule: { cron: '0 7 * * 1-5', tz: Europe/London } }\naction: { wake: self, message: { body: 'Morning: triage what failed overnight.' } }\n").unwrap();
        assert!(morning.only_self());
        let ci = spec(
            "trigger: ci-failed\nsource: { github: { repo: acme/app, events: [check_suite], verify: { hmac_sha256: gh-hook-acme } } }\nfilter: { conclusion: failure, branch: '!main' }\naction: { message: { to: 'spiffe://w/t/t0/z/build/a/captain', body: 'CI failed on {{ event.pr.number }}: {{ event.check.url }}' } }\nlimits: { debounce: 10m }\n",
        )
        .unwrap();
        assert!(!ci.only_self(), "messages another principal: a widening for an agent");
        assert_eq!(template("on {{ event.pr.number }} at {{event.check.url}}").unwrap(), ["pr.number", "check.url"]);
    }

    /// The shape is held: known sources and kinds, a template naming only event fields, limits in
    /// bounds, a pinned manifest, one action kind that makes sense.
    #[test]
    fn a_trigger_document_is_held_to_its_shape() {
        let bad = |y: &str, why: &str| {
            let e = spec(y).unwrap_err();
            assert!(e.contains(why), "{y}: {e}");
        };
        let act = "action: { wake: self }\n";
        bad(&format!("trigger: Bad_Name\nsource: {{ schedule: {{ cron: '* * * * *' }} }}\n{act}"), "trigger name");
        bad(&format!("trigger: t\nsource: {{ schedule: {{ cron: '60 * * * *' }} }}\n{act}"), "outside 0-59");
        bad(&format!("trigger: t\nsource: {{ schedule: {{ cron: '* * *' }} }}\n{act}"), "five fields");
        bad(&format!("trigger: t\nsource: {{ timer: {{ at: '2026-11-20T07:00:00Z', after: 2h }} }}\n{act}"), "exactly one");
        bad(&format!("trigger: t\nsource: {{ wicket: {{ kinds: [secret.set] }} }}\n{act}"), "is not one of");
        bad(
            &format!("trigger: t\nsource: {{ github: {{ repo: acme, events: [push], verify: {{ hmac_sha256: k }} }} }}\n{act}"),
            "owner/name",
        );
        bad("trigger: t\nsource: { wicket: { kinds: [run.end] } }\naction: {}\n", "an action starts");
        bad(
            "trigger: t\nsource: { wicket: { kinds: [run.end] } }\naction: { start: { manifest: a.yaml, sha256: abc } }\n",
            "64 lower-case hex",
        );
        bad(
            "trigger: t\nsource: { wicket: { kinds: [run.end] } }\naction: { message: { body: '{{ zone.reach }}' } }\n",
            "only event fields",
        );
        bad("trigger: t\nsource: { wicket: { kinds: [run.end] } }\naction: { message: { body: 'x {{ event.a' } }\n", "unclosed");
        bad("trigger: t\nsource: { wicket: { kinds: [run.end] } }\naction: { message: { to: alex, body: x } }\n", "principal");
        bad(
            "trigger: t\nsource: { wicket: { kinds: [run.end] } }\naction: { wake: a, message: { to: 'spiffe://w/t/t0/z/z/a/b', body: x } }\n",
            "leave message.to out",
        );
        bad("trigger: t\nsource: { wicket: { kinds: [run.end] } }\naction: { wake: self }\nlimits: { per_hour: 1000 }\n", "per_hour");
        bad("trigger: t\nsource: { wicket: { kinds: [run.end] } }\nfilter: { x: [] }\naction: { wake: self }\n", "matches nothing");
        let start = format!(
            "trigger: t\nsource: {{ timer: {{ after: 2h }} }}\naction: {{ start: {{ manifest: triage.yaml, sha256: {} }} }}\n",
            "a".repeat(64)
        );
        assert!(!spec(&start).unwrap().only_self(), "starting a manifest is a widening for an agent");
        assert!(
            crate::yaml::from_str::<TriggerSpec>("trigger: t\nsource: { cron: x }\naction: { wake: self }\n").is_err(),
            "unknown source"
        );
    }

    /// A filter's conditions over an event's dotted fields: values, lists, globs and `!`.
    #[test]
    fn a_filter_admits_the_events_it_names() {
        let s = spec("trigger: t\nsource: { wicket: { kinds: [run.end] } }\nfilter: { conclusion: [failure, timed_out], branch: '!main', pr.number: 7, repo: 'acme/*' }\naction: { wake: self }\n").unwrap();
        let ev = |c: &str, b: Option<&str>, n: i64| {
            let mut v = serde_json::json!({ "conclusion": c, "pr": { "number": n }, "repo": "acme/app" });
            if let Some(b) = b {
                v["branch"] = b.into();
            }
            v
        };
        assert!(s.admits(&ev("failure", Some("fix/x"), 7)));
        assert!(s.admits(&ev("timed_out", None, 7)), "a ! condition admits a missing field");
        assert!(!s.admits(&ev("success", Some("fix/x"), 7)));
        assert!(!s.admits(&ev("failure", Some("main"), 7)));
        assert!(!s.admits(&ev("failure", Some("fix/x"), 8)));
        assert!(glob("a*b*c", "aXXbYc") && glob("*", "") && !glob("a*b", "acb-") && glob("**x", "x"));
    }

    /// A template is filled with the event's text, stripped and cut; a missing field is nothing.
    #[test]
    fn a_template_is_filled_with_quoted_text() {
        let f = serde_json::json!({ "pr": { "number": 12 }, "title": "fix\u{1b}[31m it", "long": "é".repeat(800) });
        assert_eq!(render("PR {{ event.pr.number }}: {{event.title}} ({{ event.none }})", &f), "PR 12: fix [31m it ()");
        let long = render("{{ event.long }}", &f);
        assert!(long.ends_with('…') && long.len() <= MAX_FIELD_TEXT + '…'.len_utf8(), "{}", long.len());
        assert_eq!(render("{{ zone.reach }}", &f), "{{ zone.reach }}", "not a template: left as it is");
    }

    /// Cron: lists, ranges, steps, Sunday as 0 or 7, and cron's day-of-month-or-weekday rule.
    #[test]
    fn cron_fields_parse_and_match() {
        let c = Cron::parse("*/15 7-9 * * 1-5").unwrap();
        assert_eq!(c.minutes, [0, 15, 30, 45]);
        assert_eq!(c.hours, [7, 8, 9]);
        // Wed 2026-11-18 08:30; and Sunday not.
        assert!(c.matches(30, 8, 18, 11, 3) && !c.matches(30, 8, 22, 11, 0) && !c.matches(31, 8, 18, 11, 3));
        assert_eq!(Cron::parse("0 0 * * 7").unwrap().weekdays, [0]);
        // Day 1 or Monday, when both are restricted.
        let both = Cron::parse("0 0 1 * 1").unwrap();
        assert!(both.matches(0, 0, 1, 5, 4) && both.matches(0, 0, 9, 5, 1) && !both.matches(0, 0, 9, 5, 2));
        for bad in ["* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "* * 0 * *"] {
            assert!(Cron::parse(bad).is_err(), "{bad}");
        }
    }
}

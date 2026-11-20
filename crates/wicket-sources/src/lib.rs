//! Webhook trigger sources behind an adapter (#740; docs/explanation/trigger-intake.md).
//!
//! `wicket node intake` and the control host treat every webhook source the same way: the token
//! before the body, the body's cap and budget, a signature, the deliveries seen, the trigger's rate,
//! the hand-off and the control host's checks. What differs between sources lives here, one
//! [`Adapter`] each:
//!
//! - how a delivery is verified: its headers, and the message its MAC covers ([`Adapter::verify`]);
//! - its delivery id and event kind, and which deliveries the trigger fires on
//!   ([`Adapter::normalise`], [`Adapter::listens`]);
//! - its fields, as a capped set of stripped text ([`Adapter::normalise`]);
//! - what the trigger document names: the verify secret, a repository, the events ([`Adapter::hook`]).
//!
//! The generic webhook ([`generic`]) and GitHub ([`github`]) are the first two. What every source
//! shares stays in `wicket_core::intake`: HMAC and constant-time comparison, tokens, delivery ids,
//! the caps on fields (`fields_within`) and `keep_text`. A new source (GitLab, Forgejo, a tracker)
//! is a new adapter here, and its `Source` variant in the trigger document; nothing in
//! `wicket_core::intake` changes.

use serde_json::Value;
use std::borrow::Cow;
use std::sync::OnceLock;
use wicket_core::intake::IntakeTrigger;
use wicket_core::trigger::Source;

pub mod generic;
pub mod github;

/// What intake serves of a trigger's source, from its document: the table entry's own parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hook<'a> {
    /// The adapter's kind (the table's `kind`, and the ledger's event source).
    pub kind: &'static str,
    /// The vault secret holding the HMAC key (a `verify` secret).
    pub verify: &'a str,
    /// The repository (or other scope) the source's deliveries must name, if it has one.
    pub repo: Option<String>,
    /// The events listened to, if the source has several.
    pub events: Vec<String>,
}

/// A delivery whose signature verified: what it covered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<'a> {
    /// The sender's delivery id header, as sent (none if it sent none).
    pub delivery: Option<String>,
    /// What the MAC covered: the dedup key's input (its sha256), and the name of a delivery that
    /// came without an id.
    pub message: Cow<'a, [u8]>,
}

/// Why a verified delivery is passed over rather than fired on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unfit {
    /// Not what this source sends (400), counted.
    Malformed(&'static str),
    /// Never fired on, counted: answered 202, so the sender doesn't send it again.
    Refused(&'static str),
    /// An event the trigger doesn't listen to: answered 202, not counted (a hook may send every
    /// event).
    NotListened(&'static str),
}

/// A header of a delivery, by its lower-case name.
pub type Header<'h> = &'h dyn Fn(&str) -> Option<String>;

/// One webhook source. Everything it reads is attacker-written, signed or not: an adapter keeps
/// only fields within `wicket_core::intake::fields_within`, through `keep_text`.
pub trait Adapter: Send + Sync {
    /// Its kind: the table's `kind` and the ledger's event source (`webhook`, `github`).
    fn kind(&self) -> &'static str;

    /// What intake serves of `source`, if it is this adapter's.
    fn hook<'a>(&self, source: &'a Source) -> Option<Hook<'a>>;

    /// Whether the delivery's signature is right under `secret` (at least
    /// `wicket_core::intake::MIN_SECRET` bytes), at `now` (Unix s): what it covered, or none.
    fn verify<'b>(&self, secret: &[u8], header: Header<'_>, body: &'b [u8], now: i64) -> Option<Signed<'b>>;

    /// A verified, new delivery to trigger `t`: its event kind and fields, or why it is passed
    /// over.
    fn normalise(&self, t: &IntakeTrigger, header: Header<'_>, body: &[u8]) -> Result<(String, Value), Unfit>;

    /// On the control host: whether an event of `kind` is one `hook`'s trigger listens to (a node
    /// is trusted as far as its own triggers).
    fn listens(&self, hook: &Hook<'_>, kind: &str) -> bool;
}

/// The adapters intake and the control host know, by kind.
pub struct Adapters(Vec<Box<dyn Adapter>>);

impl Adapters {
    /// The generic webhook and GitHub.
    pub fn builtin() -> Adapters {
        Adapters(vec![Box::new(generic::Generic), Box::new(github::Github)])
    }

    /// These, and `a`. One of a kind already known replaces it.
    pub fn with(mut self, a: impl Adapter + 'static) -> Adapters {
        self.0.retain(|x| x.kind() != a.kind());
        self.0.push(Box::new(a));
        self
    }

    /// The adapter of `kind`, if one is known.
    pub fn by_kind(&self, kind: &str) -> Option<&dyn Adapter> {
        self.0.iter().find(|a| a.kind() == kind).map(|a| &**a)
    }

    /// The adapter of a trigger's source, and what intake serves of it: none for a source no
    /// adapter serves (a schedule, a timer, wicket's own events).
    pub fn for_source<'a>(&self, source: &'a Source) -> Option<(&dyn Adapter, Hook<'a>)> {
        self.0.iter().find_map(|a| a.hook(source).map(|h| (&**a, h)))
    }
}

/// The built-in adapters ([`Adapters::builtin`]), made once.
pub fn builtin() -> &'static Adapters {
    static A: OnceLock<Adapters> = OnceLock::new();
    A.get_or_init(Adapters::builtin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::trigger::Verify;

    #[test]
    fn each_source_has_its_adapter() {
        let verify = || Verify { hmac_sha256: "hook".into() };
        let hook = Source::Webhook { verify: verify() };
        let gh = Source::Github { repo: "acme/app".into(), events: vec!["push".into()], verify: verify() };
        let (a, h) = builtin().for_source(&hook).expect("the generic webhook");
        assert_eq!((a.kind(), h.verify, h.repo, h.events.len()), ("webhook", "hook", None, 0));
        let (a, h) = builtin().for_source(&gh).expect("GitHub");
        assert_eq!((a.kind(), h.repo.as_deref(), h.events), ("github", Some("acme/app"), vec!["push".to_string()]));
        assert!(builtin().for_source(&Source::Wicket { kinds: vec!["run.end".into()] }).is_none());
        assert!(builtin().by_kind("github").is_some() && builtin().by_kind("gitlab").is_none());
    }
}

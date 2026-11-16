//! What a decision is about (#369): the effect descriptor a request asks for and an approval signs
//! ([`descriptor`]), and what else an approval that widens would allow ([`blast_radius`]).
//!
//! The CLI (`wicket approve`), the console and an agent's `decide` all show a decider the request's
//! descriptor with the terms they picked, and [`crate::grant::decide`] makes the grant only if the
//! descriptor it builds from the ledger's row then is the one the decider was shown
//! ([`SHOWN_EFFECT`]): a request that changed in between (who asked, its risk, its arguments) is
//! refused, not granted as something nobody saw. The reason text is not part of the effect: for
//! wicket's own request kinds it is written from the arguments, which are.

use crate::grant::Terms;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;
use wicket_core::effect::{self, Effect};
use wicket_core::ZoneSpec;
use wicket_store::{EgressSeen, Ledger, Request};

/// The key in a decision's `extra` that carries the sha256 of the descriptor the decider was shown.
/// [`crate::grant::decide`] removes it and refuses the decision if it isn't the request's now.
pub const SHOWN_EFFECT: &str = "shown_effect_sha256";

/// How many of the run's latest egress decisions the blast radius counts.
pub const RECENT: usize = 200;

/// The ledger's terms for an approval with `t`.
pub fn decision_terms(t: &Terms) -> wicket_store::DecisionTerms {
    wicket_store::DecisionTerms { uses: t.uses, ttl_secs: t.ttl.as_secs(), prefix: t.prefix.clone(), zone_wide: t.zone_wide }
}

/// The effect descriptor of `req`: as asked (`t` None), or as approving it with terms `t` would
/// grant it ([`wicket_store::descriptor`]).
pub fn descriptor(req: &Request, t: Option<&Terms>) -> Effect {
    wicket_store::descriptor(req, t.map(decision_terms).as_ref())
}

/// What else an approval that widens (#369: a prefix, more than one use, a lifetime over an hour,
/// every run in the zone) would allow, shown before it is made.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Blast {
    /// How it is wider than the one request: one line each.
    pub widens: Vec<String>,
    /// Concrete requests it would also allow: ones the run made (newest first), then examples.
    pub examples: Vec<String>,
    /// The zone's reach rules for the same host: what the run may already do there.
    pub zone_rules: Vec<String>,
    /// Of the run's last `recent` egress decisions, how many it would have covered.
    pub covered: usize,
    pub recent: usize,
}

/// The blast radius of approving `req` with `t`, or None if the approval doesn't widen. `zone` is
/// the run's zone, when it can be read ([`zone_of_run`]).
pub fn blast_radius(l: &Ledger, zone: Option<&ZoneSpec>, req: &Request, t: &Terms) -> Result<Option<Blast>> {
    let e = descriptor(req, Some(t));
    if !e.widens() {
        return Ok(None);
    }
    let terms = e.terms.clone().expect("an approval has terms");
    let mut widens = Vec::new();
    if e.prefix {
        widens.push(format!("every path under {} on {}, not only {}", e.path, e.host, req.path));
    }
    match terms.uses {
        None => widens.push("unlimited uses for its whole lifetime".into()),
        Some(n) if n > 1 => widens.push(format!("{n} uses, not one")),
        _ => {}
    }
    if terms.ttl_secs > effect::WIDE_TTL_SECS {
        widens.push(format!("it lasts {}", humantime::format_duration(std::time::Duration::from_secs(terms.ttl_secs))));
    }
    if terms.scope == "zone" {
        widens.push(format!("any run in zone {}, not only {}", e.zone, e.run));
    }
    let seen = l.recent_egress(&req.run, RECENT)?;
    let covers = |s: &EgressSeen| {
        s.method == e.method && s.host == e.host && if e.prefix { wicket_core::prefix_covers(&e.path, &s.path) } else { s.path == e.path }
    };
    let covered = seen.iter().filter(|s| covers(s)).count();
    let mut examples: Vec<String> = Vec::new();
    for s in seen.iter().filter(|s| covers(s) && s.path != req.path) {
        let x = format!("{} {}{} (made by this run)", s.method, s.host, s.path);
        if !examples.contains(&x) && examples.len() < 5 {
            examples.push(x);
        }
    }
    if e.prefix {
        let dir = e.path.trim_end_matches('/');
        for tail in ["any-file", "any/deeper/path"] {
            examples.push(format!("{} {}{dir}/{tail}", e.method, e.host));
        }
    }
    let zone_rules = zone
        .map(|z| {
            z.reach
                .iter()
                .filter(|r| wicket_core::manifest::host_matches(&r.host, &e.host))
                .map(|r| format!("{} {} {}", r.methods.join(","), r.host, r.paths.join(" ")))
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(Blast { widens, examples, zone_rules, covered, recent: seen.len() }))
}

/// The blast radius as text, for `wicket approve`. Paths and hosts come from audit records a node
/// or a box influenced, so every line is clipped and stripped of terminal escapes (#128).
pub fn render(b: &Blast) -> String {
    let c = |x: &str| wicket_core::text::clip(x, 400);
    let mut out = String::from("This approval is wider than the one request:\n");
    for w in &b.widens {
        out.push_str(&format!("  - {}\n", c(w)));
    }
    if !b.examples.is_empty() {
        out.push_str("It would also allow, for example:\n");
        for x in &b.examples {
            out.push_str(&format!("  - {}\n", c(x)));
        }
    }
    out.push_str(&format!("It would have covered {} of this run's last {} egress requests.\n", b.covered, b.recent));
    if !b.zone_rules.is_empty() {
        out.push_str("The zone already reaches this host by:\n");
        for r in &b.zone_rules {
            out.push_str(&format!("  - {}\n", c(r)));
        }
    }
    out
}

/// Run `run`'s zone, from the feed its node holds (as the console's authority view reads it), if
/// the feed and the installation's authority root can be read here.
pub fn zone_of_run(l: &Ledger, data: &Path, run: &str) -> Option<ZoneSpec> {
    let node = l.run_node(run).ok().flatten().unwrap_or_else(|| crate::localnode::NAME.to_string());
    if node.is_empty() || !node.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        return None;
    }
    let root = crate::roots::authz_root_public().ok()?;
    let st = wicket_feed::read_state::<wicket_feed::BoxAuthority>(&data.join("nodes").join(&node).join("feed"), &node, root).ok()?;
    st.zones.get(run).map(|z| z.spec.zone.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wicket_core::{Op, RunId, TenantId};

    fn terms(uses: Option<u32>, ttl: u64, prefix: Option<&str>, zone_wide: bool) -> Terms {
        Terms { uses, ttl: Duration::from_secs(ttl), prefix: prefix.map(String::from), zone_wide }
    }

    fn setup() -> (Ledger, Request) {
        let l = Ledger::open_in_memory().unwrap();
        let run = RunId("run_a".into());
        let t = TenantId::single();
        let op = Op::egress(&t, &run, "z", "GET", "files.example", "/docs/a");
        let (id, _) = l.pending_for(&op, "", None).unwrap();
        let ev =
            |m: &str, p: &str| serde_json::json!({ "kind": "egress", "method": m, "host": "files.example", "path": p, "outcome": "allow" });
        for (m, p) in [("GET", "/docs/a"), ("GET", "/docs/b"), ("GET", "/docs/c/d"), ("GET", "/other"), ("POST", "/docs/b")] {
            l.audit(&t, Some(&run), "op", &ev(m, p)).unwrap();
        }
        let req = l.request(&id).unwrap();
        (l, req)
    }

    #[test]
    fn the_descriptor_names_what_the_grant_will_be() {
        let (_, req) = setup();
        let asked = descriptor(&req, None);
        assert_eq!((asked.kind.as_str(), asked.path.as_str(), asked.prefix, asked.terms.is_none()), ("access", "/docs/a", false, true));
        let e = descriptor(&req, Some(&terms(Some(1), 600, Some("/docs"), false)));
        assert_eq!((e.path.as_str(), e.prefix), ("/docs/", true));
        assert_eq!(e.terms.as_ref().map(|t| (t.uses, t.ttl_secs, t.scope.as_str())), Some((Some(1), 600, "run")));
        // Other terms are another effect.
        assert_ne!(e.sha256(), descriptor(&req, Some(&terms(Some(2), 600, Some("/docs"), false))).sha256());
    }

    #[test]
    fn a_narrow_approval_has_no_blast_radius_and_a_wide_one_shows_what_it_covers() {
        let (l, req) = setup();
        assert_eq!(blast_radius(&l, None, &req, &terms(Some(1), 600, None, false)).unwrap(), None);
        let zone: ZoneSpec =
            serde_yaml::from_str("name: z\nreach:\n  - host: files.example\n    paths: [/docs/public/**]\n  - host: other.example\n")
                .unwrap();
        let b = blast_radius(&l, Some(&zone), &req, &terms(None, 7200, Some("/docs"), true)).unwrap().expect("it widens");
        assert_eq!(b.widens.len(), 4, "{b:?}");
        assert_eq!((b.covered, b.recent), (3, 5), "GET /docs/a, /docs/b and /docs/c/d, not /other or the POST");
        assert_eq!(b.examples[..2], ["GET files.example/docs/c/d (made by this run)", "GET files.example/docs/b (made by this run)"]);
        assert!(b.examples.iter().any(|x| x == "GET files.example/docs/any/deeper/path"), "{b:?}");
        assert_eq!(b.zone_rules, vec!["GET,HEAD files.example /docs/public/**".to_string()]);
        let mut hostile = b.clone();
        hostile.examples.push("GET h/\u{1b}]0;x\u{7}\u{202e}".into());
        assert!(render(&hostile).chars().all(|c| c == '\n' || !wicket_core::text::is_unsafe(c)), "no escapes reach the terminal");
        let text = render(&b);
        assert!(text.contains("every path under /docs/ on files.example") && text.contains("3 of this run's last 5"), "{text}");
        // More uses of the one path: what the run sent there.
        let b = blast_radius(&l, None, &req, &terms(Some(5), 600, None, false)).unwrap().unwrap();
        assert_eq!((b.widens, b.covered), (vec!["5 uses, not one".to_string()], 1));
    }
}

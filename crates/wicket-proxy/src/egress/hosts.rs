//! Judging a host before any request to it: never-reachable and hidden hosts, unregistered domains
//! (#19), wildcard reach (#20), spin detection, and malformed-request refusals. Part of
//! [`super::Egress`], split out of `egress.rs` (#220).

use super::*;

impl Egress {
    /// Decides about a host before any request to it (and before TLS): never-reachable hosts are
    /// refused, saying so; in zones that hide unlisted hosts, they behave as if they didn't exist.
    pub(crate) fn judge_host(&self, host: &str, method: &str) -> Option<Response<BoxBody>> {
        match self.decider.host_verdict(&self.ctx, host) {
            wicket_core::HostVerdict::Open => None,
            wicket_core::HostVerdict::Forbidden(why) => {
                self.ctx.emit(Event::Egress {
                    method: method.into(),
                    host: host.into(),
                    path: "/".into(),
                    risk: "-".into(),
                    outcome: "forbidden".into(),
                    detail: why.clone(),
                });
                let note = self.strike(&format!("host {host}"));
                Some(problem(403, "forbidden", "Blocked by wicket sandbox: never allowed", &format!(
                    "{why}. This will never be allowed from this sandbox, and no approval can change that. {} Do not retry it; tell the user it is blocked.{note}",
                    crate::SANDBOX_FACT
                ), None))
            }
            wicket_core::HostVerdict::Hidden => {
                self.ctx.emit(Event::Egress {
                    method: method.into(),
                    host: host.into(),
                    path: "/".into(),
                    risk: "-".into(),
                    outcome: "hidden".into(),
                    detail: "not a host this zone can see".into(),
                });
                let note = self.strike(&format!("host {host}"));
                Some(problem(502, "unknown-host", "wicket sandbox: unknown host", &format!(
                    "{host} does not exist as far as this sandbox is concerned: it can only see the hosts its zone names. {} Do not retry it.{note}",
                    crate::SANDBOX_FACT
                ), None))
            }
        }
    }

    /// In an `escalate` zone, a host the zone doesn't name whose registered domain doesn't exist is an
    /// unknown host, not a pending request (#19). Only the registered domain is ever looked up (see
    /// [`crate::exists`]); when that can't be had, the host escalates as before.
    pub(crate) async fn judge_unlisted(&self, host: &str, method: &str) -> Option<Response<BoxBody>> {
        if !self.ctx.escalate || self.ctx.zone.spec().names_host(host) {
            return None;
        }
        let domain = crate::exists::registered_domain(host)?;
        if self.domain_exists(&domain).await != crate::exists::Exists::No {
            return None;
        }
        self.ctx.emit(Event::Egress {
            method: method.into(),
            host: host.into(),
            path: "/".into(),
            risk: "-".into(),
            outcome: "hidden".into(),
            detail: format!("unknown host: its registered domain {domain} does not exist (NXDOMAIN)"),
        });
        let note = self.strike(&format!("host {host}"));
        Some(problem(
            502,
            "unknown-host",
            "wicket sandbox: unknown host",
            &format!(
                "{host} does not exist: there is no domain {domain}. Check the name for a typo. {} Do not retry it.{note}",
                crate::SANDBOX_FACT
            ),
            None,
        ))
    }

    /// Whether `domain` (a registered domain) exists, asked once per run.
    pub(super) async fn domain_exists(&self, domain: &str) -> crate::exists::Exists {
        use crate::exists::Exists;
        {
            let g = self.registered.lock().expect("registered");
            if let Some(e) = g.get(domain) {
                return *e;
            }
            if g.len() >= MAX_DOMAIN_CHECKS {
                return Exists::Unknown;
            }
        }
        let found = match self.upstream.domains.get(domain) {
            Some(true) => Exists::Yes,
            Some(false) => Exists::No,
            None => crate::exists::check(domain).await,
        };
        let mut g = self.registered.lock().expect("registered");
        if g.len() < MAX_DOMAIN_CHECKS {
            g.insert(domain.to_string(), found);
        }
        found
    }

    /// The registered domains this run has looked up, sorted (tests, #19).
    pub fn domains_checked(&self) -> Vec<String> {
        let mut v: Vec<String> = self.registered.lock().expect("registered").keys().cloned().collect();
        v.sort();
        v
    }

    /// Whether `host` may be dialled before a request to it is decided: true unless it is reached
    /// through a wildcard reach rule and hasn't yet had an allowed request this run (#20).
    pub(crate) fn wildcard_reached(&self, host: &str) -> bool {
        match self.ctx.zone.spec().wildcard_for(host) {
            None => true,
            Some(w) => self.wild.lock().expect("wild").get(&w.to_ascii_lowercase()).is_some_and(|names| names.contains(host)),
        }
    }

    /// Admits an allowed request's host under its wildcard reach rule (#20): a name already reached
    /// passes; a new one counts against the zone's `wildcards.max_names` for that rule, and past it
    /// the request is refused before anything is resolved. None to go ahead.
    pub(super) fn admit_wildcard(&self, host: &str) -> Option<(String, String)> {
        let spec = self.ctx.zone.spec();
        let w = spec.wildcard_for(host)?;
        let max = spec.wildcards.max_names as usize;
        let mut g = self.wild.lock().expect("wild");
        let names = g.entry(w.to_ascii_lowercase()).or_default();
        if names.contains(host) {
            return None;
        }
        if names.len() >= max {
            return Some((w.to_string(), format!("this run has already reached {max} distinct names under {w}, the zone's limit (wildcards.max_names); {host} would be one more")));
        }
        names.insert(host.to_string());
        None
    }

    /// Counts a blocked attempt and returns a note for the agent once it starts repeating itself: the
    /// point is that an agent at the edge of its sandbox stops and asks, rather than spinning.
    pub(crate) fn strike(&self, key: &str) -> String {
        let (same, total) = {
            let mut s = self.strikes.lock().expect("strikes");
            let same = {
                let n = s.0.entry(key.to_string()).or_insert(0);
                *n += 1;
                *n
            };
            s.1 += 1;
            (same, s.1)
        };
        if total == 10 || (total > 10 && total % 10 == 0) {
            self.ctx
                .emit(Event::Tool { name: "wicket".into(), detail: format!("agent may be stuck: {total} blocked requests in this run") });
        }
        let mut note = String::new();
        if same >= 3 {
            note.push_str(&format!(" This exact request has now been blocked {same} times: stop retrying it."));
        }
        if total >= 10 {
            note.push_str(&format!(" This run has hit the sandbox's limits {total} times. Stop exploring alternatives: tell the user what you need, or call request_access once with a reason."));
        }
        note
    }

    pub(crate) fn refuse(&self, host: &str, method: &str, path: &str, why: &str) -> Response<BoxBody> {
        self.ctx.emit(Event::Egress {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            risk: "-".into(),
            outcome: "forbidden".into(),
            detail: why.into(),
        });
        problem(403, "forbidden", "Blocked by wicket sandbox: malformed request", &format!("{why}. {}", crate::SANDBOX_FACT), None)
    }
}

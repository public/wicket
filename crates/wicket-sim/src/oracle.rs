//! The oracle: what really happened (outside the simulated network, on the simulation's true
//! clock), and the invariants from #321 checked against it as the hosts act.
//!
//! - **No egress allow without a live grant.** An op that needs a grant is allowed only by a grant
//!   that was issued for exactly that op and box. The allow must come before the grant's lifetime
//!   ends by the node's clock, cut off or not: the token's grant check is `time <= not_after`, in
//!   Unix seconds, so it ends at `(not_after + 1) * 1000` ms. A node that holds the delta revoking
//!   the grant never allows by it. A fresh node does so for at most one statement TTL (plus clock
//!   skew) after the revocation: a fresh node holds every epoch a live statement names. A forbidden
//!   op, or one no grant covers, is never allowed.
//! - **Model spend within the run's budget**, across slices, crashes and reconnections. This is
//!   what the stand-in upstream billed (requests, output tokens), not what any proxy counted.

use std::collections::BTreeMap;
use wicket_feed::{Allowed, Decision, Mode};
use wicket_proxy::llm::ModelQuota;

/// How an op stands in the run's zone, by construction of the scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpClass {
    /// Allowed by the zone's reach (and so by block 0's ceiling).
    Reach,
    /// Needs a grant: the scenario issues grants for some of these.
    NeedsGrant,
    /// Forbidden by the zone.
    Forbidden,
}

#[derive(Clone, Debug, Default)]
struct GrantTruth {
    run: String,
    path: String,
    /// (true time it was published, the lifetime it was published with, Unix seconds), in order.
    versions: Vec<(i64, u64)>,
    /// (true time, the epoch whose delta carries it).
    revoked: Option<(i64, u64)>,
}

#[derive(Clone, Debug, Default)]
pub struct Billed {
    pub requests: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub allowed_reach: u64,
    pub allowed_grant: u64,
    pub allowed_offline_by_grant: u64,
    pub needs_grant: u64,
    pub refused: u64,
    pub forbidden: u64,
    pub model_ok: u64,
    pub model_refused: u64,
    pub model_lost: u64,
    pub node_starts: u64,
    pub control_starts: u64,
    pub connections: u64,
    pub feed_refusals: u64,
    pub grant_actions: u64,
}

pub struct Oracle {
    pub violations: Vec<String>,
    pub stats: Stats,
    pub billed: BTreeMap<String, Billed>,
    quota: ModelQuota,
    grants: BTreeMap<String, GrantTruth>,
    ttl_ms: i64,
    max_skew_ms: i64,
    trace: Vec<String>,
    hash: u64,
    keep_trace: bool,
}

impl Oracle {
    pub fn new(quota: ModelQuota, ttl_ms: i64, max_skew_ms: i64, keep_trace: bool) -> Oracle {
        Oracle {
            violations: vec![],
            stats: Stats::default(),
            billed: BTreeMap::new(),
            quota,
            grants: BTreeMap::new(),
            ttl_ms,
            max_skew_ms,
            trace: vec![],
            hash: 0xcbf2_9ce4_8422_2325,
            keep_trace,
        }
    }

    /// Records one line of the trace: hashed always (for the determinism check), kept if asked.
    pub fn note(&mut self, t: i64, line: impl Into<String>) {
        let line = format!("{t} {}", line.into());
        for b in line.bytes().chain(std::iter::once(b'\n')) {
            self.hash ^= u64::from(b);
            self.hash = self.hash.wrapping_mul(0x0100_0000_01b3);
        }
        if self.keep_trace {
            self.trace.push(line);
        }
    }

    pub fn hash(&self) -> u64 {
        self.hash
    }

    pub fn trace(&self) -> &[String] {
        &self.trace
    }

    fn violate(&mut self, t: i64, what: String) {
        self.note(t, format!("VIOLATION {what}"));
        self.violations.push(format!("at {} ms: {what}", t - crate::EPOCH_MS));
    }

    /// The control host published grant `gid` (for `run`'s `path`) with lifetime `not_after_s`.
    pub fn published(&mut self, t: i64, gid: &str, run: &str, path: &str, not_after_s: u64) {
        let g = self.grants.entry(gid.into()).or_default();
        g.run = run.into();
        g.path = path.into();
        g.versions.push((t, not_after_s));
        self.stats.grant_actions += 1;
        self.note(t, format!("publish {gid} {run} {path} until {not_after_s}"));
    }

    /// The control host revoked `gid` in the delta of `epoch`.
    pub fn revoked(&mut self, t: i64, gid: &str, epoch: u64) {
        let g = self.grants.entry(gid.into()).or_default();
        g.revoked.get_or_insert((t, epoch));
        self.stats.grant_actions += 1;
        self.note(t, format!("revoke {gid} epoch {epoch}"));
    }

    /// The node decided `run`'s op at true time `t` (its own clock: `node_now`), in `mode`, holding
    /// `epoch`.
    #[allow(clippy::too_many_arguments)]
    pub fn decided(&mut self, t: i64, node_now: i64, run: &str, class: OpClass, path: &str, d: &Decision, mode: Mode, epoch: Option<u64>) {
        self.note(t, format!("decide {run} {path} {mode:?} {epoch:?} -> {}", short(d)));
        match d {
            Decision::Allow(a) => {
                if class == OpClass::Forbidden {
                    self.violate(t, format!("{run}: forbidden op {path} allowed ({a:?})"));
                }
                match a {
                    Allowed::Grant(gid) => {
                        self.stats.allowed_grant += 1;
                        if mode == Mode::Offline {
                            self.stats.allowed_offline_by_grant += 1;
                        }
                        self.check_grant(t, node_now, run, path, gid, mode, epoch);
                    }
                    _ if class == OpClass::NeedsGrant => {
                        self.violate(t, format!("{run}: {path} needs a grant, allowed without one ({a:?})"));
                    }
                    _ => self.stats.allowed_reach += 1,
                }
            }
            Decision::NeedsGrant(_) => self.stats.needs_grant += 1,
            Decision::Forbidden(_) => self.stats.forbidden += 1,
            Decision::Refused { .. } => self.stats.refused += 1,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_grant(&mut self, t: i64, node_now: i64, run: &str, path: &str, gid: &str, mode: Mode, epoch: Option<u64>) {
        let Some(g) = self.grants.get(gid).cloned() else {
            return self.violate(t, format!("{run}: {path} allowed by grant {gid}, never issued"));
        };
        if g.run != run || g.path != path {
            return self.violate(t, format!("{run}: {path} allowed by grant {gid}, issued for {} {}", g.run, g.path));
        }
        // The lifetime the node could have seen: the latest version published before now.
        let Some(&(_, not_after_s)) = g.versions.iter().rev().find(|(at, _)| *at <= t) else {
            return self.violate(t, format!("{run}: {path} allowed by grant {gid} before it was published"));
        };
        let max_na = g.versions.iter().filter(|(at, _)| *at <= t).map(|(_, na)| *na).max().unwrap_or(not_after_s);
        let end = (max_na as i64 + 1) * 1000;
        if node_now >= end {
            self.violate(t, format!("{run}: {path} allowed by grant {gid} at node time {node_now}, past its lifetime (ends {end})"));
        }
        if let Some((t_r, e_r)) = g.revoked {
            if t_r <= t {
                if epoch.is_some_and(|e| e >= e_r) {
                    self.violate(t, format!("{run}: {path} allowed by grant {gid} on a node holding its revocation (epoch {e_r})"));
                }
                if mode == Mode::Fresh && t > t_r + self.ttl_ms + self.max_skew_ms + 5 {
                    self.violate(t, format!("{run}: {path} allowed by grant {gid} on a fresh node {} ms after its revocation", t - t_r));
                }
            }
        }
    }

    /// The stand-in upstream served (and billed) one model call.
    pub fn billed(&mut self, t: i64, run: &str, output: u64) {
        let b = self.billed.entry(run.into()).or_default();
        b.requests += 1;
        b.output_tokens += output;
        let (r, o) = (b.requests, b.output_tokens);
        self.note(t, format!("bill {run} {output} (total {r} requests, {o} output tokens)"));
        // Reported once per run and kind: the first call past the budget.
        if r == self.quota.requests + 1 {
            self.violate(t, format!("{run}: {r} model requests billed, budget {}", self.quota.requests));
        }
        if o > self.quota.output_tokens && o - output <= self.quota.output_tokens {
            self.violate(t, format!("{run}: {o} output tokens billed, budget {}", self.quota.output_tokens));
        }
    }
}

fn short(d: &Decision) -> String {
    match d {
        Decision::Allow(a) => format!("allow {a:?}"),
        Decision::NeedsGrant(_) => "needs-grant".into(),
        Decision::Forbidden(_) => "forbidden".into(),
        Decision::Refused { mode, .. } => format!("refused {mode:?}"),
    }
}

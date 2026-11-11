//! The money envelope (design §8.5) and the human approval hook.

use crate::money::MicroUsd;
use crate::model::{NodeHandle, Timestamp};
use std::future::Future;

/// The limits no approval can widen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoneyEnvelope {
    /// The most every owned node together may cost per hour.
    pub max_hourly: MicroUsd,
    /// The most every owned node together may cost over its lease, the new node at its worst case.
    pub max_total: MicroUsd,
}

/// Why the envelope refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeRefusal {
    Hourly { committed: MicroUsd, new: MicroUsd, max: MicroUsd },
    Total { committed: MicroUsd, new: MicroUsd, max: MicroUsd },
}

impl std::fmt::Display for EnvelopeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeRefusal::Hourly { committed, new, max } => {
                write!(f, "{committed}/h already running + {new}/h for this node is over the {max}/h limit")
            }
            EnvelopeRefusal::Total { committed, new, max } => {
                write!(f, "{committed} committed + {new} worst case for this node is over the {max} total limit")
            }
        }
    }
}

/// What owned nodes already commit: their summed hourly rate, and their cost through their lease end
/// (or through the current hour, for a node without a lease tag).
pub fn committed(nodes: &[NodeHandle], now: Timestamp) -> (MicroUsd, MicroUsd) {
    let hourly = nodes.iter().map(|n| n.billing.hourly_rate()).sum();
    let total = nodes.iter().map(|n| n.billed_through(n.lease_until.unwrap_or(now).max(now))).sum();
    (hourly, total)
}

impl MoneyEnvelope {
    pub fn check(&self, committed: (MicroUsd, MicroUsd), hourly: MicroUsd, worst_case: MicroUsd) -> Result<(), EnvelopeRefusal> {
        let (c_hourly, c_total) = committed;
        if c_hourly + hourly > self.max_hourly {
            return Err(EnvelopeRefusal::Hourly { committed: c_hourly, new: hourly, max: self.max_hourly });
        }
        if c_total + worst_case > self.max_total {
            return Err(EnvelopeRefusal::Total { committed: c_total, new: worst_case, max: self.max_total });
        }
        Ok(())
    }
}

/// What a human is asked to approve: everything on the approval card.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SpendRequest {
    pub backend: String,
    pub plan: String,
    pub region: Option<String>,
    pub node_name: String,
    pub purpose: String,
    pub hourly: MicroUsd,
    pub lifetime_secs: i64,
    /// Reserved before creating: the most this node can cost over `lifetime_secs`.
    pub worst_case: MicroUsd,
    pub committed_hourly: MicroUsd,
    pub committed_total: MicroUsd,
    pub max_hourly: MicroUsd,
    pub max_total: MicroUsd,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approval {
    Approved,
    Denied(String),
}

/// The human in the loop for anything with a money effect. The CLI asks on the terminal; the console
/// will show a card. Called only for requests already inside the envelope.
pub trait SpendApprover: Send + Sync {
    fn approve(&self, req: &SpendRequest) -> impl Future<Output = Approval> + Send;
}

/// Approves nothing: the default where no human is reachable.
pub struct DenyAll;

impl SpendApprover for DenyAll {
    async fn approve(&self, _req: &SpendRequest) -> Approval {
        Approval::Denied("no approver is configured".into())
    }
}

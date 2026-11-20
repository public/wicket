//! Spend approval: the hook every node with a money effect goes through before it is used.
//!
//! The money check itself is wicket's, in the ledger (#256: one tenant money quota grant, and the
//! live money quota grants against it, `wicket_store::money`), made by the [`SpendApprover`] in the
//! transaction that records the node's money. This crate holds no limits of its own.

use crate::money::MicroUsd;
use std::future::Future;

/// What is asked before a node is used: everything on the approval card.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SpendRequest {
    pub backend: String,
    pub plan: String,
    pub region: Option<String>,
    pub node_name: String,
    pub purpose: String,
    pub hourly: MicroUsd,
    pub lifetime_secs: i64,
    /// Reserved before using it: the most this node can cost over `lifetime_secs`.
    pub worst_case: MicroUsd,
    /// A warm node from the pool (already made, its current hour paid for), not a new one.
    pub warm: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approval {
    Approved,
    /// Refused: an operator said no, or it is over a limit.
    Denied(String),
    /// Nobody decided in time (or there was no time to wait): it needs an approval it didn't get.
    Undecided(String),
    /// Asking failed (the ledger, the request): no decision was made.
    Failed(String),
}

impl Approval {
    /// The error a spend that wasn't approved is (None: it was).
    pub fn refusal(self) -> Option<crate::PlacementError> {
        match self {
            Approval::Approved => None,
            Approval::Denied(why) => Some(crate::PlacementError::NotApproved(why)),
            Approval::Undecided(why) => Some(crate::PlacementError::Undecided(why)),
            Approval::Failed(why) => Some(crate::PlacementError::ApprovalFailed(why)),
        }
    }
}

/// Who decides anything with a money effect, and checks its money (#256): a capacity lease's
/// approver (its money was reserved when it was asked for), and `wicket node create`'s, which
/// reserves the node's money and files a CAPACITY request decided by the operator's standing
/// capacity grants or, beyond them, by an operator. Called for every paid offer and every warm
/// node claimed from the pool.
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

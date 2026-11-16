//! A test double for the egress proxy's decision source: the run's compiled zone, then a grant the
//! ledger issued for the op, else a pending request (or a recent denial). It stands in for the
//! node's feed replica in tests of the proxy itself (TLS, canonical paths, forwarding, the problem
//! texts), where a feed would only be scaffolding. It is not a decision path: since #257's slice 3
//! wicket decides egress on the node only (`decide::NodeDecider`), and the ledger never counts an
//! egress grant's uses, so neither does this.
//!
//! Shared by the crate's unit tests and its integration tests (`#[path]`), through public items
//! only.

use futures_util::future::BoxFuture;
use wicket_core::{HostVerdict, Op, Verdict};
use wicket_proxy::decide::{Decider, Outcome};
use wicket_proxy::RunCtx;

pub struct ZoneDecider;

impl Decider for ZoneDecider {
    fn host_verdict(&self, ctx: &RunCtx, host: &str) -> HostVerdict {
        ctx.zone.host_verdict(host)
    }

    fn decide<'a>(&'a self, ctx: &'a RunCtx, op: &'a Op, who: Option<&'a (serde_json::Value, String)>) -> BoxFuture<'a, Outcome> {
        Box::pin(async move { decide(ctx, op, who) })
    }

    /// The zone alone decides; under an org policy, only a host it allows wholesale.
    fn splice(&self, ctx: &RunCtx, host: &str) -> Option<usize> {
        if ctx.org.as_ref().is_some_and(|o| !o.allows_host_wholesale(host)) {
            return None;
        }
        match wicket_core::splice::inspection(ctx.zone.spec(), host) {
            wicket_core::splice::Inspection::Spliced { rule } => Some(rule),
            wicket_core::splice::Inspection::Inspected(_) => None,
        }
    }
}

fn decide(ctx: &RunCtx, op: &Op, who: Option<&(serde_json::Value, String)>) -> Outcome {
    if let Some(why) = ctx.org.as_ref().and_then(|o| o.refuses_http(&op.host, &op.method, &op.path, op.risk.rank())) {
        return Outcome::Forbidden(why);
    }
    let why = match ctx.zone.evaluate(op) {
        Verdict::AllowByReach(i) => return Outcome::Allow(format!("reach rule {i}")),
        Verdict::Forbidden(why) => return Outcome::Forbidden(why),
        Verdict::NeedsGrant(why) if !ctx.escalate => return Outcome::NoEscalation(why),
        Verdict::NeedsGrant(why) => wicket_core::git::ask_reason(op, &why),
    };
    let ledger = ctx.ledger.lock().expect("ledger lock");
    match ledger.grant_covering(op) {
        Ok(Some(gid)) => Outcome::Allow(format!("grant {gid}")),
        Ok(None) => {
            if let Ok(Some(rid)) = ledger.denied_recently(op) {
                return Outcome::Denied { request: rid };
            }
            match ledger.pending_for(op, &why, who.map(|(v, _)| v)) {
                Ok((rid, fresh)) => Outcome::Pending { request: rid, fresh, why },
                Err(e) => Outcome::Error(e.to_string()),
            }
        }
        Err(e) => Outcome::Error(e.to_string()),
    }
}

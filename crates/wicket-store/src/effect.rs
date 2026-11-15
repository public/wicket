//! Requests and grants bound to their effect (#369).
//!
//! - **Hold until decided.** While a request from a run is pending, the run's related asks don't
//!   file requests of their own that could be decided apart from it, and its actions on that
//!   effect don't run: an ask for the same target with other arguments, or an egress request a
//!   pending prefix ask covers, is answered with the pending request ([`Filed::Held`]), and a
//!   granted action waits while another request for its target is pending ([`EffectUse::Held`]).
//! - **Effect binding.** A grant for a reserved request kind (spawn, link, capacity, update) is
//!   used only for exactly its target and the arguments it was decided on
//!   ([`Ledger::use_effect_grant`]): never through a prefix, and an action whose arguments changed
//!   after the approval is refused and audited (`effect.refused`).
//! - **Exactly once.** An action presented again after its grant's last use finds it spent
//!   ([`EffectUse::Spent`]), instead of filing a new request.

use crate::{now, Ledger, Result};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use wicket_core::{Op, RunId, TenantId};

/// What filing a request for an op did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filed {
    /// A new pending request.
    New(String),
    /// The same request was already pending (a retry).
    Existing(String),
    /// A related request from the same run is pending: nothing was filed, and the ask waits on
    /// that request's decision (#369).
    Held { pending: String },
}

impl Filed {
    /// The request the asker is told to wait for.
    pub fn id(&self) -> &str {
        match self {
            Filed::New(id) | Filed::Existing(id) | Filed::Held { pending: id } => id,
        }
    }
}

/// What looking for a grant for a reserved action found ([`Ledger::use_effect_grant`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectUse {
    /// A grant for exactly this effect and these arguments; one use was taken.
    Granted(String),
    /// A request from this run for this target is pending: the action waits for its decision.
    Held { pending: String },
    /// A live grant for this target was decided on other arguments: refused, and audited.
    ArgsChanged { grant: String },
    /// The grant for exactly this was used up: the action already ran.
    Spent { grant: String },
    /// No grant: ask.
    None,
}

/// One egress decision a run's audit trail records (what the blast radius counts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressSeen {
    pub method: String,
    pub host: String,
    pub path: String,
    pub outcome: String,
}

/// The terms a decision approves a request with, as [`descriptor`] reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionTerms {
    /// None: unlimited uses until it expires.
    pub uses: Option<u32>,
    pub ttl_secs: u64,
    /// The prefix the decider grants instead of the exact path, if any.
    pub prefix: Option<String>,
    pub zone_wide: bool,
}

/// The effect descriptor of `req` (#369): as asked (`t` None), or as approving it with terms `t`
/// would grant it: the path or prefix, uses and lifetime [`Ledger::approve`] then records. The CLI,
/// the console and an agent's `decide` show it, and the decision is made only on it.
pub fn descriptor(req: &crate::Request, t: Option<&DecisionTerms>) -> wicket_core::effect::Effect {
    use wicket_core::effect;
    let (path, prefix, terms) = match t {
        None => (req.path.clone(), req.scope_prefix, None),
        Some(t) => {
            let (path, prefix) = crate::granted_scope(req, t.prefix.as_deref());
            let (uses, ttl_secs) = wicket_core::git::grant_terms(&req.method, &path, t.uses, t.ttl_secs);
            let scope = if t.zone_wide { "zone" } else { "run" };
            (path, prefix, Some(effect::Terms { uses, ttl_secs, scope: scope.into() }))
        }
    };
    effect::Effect {
        v: 1,
        kind: effect::kind_of(&req.method),
        tenant: req.tenant.clone(),
        zone: req.zone.clone(),
        run: req.run.clone(),
        requested_by: req.attribution.iter().flat_map(requesters).collect(),
        method: req.method.clone(),
        host: req.host.clone(),
        path,
        prefix,
        args_sha256: req.args_sha256.clone(),
        terms,
    }
}

/// The agents an attribution object names (its `requesters[].agent`).
pub fn requesters(v: &serde_json::Value) -> Vec<String> {
    v.get("requesters")
        .and_then(|r| r.as_array())
        .map(|rs| rs.iter().filter_map(|r| r.get("agent").and_then(|a| a.as_str()).map(String::from)).collect())
        .unwrap_or_default()
}

impl Ledger {
    /// Records a pending request for `op` asked with arguments hashed `args` (#369), or returns
    /// the one already pending; or, while a related request from the same run is pending, files
    /// nothing ([`Filed::Held`]). Related: the same target asked with other arguments, or (for an
    /// egress request) a pending prefix ask from the run that covers it.
    pub fn file_request(&self, op: &Op, args: Option<&str>, reason: &str, who: Option<&serde_json::Value>) -> Result<Filed> {
        if let Some(pending) = self.held_by(op, args)? {
            return Ok(Filed::Held { pending });
        }
        let (id, fresh) = self.pending_for_unheld(op, reason, who)?;
        if !fresh {
            return Ok(Filed::Existing(id));
        }
        if args.is_some() {
            self.conn.execute("UPDATE requests SET args_sha256 = ?2 WHERE id = ?1", params![id, args])?;
        }
        Ok(Filed::New(id))
    }

    /// Returns the id of the pending request for `op` (without arguments), creating it if needed:
    /// deduplicated on the op digest, so a retrying agent doesn't flood the queue, and held on a
    /// related pending request ([`Ledger::file_request`]). `who` is the attribution of this ask;
    /// when a *different* asker hits an existing request, it is added, so the human sees everyone a
    /// grant would serve. The bool is whether a new request was filed.
    pub fn pending_for(&self, op: &Op, reason: &str, who: Option<&serde_json::Value>) -> Result<(String, bool)> {
        let f = self.file_request(op, None, reason, who)?;
        Ok((f.id().to_string(), matches!(f, Filed::New(_))))
    }

    /// The pending request from `op`'s run that an ask for `op` with `args` must wait on, if any.
    fn held_by(&self, op: &Op, args: Option<&str>) -> Result<Option<String>> {
        let same_target = self
            .conn
            .query_row(
                "SELECT id FROM requests WHERE tenant = ?1 AND zone = ?2 AND run = ?3 AND method = ?4 AND host = ?5
                   AND path = ?6 AND status = 'pending' AND scope_prefix = 0 AND COALESCE(args_sha256, '') <> COALESCE(?7, '')
                 ORDER BY created_at, id LIMIT 1",
                params![op.tenant.0, op.zone, op.run.0, op.method, op.host, op.path, args],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        if same_target.is_some() || op.is_reserved() {
            return Ok(same_target);
        }
        let mut st = self.conn.prepare(
            "SELECT id, path FROM requests WHERE tenant = ?1 AND zone = ?2 AND run = ?3 AND method = ?4 AND host = ?5
               AND status = 'pending' AND scope_prefix = 1 ORDER BY created_at, id",
        )?;
        let rows = st.query_map(params![op.tenant.0, op.zone, op.run.0, op.method, op.host], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (id, prefix) = row?;
            if wicket_core::prefix_covers(&prefix, &op.path) {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Finds the grant a reserved action (spawn, link, capacity, update) runs under, and takes one
    /// use, atomically (#369): a live grant for exactly `op`'s target (never a prefix), bound to its
    /// run unless zone-wide, decided on exactly the arguments hashed `args`. A grant for the target
    /// decided on other arguments refuses the action, and the refusal is audited
    /// (`effect.refused`); a request for the target still pending holds it.
    pub fn use_effect_grant(&mut self, op: &Op, args: Option<&str>) -> Result<EffectUse> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending: Option<String> = tx
            .query_row(
                "SELECT id FROM requests WHERE tenant = ?1 AND zone = ?2 AND run = ?3 AND method = ?4 AND host = ?5
                   AND path = ?6 AND status = 'pending' ORDER BY created_at, id LIMIT 1",
                params![op.tenant.0, op.zone, op.run.0, op.method, op.host, op.path],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(pending) = pending {
            tx.commit()?;
            return Ok(EffectUse::Held { pending });
        }
        let rows: Vec<(String, Option<i64>, Option<String>)> = {
            let mut st = tx.prepare(
                "SELECT id, uses_left, args_sha256 FROM grants
                 WHERE tenant = ?1 AND zone = ?2 AND method = ?3 AND host = ?4 AND path = ?5 AND prefix = 0
                   AND revoked = 0 AND expires_at > ?6 AND amount IS NULL AND node IS NULL
                   AND (run IS NULL OR run = ?7) AND COALESCE(max_risk, 0) >= ?8
                 ORDER BY created_at, id",
            )?;
            let rows = st.query_map(params![op.tenant.0, op.zone, op.method, op.host, op.path, now(), op.run.0, op.risk.rank()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let usable = |u: &Option<i64>| u.is_none_or(|n| n > 0);
        let found = if let Some((gid, uses, _)) = rows.iter().find(|(_, u, a)| usable(u) && a.as_deref() == args) {
            if uses.is_some() {
                tx.execute("UPDATE grants SET uses_left = uses_left - 1 WHERE id = ?1", params![gid])?;
            }
            EffectUse::Granted(gid.clone())
        } else if let Some((gid, _, _)) = rows.iter().find(|(_, u, _)| usable(u)) {
            EffectUse::ArgsChanged { grant: gid.clone() }
        } else if let Some((gid, _, _)) = rows.iter().find(|(_, _, a)| a.as_deref() == args) {
            EffectUse::Spent { grant: gid.clone() }
        } else {
            EffectUse::None
        };
        tx.commit()?;
        if let EffectUse::ArgsChanged { grant } = &found {
            let approved: Option<String> = rows.iter().find(|(g, _, _)| g == grant).and_then(|(_, _, a)| a.clone());
            self.audit(
                &TenantId(op.tenant.0.clone()),
                Some(&RunId(op.run.0.clone())),
                "effect.refused",
                &serde_json::json!({
                    "grant": grant, "method": op.method, "host": op.host, "path": op.path,
                    "approved_args_sha256": approved, "presented_args_sha256": args,
                    "why": "the arguments changed after the approval",
                }),
            )?;
        }
        Ok(found)
    }

    /// Records the hash of the effect descriptor grant `gid` was approved as (#369).
    pub fn bind_grant_effect(&self, gid: &str, effect_sha256: &str) -> Result<()> {
        self.conn.execute("UPDATE grants SET effect_sha256 = ?2 WHERE id = ?1", params![gid, effect_sha256])?;
        Ok(())
    }

    /// The effect descriptor hash and argument hash grant `gid` was approved with.
    pub fn grant_effect(&self, gid: &str) -> Result<Option<(Option<String>, Option<String>)>> {
        Ok(self
            .conn
            .query_row("SELECT effect_sha256, args_sha256 FROM grants WHERE id = ?1", params![gid], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }

    /// The last `limit` egress decisions recorded for `run`, newest first: the proxy's own (`op`)
    /// and a node's (`node.audit`, whose body carries the decision as a JSON string).
    pub fn recent_egress(&self, run: &str, limit: usize) -> Result<Vec<EgressSeen>> {
        // Other `op` records (spawns, links) are skipped, so rows are read until `limit` decisions.
        let mut st = self.conn.prepare("SELECT kind, body FROM audit WHERE run = ?1 AND kind IN ('op', 'node.audit') ORDER BY seq DESC")?;
        let rows = st.query_map(params![run], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            if out.len() >= limit {
                break;
            }
            let (kind, body) = row?;
            let Ok(b) = serde_json::from_str::<serde_json::Value>(&body) else { continue };
            let d = match kind.as_str() {
                "node.audit" => match b["body"].as_str().and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()) {
                    Some(d) => d,
                    None => continue,
                },
                _ => b,
            };
            if d["kind"] != "egress" {
                continue;
            }
            let s = |k: &str| d[k].as_str().map(str::to_string);
            if let (Some(method), Some(host), Some(path)) = (s("method"), s("host"), s("path")) {
                out.push(EgressSeen { method, host, path, outcome: s("outcome").unwrap_or_default() });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Approval;
    use std::time::Duration;
    use wicket_core::RiskClass;

    fn op(run: &str, method: &str, path: &str) -> Op {
        let mut o = Op::egress(&TenantId::single(), &RunId(run.into()), "z", method, "wicket.internal", path);
        if method == "SPAWN" {
            o.risk = RiskClass::R4ExecOrPrivilege;
        }
        o
    }

    fn once(by: &str) -> Approval {
        Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: by.into() }
    }

    /// #369: a spawn's grant is for exactly the arguments it was decided on; a sibling ask while
    /// it is pending waits on it; changed arguments are refused and audited; a replay finds it spent.
    #[test]
    fn a_reserved_grant_binds_its_arguments_and_holds_siblings() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("run_a", "SPAWN", "/zones/child/worker");
        let a = Filed::New(String::new());
        let first = l.file_request(&o, Some("aaaa"), "spawn worker", None).unwrap();
        assert!(matches!(first, Filed::New(_)), "{a:?}");
        let rid = first.id().to_string();
        assert_eq!(l.request(&rid).unwrap().args_sha256.as_deref(), Some("aaaa"));
        // The same ask again: the same request. Other arguments while it is pending: held on it.
        assert_eq!(l.file_request(&o, Some("aaaa"), "spawn worker", None).unwrap(), Filed::Existing(rid.clone()));
        assert_eq!(l.file_request(&o, Some("bbbb"), "spawn worker", None).unwrap(), Filed::Held { pending: rid.clone() });
        assert_eq!(l.pending(&TenantId::single()).unwrap().len(), 1, "nothing else was filed");
        // Before the decision the action waits; another run's isn't affected.
        assert_eq!(l.use_effect_grant(&o, Some("aaaa")).unwrap(), EffectUse::Held { pending: rid.clone() });
        assert_eq!(l.use_effect_grant(&op("run_b", "SPAWN", "/zones/child/worker"), Some("aaaa")).unwrap(), EffectUse::None);

        let gid = l.approve(&rid, &once("op")).unwrap();
        assert_eq!(l.grant_effect(&gid).unwrap(), Some((None, Some("aaaa".into()))));
        // Changed arguments: refused, nothing used, and on the record.
        assert_eq!(l.use_effect_grant(&o, Some("bbbb")).unwrap(), EffectUse::ArgsChanged { grant: gid.clone() });
        let rec = l.audit_latest("run_a", "effect.refused").unwrap().expect("audited");
        let body: serde_json::Value = serde_json::from_str(&rec).unwrap();
        assert_eq!((body["approved_args_sha256"].as_str(), body["presented_args_sha256"].as_str()), (Some("aaaa"), Some("bbbb")));
        // Exactly the arguments: once. Again: spent.
        assert_eq!(l.use_effect_grant(&o, Some("aaaa")).unwrap(), EffectUse::Granted(gid.clone()));
        assert_eq!(l.use_effect_grant(&o, Some("aaaa")).unwrap(), EffectUse::Spent { grant: gid.clone() });
        assert_eq!(l.use_effect_grant(&o, Some("bbbb")).unwrap(), EffectUse::None, "a spent grant holds nothing back");
    }

    /// A prefix grant never covers a reserved action, and a held action waits for a sibling's request.
    #[test]
    fn a_reserved_action_takes_no_prefix_and_waits_on_a_sibling() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("run_a", "SPAWN", "/zones/child/worker");
        let rid = l.file_request(&o, Some("aaaa"), "spawn", None).unwrap().id().to_string();
        l.approve(&rid, &Approval { path_prefix: Some("/zones/".into()), ..once("op") }).unwrap();
        assert_eq!(l.use_effect_grant(&o, Some("aaaa")).unwrap(), EffectUse::None);
        // An exact grant, then a sibling's ask for the same target with other arguments: the
        // grant's action waits until that request is decided.
        let o2 = op("run_a", "SPAWN", "/zones/child/other");
        let r2 = l.file_request(&o2, Some("aaaa"), "spawn", None).unwrap().id().to_string();
        let g2 = l.approve(&r2, &Approval { uses: Some(2), ..once("op") }).unwrap();
        let r3 = l.file_request(&o2, Some("cccc"), "spawn", None).unwrap();
        assert!(matches!(r3, Filed::New(_)), "the first was decided: a new ask is filed, {r3:?}");
        assert_eq!(l.use_effect_grant(&o2, Some("aaaa")).unwrap(), EffectUse::Held { pending: r3.id().into() });
        l.deny(r3.id(), "op").unwrap();
        assert_eq!(l.use_effect_grant(&o2, Some("aaaa")).unwrap(), EffectUse::Granted(g2));
    }

    /// An egress request a pending prefix ask from its run covers waits on that ask.
    #[test]
    fn egress_under_a_pending_prefix_ask_is_held_on_it() {
        let l = Ledger::open_in_memory().unwrap();
        let ask = Op::egress(&TenantId::single(), &RunId("run_a".into()), "z", "GET", "files.example", "/docs");
        let (pid, _) = l.ask(&ask, "the docs", true, None).unwrap();
        let get = |run: &str, path: &str| Op::egress(&TenantId::single(), &RunId(run.into()), "z", "GET", "files.example", path);
        assert_eq!(l.pending_for(&get("run_a", "/docs/a"), "", None).unwrap(), (pid.clone(), false));
        assert_eq!(l.file_request(&get("run_a", "/docs/a"), None, "", None).unwrap(), Filed::Held { pending: pid.clone() });
        // Outside the prefix, another method or another run: filed on its own.
        assert!(l.pending_for(&get("run_a", "/other"), "", None).unwrap().1);
        assert!(l.pending_for(&get("run_b", "/docs/a"), "", None).unwrap().1);
    }

    #[test]
    fn a_runs_recent_egress_reads_its_own_and_its_nodes_records() {
        let l = Ledger::open_in_memory().unwrap();
        let run = RunId("run_a".into());
        let t = TenantId::single();
        let ev =
            |m: &str, p: &str| serde_json::json!({ "kind": "egress", "method": m, "host": "h.example", "path": p, "outcome": "allow" });
        l.audit(&t, Some(&run), "op", &ev("GET", "/a")).unwrap();
        l.audit(&t, Some(&run), "node.audit", &serde_json::json!({ "body": ev("POST", "/b").to_string() })).unwrap();
        l.audit(&t, Some(&run), "op", &serde_json::json!({ "kind": "spawn" })).unwrap();
        l.audit(&t, Some(&RunId("run_b".into())), "op", &ev("GET", "/c")).unwrap();
        let seen = l.recent_egress("run_a", 10).unwrap();
        assert_eq!(seen.iter().map(|e| (e.method.as_str(), e.path.as_str())).collect::<Vec<_>>(), vec![("POST", "/b"), ("GET", "/a")]);
        assert_eq!(l.recent_egress("run_a", 1).unwrap().len(), 1);
    }
}

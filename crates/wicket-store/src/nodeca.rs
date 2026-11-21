//! What a node's CA may be widened to at runtime, and what is wanted of it (#573).
//!
//! A node's CA is name-constrained to a host list (`node_cas.hosts`). Its operator says per node
//! how the control host may widen it (`node_ca_policy`; no row is `fixed`): never (`fixed`, as
//! before #573), to whatever its boxes need (`auto`), or only to hosts an allowed list matches.
//! What its boxes need beyond the operator's hosts is recorded in `node_ca_wants`, one row per host
//! and run (`why` names the reach or the grant): a renewal over the channel signs for the operator's
//! hosts and the live runs' wants, within the policy (`wicket-node`'s `controlca`). A run's wants go
//! when it ends, and are ignored once it has; re-enrolling or revoking the node clears its policy
//! and wants.

use crate::{Ledger, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS node_ca_policy (
  node TEXT PRIMARY KEY, mode TEXT NOT NULL, allowed TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS node_ca_wants (
  node TEXT NOT NULL, host TEXT NOT NULL, run TEXT NOT NULL, why TEXT NOT NULL, at INTEGER NOT NULL,
  PRIMARY KEY (node, host, run)
);
"#;

/// How the control host may widen a node's CA at runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "allowed", rename_all = "snake_case")]
pub enum CaHosts {
    /// Never: the CA keeps the hosts it was enrolled or renewed with (`wicket node renew-ca`).
    Fixed,
    /// To every inspected host its boxes need.
    Auto,
    /// To the hosts these patterns match (`api.example.com`, `*.example.org`).
    Allowed(Vec<String>),
}

impl CaHosts {
    /// What `wicket node set --ca-hosts` takes: `fixed`, `auto`, or a comma-separated list.
    pub fn parse(s: &str) -> std::result::Result<CaHosts, String> {
        match s.trim() {
            "fixed" => Ok(CaHosts::Fixed),
            "auto" => Ok(CaHosts::Auto),
            "" => Err("--ca-hosts is fixed, auto, or a list of hosts (api.example.com,*.example.org)".into()),
            list => {
                let mut hosts = vec![];
                for h in list.split(',').map(str::trim).filter(|h| !h.is_empty()) {
                    if h == "fixed" || h == "auto" {
                        return Err(format!("--ca-hosts: {h} is a policy of its own, not a host in a list"));
                    }
                    // Only what a node CA may be constrained to (#573's review): never `*`, an IP,
                    // a single label or `*.com`; stored canonical (punycode).
                    let entry = wicket_core::splice::ca_subtree(h).ok_or_else(|| {
                        format!("--ca-hosts: {h:?} is not a host name or *.domain (of two labels or more) a node CA can be constrained to")
                    })?;
                    let pattern = match entry.strip_prefix('.') {
                        Some(d) => format!("*.{d}"),
                        None => entry,
                    };
                    if !hosts.contains(&pattern) {
                        hosts.push(pattern);
                    }
                }
                if hosts.is_empty() {
                    return Err("--ca-hosts is fixed, auto, or a list of hosts (api.example.com,*.example.org)".into());
                }
                Ok(CaHosts::Allowed(hosts))
            }
        }
    }

    /// Whether a CA may be widened to `subtree` (`h`, or `.d` for the names under d).
    /// Never one no node CA may carry (`*`, an IP, a single label…), whatever the policy.
    pub fn allows(&self, subtree: &str) -> bool {
        if !wicket_core::splice::issuable_subtree(subtree) {
            return false;
        }
        match self {
            CaHosts::Fixed => false,
            CaHosts::Auto => true,
            CaHosts::Allowed(pats) => {
                let want = match subtree.strip_prefix('.') {
                    Some(d) => format!("*.{d}"),
                    None => subtree.to_string(),
                };
                // Every name the want stands for must be one a pattern matches.
                pats.iter().any(|p| match (p.strip_prefix("*."), want.strip_prefix("*.")) {
                    (None, None) => p.eq_ignore_ascii_case(&want),
                    (Some(s), None) => wicket_core::manifest::host_matches(p, &want) && !want.eq_ignore_ascii_case(s),
                    (Some(s), Some(t)) => {
                        t.eq_ignore_ascii_case(s) || t.to_ascii_lowercase().ends_with(&format!(".{}", s.to_ascii_lowercase()))
                    }
                    (None, Some(_)) => false,
                })
            }
        }
    }
}

/// One host wanted of a node's CA: by which run (or `grant:<id>`), and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaWant {
    pub host: String,
    pub run: String,
    pub why: String,
    pub at: i64,
}

impl Ledger {
    /// A node's policy for widening its CA (`fixed` when none is recorded).
    pub fn node_ca_policy(&self, node: &str) -> Result<CaHosts> {
        let row: Option<(String, String)> = self
            .conn
            .query_row("SELECT mode, allowed FROM node_ca_policy WHERE node = ?1", params![node], |r| Ok((r.get(0)?, r.get(1)?)))
            .map(Some)
            .or_else(|e| if matches!(e, rusqlite::Error::QueryReturnedNoRows) { Ok(None) } else { Err(e) })?;
        Ok(match row {
            Some((m, _)) if m == "auto" => CaHosts::Auto,
            Some((m, list)) if m == "allowed" => CaHosts::Allowed(serde_json::from_str(&list).unwrap_or_default()),
            _ => CaHosts::Fixed,
        })
    }

    pub fn set_node_ca_policy(&self, node: &str, p: &CaHosts) -> Result<()> {
        let (mode, allowed) = match p {
            CaHosts::Fixed => ("fixed", "[]".to_string()),
            CaHosts::Auto => ("auto", "[]".to_string()),
            CaHosts::Allowed(h) => ("allowed", serde_json::to_string(h).unwrap_or_else(|_| "[]".into())),
        };
        self.conn.execute(
            "INSERT INTO node_ca_policy (node, mode, allowed) VALUES (?1, ?2, ?3)
             ON CONFLICT(node) DO UPDATE SET mode = excluded.mode, allowed = excluded.allowed",
            params![node, mode, allowed],
        )?;
        Ok(())
    }

    /// Sets `node`'s policy and audits it (`node.ca_policy`, with who set it) in one transaction:
    /// both, or neither. Refused for a node that isn't enrolled and active.
    pub fn set_node_ca_policy_audited(&self, node: &str, p: &CaHosts, by: &str) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let r = (|| {
            let active = self.node(node)?.is_some_and(|n| n.status == "active");
            if !active {
                return Err(crate::StoreError::Node(node.into(), "is not enrolled and active"));
            }
            self.set_node_ca_policy(node, p)?;
            let body = serde_json::json!({ "name": node, "ca_hosts": p, "by": by });
            self.audit(&wicket_core::TenantId::single(), None, "node.ca_policy", &body).map(|_| ())
        })();
        let _ = self.conn.execute_batch(if r.is_ok() { "COMMIT" } else { "ROLLBACK" });
        r
    }

    /// Records that `run` wants `hosts` (subtrees: `h`, or `.d` for `*.d`) of `node`'s CA, `why`
    /// naming the reach or the grant. Returns how many are new, and the entries refused because no
    /// node CA may carry them (`*`, an IP, a single label…): those are never recorded.
    pub fn want_node_ca_hosts(&self, node: &str, hosts: &[String], run: &str, why: &str, now: i64) -> Result<(usize, Vec<String>)> {
        let (mut n, mut refused) = (0, vec![]);
        for h in hosts {
            if !wicket_core::splice::issuable_subtree(h) {
                refused.push(h.clone());
                continue;
            }
            n += self.conn.execute(
                "INSERT OR IGNORE INTO node_ca_wants (node, host, run, why, at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![node, h, run, why, now],
            )?;
        }
        Ok((n, refused))
    }

    /// What is wanted of `node`'s CA by runs still live (a run that ended without dropping its wants,
    /// a start that failed or a control host that crashed, wants nothing), oldest first.
    pub fn node_ca_wants(&self, node: &str) -> Result<Vec<CaWant>> {
        let mut st = self.conn.prepare(
            "SELECT w.host, w.run, w.why, w.at FROM node_ca_wants w JOIN runs r ON r.id = w.run
             WHERE w.node = ?1 AND r.ended_at IS NULL ORDER BY w.at, w.host, w.run",
        )?;
        let rows = st.query_map(params![node], |r| Ok(CaWant { host: r.get(0)?, run: r.get(1)?, why: r.get(2)?, at: r.get(3)? }))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Drops what `run` wanted of any node's CA: it ended.
    pub fn drop_node_ca_wants(&self, run: &str) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM node_ca_wants WHERE run = ?1", params![run])?)
    }
}

/// Clears `node`'s CA policy and wants: it was revoked, or a machine is enrolled under its name,
/// which must not inherit `auto` or another machine's wants.
pub(crate) fn forget_node_ca(conn: &rusqlite::Connection, node: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM node_ca_policy WHERE node = ?1", params![node])?;
    conn.execute("DELETE FROM node_ca_wants WHERE node = ?1", params![node])?;
    // Nor public addresses (#716 review, F2): a released node's address may be someone else's
    // server now, and a machine enrolled again under its name is another machine.
    conn.execute("DELETE FROM node_addresses WHERE node = ?1", params![node])?;
    Ok(())
}

impl Ledger {
    /// Test seam: a live run to want hosts for.
    #[cfg(test)]
    pub(crate) fn live_run(&self, run: &str) {
        self.run_started(&wicket_core::TenantId::single(), &wicket_core::RunId(run.into()), "z", "a").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nodes_ca_policy_and_wants() {
        let l = Ledger::open_in_memory().unwrap();
        assert_eq!(l.node_ca_policy("n1").unwrap(), CaHosts::Fixed, "none recorded: fixed");
        l.set_node_ca_policy("n1", &CaHosts::Auto).unwrap();
        assert_eq!(l.node_ca_policy("n1").unwrap(), CaHosts::Auto);
        let allowed = CaHosts::parse("api.example.com, *.Example.org").unwrap();
        l.set_node_ca_policy("n1", &allowed).unwrap();
        assert_eq!(l.node_ca_policy("n1").unwrap(), CaHosts::Allowed(vec!["api.example.com".into(), "*.example.org".into()]));
        assert!(CaHosts::parse("").is_err() && CaHosts::parse("10.0.0.1").is_err());
        l.live_run("run_a");
        l.live_run("run_b");
        let hosts = vec!["api.example.com".to_string(), ".example.org".to_string()];
        assert_eq!(l.want_node_ca_hosts("n1", &hosts, "run_a", "reach", 10).unwrap(), (2, vec![]));
        assert_eq!(l.want_node_ca_hosts("n1", &hosts, "run_a", "reach", 11).unwrap().0, 0, "once per host and run");
        assert_eq!(l.want_node_ca_hosts("n1", &hosts[..1], "run_b", "reach", 12).unwrap().0, 1);
        assert_eq!(l.node_ca_wants("n1").unwrap().len(), 3);
        assert_eq!(l.drop_node_ca_wants("run_a").unwrap(), 2);
        assert_eq!(l.node_ca_wants("n1").unwrap().iter().map(|w| w.run.as_str()).collect::<Vec<_>>(), ["run_b"]);
    }

    /// #573's review: nothing a node CA can't carry is recorded or allowed, a run that ended (by any
    /// path) wants nothing, and a node re-enrolled or revoked starts with no policy and no wants.
    #[test]
    fn wants_are_issuable_live_and_forgotten_with_the_node() {
        let l = Ledger::open_in_memory().unwrap();
        l.live_run("run_a");
        let bad: Vec<String> = ["*", ".com", "8.8.8.8", "intranet", ".*.example.com"].map(String::from).to_vec();
        let (n, refused) = l.want_node_ca_hosts("n1", &[bad.clone(), vec!["ok.example.com".into()]].concat(), "run_a", "reach", 1).unwrap();
        assert_eq!((n, refused), (1, bad.clone()));
        for b in &bad {
            assert!(!CaHosts::Auto.allows(b), "{b}");
        }
        for p in ["*", "*.com", "intranet", "fixed,auto", "auto,api.example.com", "*.*.example.com"] {
            assert!(CaHosts::parse(p).is_err(), "{p}");
        }
        assert_eq!(CaHosts::parse("Bücher.example.com").unwrap(), CaHosts::Allowed(vec!["xn--bcher-kva.example.com".into()]));
        // Ended without dropping its wants (a start that failed, a crash): ignored.
        l.run_ended(&wicket_core::RunId("run_a".into()), "failed", "").unwrap();
        assert!(l.node_ca_wants("n1").unwrap().is_empty());
        l.live_run("run_b");
        l.want_node_ca_hosts("n1", &["ok.example.com".into()], "run_b", "reach", 2).unwrap();
        l.set_node_ca_policy("n1", &CaHosts::Auto).unwrap();
        forget_node_ca(&l.conn, "n1").unwrap();
        assert_eq!(l.node_ca_policy("n1").unwrap(), CaHosts::Fixed);
        assert!(l.node_ca_wants("n1").unwrap().is_empty());
    }

    #[test]
    fn an_allowed_list_bounds_a_widening() {
        let p = CaHosts::parse("api.example.com,*.example.org").unwrap();
        assert!(p.allows("api.example.com") && p.allows("a.example.org") && p.allows(".example.org") && p.allows(".b.example.org"));
        assert!(!p.allows("example.org"), "the apex isn't under *.example.org");
        assert!(!p.allows("x.api.example.com") && !p.allows(".example.com") && !p.allows("other.test"));
        assert!(!CaHosts::Fixed.allows("api.example.com") && CaHosts::Auto.allows("anything.test"));
    }
}

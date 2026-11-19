//! What a node's CA may be widened to at runtime, and what is wanted of it (#573).
//!
//! A node's CA is name-constrained to a host list (`node_cas.hosts`). Its operator says per node
//! how the control host may widen it (`node_ca_policy`; no row is `fixed`): never (`fixed`, as
//! before #573), to whatever its boxes need (`auto`), or only to hosts an allowed list matches.
//! What its boxes need beyond the CA is recorded in `node_ca_wants`, one row per host and run (or
//! grant): the next renewal over the channel signs for the CA's hosts and the live wants, within
//! the policy (`wicket-node`'s `controlca`). A run's wants go when it ends.

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
                    let bare = h.strip_prefix("*.").unwrap_or(h);
                    wicket_core::canonical_host(bare).map_err(|e| format!("--ca-hosts: {h}: {e}"))?;
                    hosts.push(h.to_ascii_lowercase());
                }
                Ok(CaHosts::Allowed(hosts))
            }
        }
    }

    /// Whether a CA may be widened to `subtree` (`h`, or `.d` for the names under d).
    pub fn allows(&self, subtree: &str) -> bool {
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

    /// Records that `run` (or `grant:<id>`) wants `hosts` of `node`'s CA. Returns how many are new.
    pub fn want_node_ca_hosts(&self, node: &str, hosts: &[String], run: &str, why: &str, now: i64) -> Result<usize> {
        let mut n = 0;
        for h in hosts {
            n += self.conn.execute(
                "INSERT OR IGNORE INTO node_ca_wants (node, host, run, why, at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![node, h.to_ascii_lowercase(), run, why, now],
            )?;
        }
        Ok(n)
    }

    /// What is wanted of `node`'s CA, oldest first.
    pub fn node_ca_wants(&self, node: &str) -> Result<Vec<CaWant>> {
        let mut st = self.conn.prepare("SELECT host, run, why, at FROM node_ca_wants WHERE node = ?1 ORDER BY at, host")?;
        let rows = st.query_map(params![node], |r| Ok(CaWant { host: r.get(0)?, run: r.get(1)?, why: r.get(2)?, at: r.get(3)? }))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Drops what `run` (or `grant:<id>`) wanted of any node's CA: it ended.
    pub fn drop_node_ca_wants(&self, run: &str) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM node_ca_wants WHERE run = ?1", params![run])?)
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
        let hosts = vec!["api.example.com".to_string(), ".example.org".to_string()];
        assert_eq!(l.want_node_ca_hosts("n1", &hosts, "run_a", "reach", 10).unwrap(), 2);
        assert_eq!(l.want_node_ca_hosts("n1", &hosts, "run_a", "reach", 11).unwrap(), 0, "once per host and run");
        assert_eq!(l.want_node_ca_hosts("n1", &hosts[..1], "run_b", "reach", 12).unwrap(), 1);
        assert_eq!(l.node_ca_wants("n1").unwrap().len(), 3);
        assert_eq!(l.drop_node_ca_wants("run_a").unwrap(), 2);
        assert_eq!(l.node_ca_wants("n1").unwrap().iter().map(|w| w.run.as_str()).collect::<Vec<_>>(), ["run_b"]);
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

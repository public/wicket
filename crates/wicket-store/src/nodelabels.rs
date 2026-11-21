//! A node's labels and taints (#579): what its operator says about it, for placement
//! (`wicket-placement::schedule`). Set with `wicket node set <node> --label k=v --taint k=v`.
//!
//! And its public addresses (#575): where a public name of a box on it points. Set by the operator
//! (`wicket node set <node> --public-ipv4 … --public-ipv6 …`), never by the node itself: a node that
//! could name its own address could point a name at someone else's server.

use crate::{Ledger, Result};
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeMap;
use wicket_core::placement::Taint;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS node_labels (
  node TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (node, key)
);
CREATE TABLE IF NOT EXISTS node_taints (
  node TEXT NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY (node, key)
);
CREATE TABLE IF NOT EXISTS node_addresses (
  node TEXT PRIMARY KEY, ipv4 TEXT, ipv6 TEXT, set_at INTEGER NOT NULL, set_by TEXT NOT NULL
);
"#;

/// A node's public addresses, as its operator set them. Neither: it can't publish.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeAddresses {
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

impl NodeAddresses {
    pub fn is_empty(&self) -> bool {
        self.ipv4.is_none() && self.ipv6.is_none()
    }
}

/// A change to one of a node's public addresses: keep it, set it, or clear it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressChange<T> {
    Keep,
    Set(T),
    Clear,
}

impl<T: Copy> AddressChange<T> {
    pub fn apply(self, old: Option<T>) -> Option<T> {
        match self {
            AddressChange::Keep => old,
            AddressChange::Set(v) => Some(v),
            AddressChange::Clear => None,
        }
    }
}

impl Ledger {
    pub fn node_labels(&self, node: &str) -> Result<BTreeMap<String, String>> {
        let mut st = self.conn.prepare("SELECT key, value FROM node_labels WHERE node = ?1 ORDER BY key")?;
        let rows = st.query_map(params![node], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<BTreeMap<_, _>, _>>()?)
    }

    /// Sets a label, or removes it (`None`). Returns whether anything changed.
    pub fn set_node_label(&self, node: &str, key: &str, value: Option<&str>) -> Result<bool> {
        let n = match value {
            Some(v) => self.conn.execute(
                "INSERT INTO node_labels (node, key, value) VALUES (?1, ?2, ?3)
                 ON CONFLICT(node, key) DO UPDATE SET value = excluded.value WHERE value IS NOT excluded.value",
                params![node, key, v],
            )?,
            None => self.conn.execute("DELETE FROM node_labels WHERE node = ?1 AND key = ?2", params![node, key])?,
        };
        Ok(n > 0)
    }

    /// A node's taints, by key. A node has at most one per key.
    pub fn node_taints(&self, node: &str) -> Result<Vec<Taint>> {
        let mut st = self.conn.prepare("SELECT key, value FROM node_taints WHERE node = ?1 ORDER BY key")?;
        let rows = st.query_map(params![node], |r| Ok(Taint { key: r.get(0)?, value: r.get(1)? }))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Taints a node (replacing a taint with the same key). Returns whether anything changed.
    pub fn set_node_taint(&self, node: &str, t: &Taint) -> Result<bool> {
        Ok(self.conn.execute(
            "INSERT INTO node_taints (node, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(node, key) DO UPDATE SET value = excluded.value WHERE value IS NOT excluded.value",
            params![node, t.key, t.value],
        )? > 0)
    }

    /// `node`'s public addresses: none if its operator set none, it isn't an active node, or they
    /// were set before it was last enrolled (a machine enrolled again under its name, perhaps by a
    /// build that doesn't know the table, is another machine).
    pub fn node_addresses(&self, node: &str) -> Result<NodeAddresses> {
        let row: Option<(Option<String>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT a.ipv4, a.ipv6 FROM node_addresses a JOIN nodes n ON n.name = a.node WHERE a.node = ?1 AND n.status = 'active' AND a.set_at >= n.enrolled_at",
                params![node],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (v4, v6) = row.unwrap_or_default();
        Ok(NodeAddresses { ipv4: v4.and_then(|a| a.parse().ok()), ipv6: v6.and_then(|a| a.parse().ok()) })
    }

    /// Changes `node`'s public addresses as `by` (an operator), audited as `node.addresses`. Only
    /// addresses on the public internet (`wicket_core::op::is_public_ip`): a name pointing at a
    /// private one would reach nobody, or the wrong host. The addresses it has now.
    pub fn set_node_addresses(
        &self,
        node: &str,
        ipv4: AddressChange<std::net::Ipv4Addr>,
        ipv6: AddressChange<std::net::Ipv6Addr>,
        by: &str,
    ) -> Result<NodeAddresses> {
        self.set_node_addresses_checked(node, None, ipv4, ipv6, by, serde_json::json!({}))
    }

    /// [`Ledger::set_node_addresses`], refused unless the node's addresses are `expected` when the
    /// write lock is held (the console's signed change binds the addresses it showed, #575 step
    /// 4d), with `extra` on the audit record. The record is written first, in the same write: a
    /// change that can't be recorded isn't made.
    pub fn set_node_addresses_checked(
        &self,
        node: &str,
        expected: Option<&NodeAddresses>,
        ipv4: AddressChange<std::net::Ipv4Addr>,
        ipv6: AddressChange<std::net::Ipv6Addr>,
        by: &str,
        extra: serde_json::Value,
    ) -> Result<NodeAddresses> {
        for ip in [
            if let AddressChange::Set(a) = ipv4 { Some(std::net::IpAddr::V4(a)) } else { None },
            if let AddressChange::Set(a) = ipv6 { Some(std::net::IpAddr::V6(a)) } else { None },
        ]
        .into_iter()
        .flatten()
        {
            if !wicket_core::op::is_public_ip(&ip) {
                return Err(crate::StoreError::Refused(format!("{ip} is not an address on the public internet")));
            }
        }
        self.immediate(|l| {
            let Some(row) = l.node(node)? else {
                return Err(crate::StoreError::Refused(format!("node {node} is not enrolled")));
            };
            if row.status != "active" {
                return Err(crate::StoreError::Refused(format!("node {node} is {}, not active", row.status)));
            }
            let old = l.node_addresses(node)?;
            if expected.is_some_and(|e| *e != old) {
                return Err(crate::StoreError::Refused(format!("node {node}'s public addresses changed since you were shown them: look again")));
            }
            let new = NodeAddresses { ipv4: ipv4.apply(old.ipv4), ipv6: ipv6.apply(old.ipv6) };
            if new == old {
                return Ok(new);
            }
            // One address, one node (#716 review, F4): host ports are allocated per node, so two
            // nodes behind one address would both hand out the same port.
            // Which node (perhaps another tenant's) isn't said: the reply reaches a console or CLI
            // of this node's tenant (#575 review, L2).
            let other: Option<String> = l
                .conn
                .query_row(
                    "SELECT a.node FROM node_addresses a JOIN nodes n ON n.name = a.node
                     WHERE n.status = 'active' AND a.set_at >= n.enrolled_at AND a.node != ?1 AND ((?2 IS NOT NULL AND a.ipv4 = ?2) OR (?3 IS NOT NULL AND a.ipv6 = ?3))
                     LIMIT 1",
                    params![node, new.ipv4.map(|a| a.to_string()), new.ipv6.map(|a| a.to_string())],
                    |r| r.get(0),
                )
                .optional()?;
            if other.is_some() {
                return Err(crate::StoreError::Refused("that public address is already another node's".into()));
            }
            let mut body = serde_json::json!({
                "name": node, "ipv4": new.ipv4.map(|a| a.to_string()), "ipv6": new.ipv6.map(|a| a.to_string()),
                "was_ipv4": old.ipv4.map(|a| a.to_string()), "was_ipv6": old.ipv6.map(|a| a.to_string()), "by": by,
            });
            if let (Some(b), serde_json::Value::Object(x)) = (body.as_object_mut(), extra) {
                b.extend(x);
            }
            // On the record first, in the same write: a change that can't be recorded isn't made.
            l.audit(&wicket_core::TenantId(row.tenant), None, "node.addresses", &body)?;
            l.conn.execute(
                "INSERT INTO node_addresses (node, ipv4, ipv6, set_at, set_by) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(node) DO UPDATE SET ipv4 = excluded.ipv4, ipv6 = excluded.ipv6, set_at = excluded.set_at, set_by = excluded.set_by",
                params![node, new.ipv4.map(|a| a.to_string()), new.ipv6.map(|a| a.to_string()), crate::now(), by],
            )?;
            Ok(new)
        })
    }

    /// The other active nodes that have one of `node`'s public addresses (each as read by
    /// [`Ledger::node_addresses`]): none, unless the ledger was written around its checks.
    pub fn nodes_sharing_addresses(&self, node: &str) -> Result<Vec<String>> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT b.node FROM node_addresses a
               JOIN nodes na ON na.name = a.node AND na.status = 'active' AND a.set_at >= na.enrolled_at
               JOIN node_addresses b ON b.node != a.node AND ((a.ipv4 IS NOT NULL AND a.ipv4 = b.ipv4) OR (a.ipv6 IS NOT NULL AND a.ipv6 = b.ipv6))
               JOIN nodes nb ON nb.name = b.node AND nb.status = 'active' AND b.set_at >= nb.enrolled_at
             WHERE a.node = ?1 ORDER BY b.node",
        )?;
        let rows = st.query_map(params![node], |r| r.get(0))?.collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    /// Test support: sets `node`'s public addresses without the checks of
    /// [`Ledger::set_node_addresses`] (one node per address among them), as a ledger written by
    /// hand or by an older build might have them. Not for production use.
    #[doc(hidden)]
    pub fn force_node_addresses_for_tests(
        &self,
        node: &str,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO node_addresses (node, ipv4, ipv6, set_at, set_by) VALUES (?1, ?2, ?3, ?4, 'test')
             ON CONFLICT(node) DO UPDATE SET ipv4 = excluded.ipv4, ipv6 = excluded.ipv6, set_at = excluded.set_at",
            params![node, ipv4.map(|a| a.to_string()), ipv6.map(|a| a.to_string()), crate::now()],
        )?;
        Ok(())
    }

    /// Removes the taint with this key. Returns whether there was one.
    pub fn remove_node_taint(&self, node: &str, key: &str) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM node_taints WHERE node = ?1 AND key = ?2", params![node, key])? > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nodes_labels_and_taints() {
        let l = Ledger::open_in_memory().unwrap();
        assert!(l.node_labels("n1").unwrap().is_empty() && l.node_taints("n1").unwrap().is_empty());
        assert!(l.set_node_label("n1", "gpu", Some("t4")).unwrap());
        assert!(l.set_node_label("n1", "gpu", Some("a100")).unwrap(), "a new value");
        assert!(!l.set_node_label("n1", "gpu", Some("a100")).unwrap(), "the same value changes nothing");
        assert!(l.set_node_label("n1", "zone", Some("eu")).unwrap());
        assert_eq!(l.node_labels("n1").unwrap(), BTreeMap::from([("gpu".into(), "a100".into()), ("zone".into(), "eu".into())]));
        assert!(l.node_labels("n2").unwrap().is_empty(), "per node");
        assert!(l.set_node_label("n1", "zone", None).unwrap());
        assert!(!l.set_node_label("n1", "zone", None).unwrap());

        let ci = Taint::parse("dedicated=ci").unwrap();
        let bare = Taint::parse("dedicated").unwrap();
        assert!(l.set_node_taint("n1", &ci).unwrap());
        assert!(!l.set_node_taint("n1", &ci).unwrap());
        assert!(l.set_node_taint("n1", &bare).unwrap(), "one per key: the value goes");
        assert_eq!(l.node_taints("n1").unwrap(), vec![bare]);
        assert!(l.remove_node_taint("n1", "dedicated").unwrap());
        assert!(l.node_taints("n1").unwrap().is_empty());
    }
}

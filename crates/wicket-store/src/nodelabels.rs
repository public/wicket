//! A node's labels and taints (#579): what its operator says about it, for placement
//! (`wicket-placement::schedule`). Set with `wicket node set <node> --label k=v --taint k=v`.

use crate::{Ledger, Result};
use rusqlite::params;
use std::collections::BTreeMap;
use wicket_core::placement::Taint;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS node_labels (
  node TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (node, key)
);
CREATE TABLE IF NOT EXISTS node_taints (
  node TEXT NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY (node, key)
);
"#;

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

//! A node (#219): `wicket node serve` ([`nodesrv`]), which runs the boxes on a machine and talks
//! the control channel to the control host, with its MCP gateway ([`nodesrv`]'s `gw`, `nodegw.rs`).
//!
//! A library split from wicket-cli, which imports its modules under their old names. With it go
//! the few things of the CLI's the node used, now this crate's and re-exported where they were:
//! the node's status and its view's types ([`status`], from `top`), a spawn's plan ([`childplan`],
//! from `spawn`), the files a node reads and writes in a box's tree without trusting it
//! ([`boxfiles`], from `hibernate`), re-executing on a new build ([`reexec`], from `update`), the
//! control host's calls on a node's channel ([`calls`], from `nodecall`) and its half of a node
//! CA's renewal ([`controlca`], from `nodeca`), whose tests drive a node.

// say! and say_err!, as wicket-cli prints with them.
#[macro_use]
extern crate wicket_home;

// The modules of the crates split before this one, under the names the node's code uses.
use wicket_chan::{chan, health, nodesecrets, oci, registry};
use wicket_home::{audit_export, data_dir, exitcause, nodeauth, owner};

pub mod boxfiles;
pub mod calls;
pub mod childplan;
pub mod controlca;
pub mod nodesrv;
pub mod reexec;
pub mod status;

use std::time::Duration;

/// Where wicket keeps its files on a node, relative to the login's home directory.
pub const NODE_DIR: &str = ".local/share/wicket-node";

/// The built-in node's name (reserved: `wicket node enrol` refuses it).
pub const LOCAL_NODE: &str = "local";

/// How a node marks an ask the agent made itself (`request_access`), its reason following.
pub const AGENT_ASKS: &str = "asked by the agent: ";

/// Why a placed node takes no new run: it is past its lease, which ended at `until`.
pub fn past_lease(node: &str, until: i64) -> String {
    format!(
        "node {node} is past its lease (it ended {}): it takes no new runs, and the reconciler releases it once nothing is on it. Create another node (wicket node create)",
        fmt_time(until)
    )
}

fn fmt_time(t: i64) -> String {
    wicket_core::time::format_rfc3339_seconds(std::time::UNIX_EPOCH + Duration::from_secs(t.max(0) as u64)).to_string()
}

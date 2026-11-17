//! Renewing a node's CA over its control channel (#416), the control host's side: in wicket-node
//! (`controlca`), whose tests drive a node, and re-exported here. What stays is the installation
//! CA's loading, from this host's enrolment paths.

pub use wicket_node::controlca::*;
use wicket_proxy::ca::InstallationCa;

/// The installation CA, for renewals, if this control host has one (never created here).
pub fn installation_ca() -> Option<InstallationCa> {
    let key = crate::enrol::Paths::installation().ca_key;
    key.exists().then(|| InstallationCa::load_or_create(&key)).and_then(|r| r.map_err(|e| say_err!("[wicket] installation CA: {e:#}")).ok())
}

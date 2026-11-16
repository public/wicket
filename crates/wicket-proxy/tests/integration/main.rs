//! wicket-proxy's integration tests, one binary (#219: one link per crate, not one per file).

#[path = "../support/zone_decider.rs"]
mod zone_decider;

mod canary;
mod conformance;
mod git_push;
mod h3;
mod remote_session;
mod splice;
mod streaming;

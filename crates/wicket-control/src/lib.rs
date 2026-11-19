//! The control host's core (#219): a run's supervisor ([`run`]) and its box on a node
//! ([`noderun`], [`nodecall`], [`links`]), spawns ([`spawn`], [`quotas`]), hibernation and its
//! stores ([`hibernate`], [`snapstore`], [`storegc`], [`gitguard`]), transcripts ([`transcript`]),
//! the authority roots and the feed ([`roots`]), and what a run needs of the rest: nodes'
//! enrolment, placement and leases ([`enrol`], [`localnode`], [`node`],
//! [`nodecreate`], [`capacity`]), grants and their effects ([`grant`], [`effect`]), operators
//! ([`operators`]), policy ([`policy`]) and images ([`image`]).
//!
//! A library split from wicket-cli, which imports its modules under their old names. These were
//! one cycle of modules there, and still are here; what they needed of the CLI's other modules
//! moved down (to wicket-node) or up (`wicket node install`, which pushes this build, to the CLI's
//! `update`).

// say! and say_err!, as wicket-cli prints with them.
#[macro_use]
extern crate wicket_home;

// The modules and helpers of the crates split before this one, under the names this code uses.
use wicket_chan::{chan, nodesecrets, oci, registry};
use wicket_home::{audit_export, control, exitcause, images_policy, nodeauth, out, owner, program, statestore};
use wicket_home::{cli_principal, data_dir, issuer, issuer_key_path, ledger_path, operator, trust_domain, verified_identity};
use wicket_node::nodesrv;

pub mod capacity;
pub mod digest;
pub mod effect;
pub mod enrol;
// The control host's gateway tools (#257), a crate of their own: what the simulation calls.
pub use wicket_gateway as gateway;
pub mod gitguard;
pub mod grant;
pub mod hibernate;
pub mod image;
pub mod links;
pub mod localnode;
pub mod node;
pub mod nodecall;
pub mod nodecreate;
pub mod noderun;
pub mod operators;
pub mod policy;
pub mod quotas;
pub mod roots;
pub mod run;
pub mod services;
pub mod serviceuse;
pub mod snapstore;
pub mod spawn;
pub mod standing;
pub mod storegc;
pub mod transcript;
pub mod whyhere;

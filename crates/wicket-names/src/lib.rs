//! DNS names for boxes (#575; design in `docs/explanation/box-dns.md`).
//!
//! This crate is the part of public names that needs nothing else of wicket:
//!
//! - [`config`]: the installation's `names:` settings (`wicket.yaml`) and their checks.
//! - [`label`]: the rules a name's label must meet (one DNS label, no IDNs, no reserved label or
//!   lookalike of one).
//! - [`record`]: DNS records, and which box name a record belongs to.
//! - [`plan`]: the reconcile plan. From the records wicket wants, the records the zone holds and the
//!   records the ledger says this installation created, it computes the changes that make the
//!   zone's owned records the wanted ones, and never a change to a record wicket doesn't own.
//! - [`provider`]: the [`DnsProvider`] trait a zone's provider implements (list, apply), and the
//!   no-op provider, which applies nothing and keeps the plans it was given.
//!
//! **Ownership**, as external-dns has it: every box name `N` that wicket publishes has an owner
//! record, a TXT at `_wicket.N` whose value names this installation (`wicket-owner=<id>;…`). A
//! record is wicket's only if both the ledger lists it as created by this installation and the zone
//! holds an owner record for its name with this installation's id ([`plan::Owned::owns`]).

pub mod config;
pub mod label;
pub mod plan;
pub mod provider;
pub mod record;

#[cfg(test)]
mod props;

pub use config::{own_ports, own_ports_from, NamesConfig, PortRange, ProviderKind, PublicConfig};
pub use label::{check_label, check_shape, zone_part, LabelError, Rules};
pub use plan::{plan, Change, Conflict, Desired, Owned, Plan, PlanError};
pub use provider::{Applied, Caps, DnsProvider, MemoryProvider, NoopProvider, ProviderError};
pub use record::{OwnerId, Record, RecordType, Zone};

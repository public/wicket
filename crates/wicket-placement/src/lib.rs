//! Placement: which machine a box runs on, and the money that costs (#37, design §8.3–§8.5).
//!
//! Everything backend-specific sits behind two traits:
//! - [`Provider`]: the raw backend. It lists what it can offer, creates and destroys nodes, and lists the
//!   nodes carrying an owner tag. Implementations: [`static_hosts::StaticHosts`] (the operator's own
//!   machines, reached over ssh) and [`vultr::VultrProvider`] (Vultr API v2). A Kubernetes backend (#45)
//!   is a third `Provider`.
//! - [`Placement`]: what the rest of wicket calls (`acquire`, `get`, `list`, `release`,
//!   `next_paid_hour_at`). [`Placer`] implements it once, over any `Provider`, so the rules below hold
//!   for every backend.
//!
//! **Rules [`Placer`] enforces.**
//! - **Owner tags.** Every node it creates carries `wicket-owner-<installation>`, and the idempotency
//!   and lease tags below. `get`, `list` and `release` only see owned nodes; `release` refuses a node
//!   without the owner tag or with `wicket-protected`. The control host is a machine in the same
//!   account, so this is the line between garbage collection and an outage.
//! - **Idempotent creates.** The caller supplies an idempotency key. A second `acquire` with the same
//!   key returns the same node: from memory, or after a restart from the provider, by listing the tag
//!   `wicket-idem-<sha256(key)[..16]>`. Vultr has no server-side idempotency token, so two *processes*
//!   racing on one key can still both create (design §8.4: "tag-then-list-before-create"); one
//!   process serialises its own acquires, and the reconciler destroys the duplicate.
//! - **The money envelope** ([`MoneyEnvelope`]): a maximum hourly rate summed over every owned node,
//!   and a maximum total (every owned node's billed cost through its lease end, plus the new node's
//!   worst case). A request beyond either is refused outright: no approval can widen it. A request's own
//!   `max_hourly` bounds the plans considered.
//! - **A human approves spend.** Any node with a non-zero worst-case cost is created only after the
//!   [`SpendApprover`] says yes, with the plan, rate and worst case on the request. wicket supplies no
//!   UI here: the CLI prompts on the terminal, the console will show an approval card.
//! - **Worst case, reserved first.** The worst case is what the provider bills for the requested
//!   lifetime under its [`BillingModel`], every partial unit rounded up.
//!
//! **Billing (Vultr).** Measured on our own account's pending charges (docs/research/10-infrastructure.md,
//! 2026-11-08; Vultr's billing doc of 2026-10-26 agrees): cloud compute is billed **per started hour**,
//! each charge line rounded **up** to the cent, capped at **672 hours a month**, and stopped instances
//! still bill. A plan's hourly rate is its `hourly_cost` when the API gives one, else
//! `monthly_cost / 672`. So a node is worth keeping until shortly before its next paid hour starts if
//! more boxes may come, and not after ([`billing::release_decision`]): pooled if at least 10 minutes of
//! paid time remain, claimed from the pool only with at least 20 left, and leases stop at minute 50 of
//! their last hour, because Vultr's clock starts a few seconds after ours and the reconciler is periodic.
//!
//! **Trust bootstrap (Vultr).** The control host generates the node's ssh host key (ed25519, with
//! `ssh-keygen`) and puts it in the instance's cloud-init `ssh_keys`, with every other host key type
//! disabled; the public half is pinned before the node first boots, so the first connection is already
//! authenticated and no host key is taken from the network. The private half transits Vultr's API and the
//! node's metadata service, which adds no one to the trusted base (Vultr can read the node's disk anyway);
//! what remains is that a process with network on the node could read it from the metadata service.
//! Boxes run with `--network none`, and after enrolment the CLI replaces the instance's `user_data` so the
//! metadata copy goes too. Vultr exposes no console output through its API, so this is the only way to
//! get a pinned key without trust on first use; `wicket node enrol --trust-first-use` stays the explicit
//! fallback for a node created any other way. See [`boot`].
//!
//! **Not here.** #37's `launch(node, SandboxSpec)` stays with `wicket run --node` (it already starts a
//! box over ssh with the sockets forwarded); this crate decides and pays for *where*. The reconciler is
//! a pure function ([`reconcile::reconcile`]) with no daemon; #38 runs it.

pub mod billing;
pub mod boot;
pub mod envelope;
pub mod model;
pub mod money;
pub mod placer;
pub mod reconcile;
pub mod static_hosts;
pub mod vultr;

pub use billing::{BillingModel, PoolRules, ReleaseDecision};
pub use envelope::{Approval, MoneyEnvelope, SpendApprover, SpendRequest};
pub use model::{
    CapacityRequest, CreateSpec, IsolationTier, NodeHandle, NodeId, NodeState, Offer, Owner, Placement, PlacementError, Provider, Released,
    Resources, Timestamp,
};
pub use money::MicroUsd;
pub use placer::{Placer, ReleaseMode};

//! The placement vocabulary and the two traits: [`Provider`] (a backend) and [`Placement`] (what wicket
//! calls).

use crate::billing::BillingModel;
use crate::envelope::EnvelopeRefusal;
use crate::money::MicroUsd;
use sha2::{Digest, Sha256};
use std::future::Future;

/// Unix seconds.
pub type Timestamp = i64;

pub fn now() -> Timestamp {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Isolation tiers, weakest first (design §7.2: `process ≈ runc ≈ seatbelt < gvisor < vm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationTier {
    Process,
    Gvisor,
    Vm,
}

impl IsolationTier {
    pub fn parse(s: &str) -> Option<IsolationTier> {
        match s {
            "process" | "runc" | "seatbelt" => Some(IsolationTier::Process),
            "gvisor" | "runsc" => Some(IsolationTier::Gvisor),
            "vm" | "firecracker" | "microvm" => Some(IsolationTier::Vm),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Resources {
    pub vcpus: u32,
    pub memory_mib: u64,
}

impl Resources {
    pub fn fits_in(&self, other: &Resources) -> bool {
        self.vcpus <= other.vcpus && self.memory_mib <= other.memory_mib
    }
}

/// What a caller asks for.
#[derive(Clone, Debug)]
pub struct CapacityRequest {
    pub resources: Resources,
    /// The zone's minimum; the node may be stronger, never weaker.
    pub min_isolation: IsolationTier,
    /// Preferred region (a provider's code, e.g. `lhr`); other regions are used only if none match.
    pub region_hint: Option<String>,
    /// Preferred plan or host name; other offers are used only if it isn't offered.
    pub plan_hint: Option<String>,
    /// The most this one node may cost per hour.
    pub max_hourly: Option<MicroUsd>,
    /// How long the node is needed for (seconds): its worst-case cost is reserved for this long.
    pub lifetime_secs: i64,
    /// Client-supplied: a second acquire with the same key returns the same node.
    pub idempotency_key: String,
    /// The node's name (hostname/label): lowercase letters, digits and `-`.
    pub name: String,
    /// What it is for, shown on the approval request.
    pub purpose: String,
    /// Backend boot data (Vultr: cloud-init user data and the host key it pins). Opaque here.
    pub boot: Option<Boot>,
}

/// What a fresh node boots with: user data for its first boot, and the ssh host key that boot installs
/// (pinned before the node exists).
#[derive(Clone)]
pub struct Boot {
    pub user_data: String,
    pub host_key: String,
}

impl std::fmt::Debug for Boot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // user_data holds the node's private host key.
        f.debug_struct("Boot").field("user_data", &"[redacted]").field("host_key", &self.host_key).finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId(pub String);

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// Created; not yet running or reachable.
    Pending,
    Active,
    /// Being destroyed, or gone.
    Gone,
}

/// A node: a machine (or a slice of one) that boxes can run on.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct NodeHandle {
    pub id: NodeId,
    pub backend: String,
    pub name: String,
    /// `user@address` for ssh, once the node has an address.
    pub ssh_target: Option<String>,
    pub region: Option<String>,
    pub plan: Option<String>,
    pub isolation: IsolationTier,
    pub resources: Resources,
    pub billing: BillingModel,
    pub created_at: Timestamp,
    /// When its lease ends (from its lease tag).
    pub lease_until: Option<Timestamp>,
    /// The ssh host key pinned at creation, if this process created it.
    pub host_key: Option<String>,
    pub tags: Vec<String>,
    pub state: NodeState,
}

impl NodeHandle {
    pub fn has_tag(&self, t: &str) -> bool {
        self.tags.iter().any(|x| x == t)
    }

    /// What the node has cost, or will have cost, by `t`.
    pub fn billed_through(&self, t: Timestamp) -> MicroUsd {
        self.billing.billed(t - self.created_at)
    }
}

/// Something a provider can create.
#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
    pub plan: String,
    pub region: Option<String>,
    pub resources: Resources,
    pub isolation: IsolationTier,
    pub billing: BillingModel,
}

/// What [`Placer`](crate::Placer) asks a provider to create.
#[derive(Clone, Debug)]
pub struct CreateSpec {
    pub offer: Offer,
    pub name: String,
    pub tags: Vec<String>,
    pub boot: Option<Boot>,
}

/// The installation that owns what it creates, and the tags that say so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    installation: String,
}

/// Never destroyed, even if owned (the control host, a broker).
pub const PROTECTED_TAG: &str = "wicket-protected";
const IDEM_PREFIX: &str = "wicket-idem-";
const UNTIL_PREFIX: &str = "wicket-until-";

impl Owner {
    /// `installation` is sanitised to lowercase letters, digits, `-` and `.`.
    pub fn new(installation: &str) -> Owner {
        let s: String = installation
            .to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '-' })
            .take(48)
            .collect();
        Owner { installation: if s.is_empty() { "wicket".into() } else { s } }
    }

    pub fn tag(&self) -> String {
        format!("wicket-owner-{}", self.installation)
    }

    pub fn owns(&self, n: &NodeHandle) -> bool {
        n.has_tag(&self.tag())
    }

    /// The tag a node created for this idempotency key carries: a hash, so the key itself (which may
    /// name a task) isn't stored at the provider.
    pub fn idem_tag(&self, key: &str) -> String {
        let h = Sha256::digest(format!("{}\0{key}", self.installation));
        format!("{IDEM_PREFIX}{}", &hex::encode(h)[..16])
    }

    pub fn lease_tag(until: Timestamp) -> String {
        format!("{UNTIL_PREFIX}{until}")
    }

    pub fn lease_from_tags(tags: &[String]) -> Option<Timestamp> {
        tags.iter().filter_map(|t| t.strip_prefix(UNTIL_PREFIX)?.parse().ok()).max()
    }

    pub fn idem_tag_of(n: &NodeHandle) -> Option<&str> {
        n.tags.iter().find(|t| t.starts_with(IDEM_PREFIX)).map(String::as_str)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    #[error("refused by the money envelope: {0}")]
    Envelope(EnvelopeRefusal),
    #[error("spend not approved: {0}")]
    NotApproved(String),
    #[error("no capacity: {0}")]
    NoCapacity(String),
    #[error("node {0} does not carry this installation's owner tag: refusing to touch it")]
    NotOwned(NodeId),
    #[error("node {0} is protected: refusing to destroy it")]
    Protected(NodeId),
    #[error("no node {0}")]
    NotFound(NodeId),
    #[error(transparent)]
    Provider(#[from] anyhow::Error),
}

pub type Result<T, E = PlacementError> = std::result::Result<T, E>;

/// A backend: creates and destroys nodes, and lists the ones carrying a tag. No policy, no money
/// decisions: [`Placer`](crate::Placer) makes those.
pub trait Provider: Send + Sync {
    fn id(&self) -> &str;
    /// What could satisfy `req` (resources, isolation; region and plan are preferences the placer
    /// applies).
    fn offers(&self, req: &CapacityRequest) -> impl Future<Output = anyhow::Result<Vec<Offer>>> + Send;
    fn create(&self, spec: &CreateSpec) -> impl Future<Output = anyhow::Result<NodeHandle>> + Send;
    fn get(&self, id: &NodeId) -> impl Future<Output = anyhow::Result<Option<NodeHandle>>> + Send;
    /// Nodes carrying `tag` (the owner tag, or an idempotency tag).
    fn list_tagged(&self, tag: &str) -> impl Future<Output = anyhow::Result<Vec<NodeHandle>>> + Send;
    /// Destroys a node. Already gone is success.
    fn destroy(&self, id: &NodeId) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// What `release` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Released {
    Destroyed,
    /// Kept warm, already paid for, until then.
    Pooled {
        until: Timestamp,
    },
    AlreadyGone,
}

/// The interface the rest of wicket uses. One implementation, [`Placer`](crate::Placer), over any
/// [`Provider`].
pub trait Placement: Send + Sync {
    /// A node for `req`: an existing one for the same idempotency key, a warm pooled one, or a new one
    /// inside the money envelope and approved by a human.
    fn acquire(&self, req: &CapacityRequest) -> impl Future<Output = Result<NodeHandle>> + Send;
    /// An owned node.
    fn get(&self, id: &NodeId) -> impl Future<Output = Result<Option<NodeHandle>>> + Send;
    /// Every owned node (for the reconciler).
    fn list(&self) -> impl Future<Output = Result<Vec<NodeHandle>>> + Send;
    fn release(&self, id: &NodeId, mode: crate::ReleaseMode) -> impl Future<Output = Result<Released>> + Send;
    /// When the node's next billing unit starts (`None`: no stepped billing).
    fn next_paid_hour_at(&self, node: &NodeHandle) -> Option<Timestamp>;
}

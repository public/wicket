//! The node control channel (#57): one multiplexed, length-prefixed byte stream between a control host
//! process (a `wicket run`, or a link relay) and a node's `wicket node serve`, carried over ssh, or
//! over the node's unix socket for this host's own node (#146).
//!
//! **Framing.** Each frame is a 4-byte big-endian length `N` (1 ≤ N ≤ [`MAX_FRAME`]) followed by `N`
//! bytes: one kind byte, then the body.
//!
//! | kind | body | what |
//! |---|---|---|
//! | `1` msg | JSON [`Msg`] | control messages both ways |
//! | `2` data | stream id (u64 BE), offset (u64 BE), bytes | a box's stdin, stdout or stderr, or a tunnel's bytes |
//! | `3` feed | one wicket-feed `Frame` line | control host → node only; verified by the node's replica |
//!
//! Integrity of policy comes from the feed's signatures, not from this channel (a tampered feed frame
//! is refused by the replica). ssh gives the channel confidentiality and checks the node's pinned host
//! key; on top of that, both ends authenticate each other before anything else (`nodeauth.rs`): the
//! node with its node key and identity certificate, the control host with the installation's issuer
//! key ([`Msg::Hello`]'s nonce, [`Msg::Challenge`], [`Msg::Prove`]).
//!
//! **Streams.** A box's stdio streams are numbered by the control host when it starts the box
//! ([`BoxStart::streams`]); their data frames carry the byte offset of their first byte, so after a
//! reconnect the receiver can say where to resume and duplicates are dropped. Tunnels (a link's
//! connection to a box on the other side) are numbered by the node with the top bit set, and die
//! with the connection.
//!
//! [`read_frame`] never panics on any input: a bad frame is an error and the connection is dropped.
//!
//! **Versions** (#162). Both ends say which protocol version they speak ([`PROTOCOL`], in
//! [`Msg::Hello`] and [`Msg::Welcome`]); they talk if the two are at most [`PROTOCOL_SKEW`] apart,
//! at the lower of the two ([`negotiate`]). That is what lets a rollout update the control host and
//! its nodes one at a time: a control host at N talks to nodes at N−1 and N, and a node at N to a
//! control host at N−1 (rolled back) and N+1. The build (sha256 of the binary) is still sent, for
//! the logs only. The rules for changing the protocol:
//! - A change either side of an older peer could misread (a new [`Msg`] variant, a new required
//!   field, a changed meaning) bumps [`PROTOCOL`]. A new field with `#[serde(default)]` that an older
//!   peer may ignore does not.
//! - A message added in version N is sent only on a connection that negotiated N or later, since an
//!   older peer drops the connection on a message it can't parse.
//! - Support for version N−1 is removed only after a release that spoke N everywhere. What versions
//!   below `PROTOCOL - PROTOCOL_SKEW` added is assumed, not checked: such a peer is refused at the
//!   handshake.

use serde::{Deserialize, Serialize};
use wicket_proxy::llm::Slice;

/// The control/node protocol version this build speaks. What each version added is in
/// docs/reference/protocol.md ("Versions and skew"). With [`PROTOCOL_SKEW`] 1, a connection talks
/// 15 or 16, so only the versions above 14 have a check here; the checks for features of 14 and
/// earlier (edge decisions, image pins, delivery and pulls, budget slices, credential swaps,
/// forwarded egress, node health, the control host's tools as [`Msg::Call`], CA renewal) went once
/// every peer had them.
pub const PROTOCOL: u32 = 16;
/// The first protocol version whose nodes say when a box has had a message the control host gave
/// it (#445): [`Msg::MessageRead`]. Until then the control host counts a message read when it
/// hands it over.
pub const MESSAGE_READ: u32 = 15;
/// The first protocol version with standing reach (#572): a node sends a box's ask for it as
/// [`Msg::AskStanding`], and the control host publishes approved rules to the node as token
/// blocks. A node at 15 neither asks for nor honours one.
pub const STANDING: u32 = 16;

/// The gateway tools the control host answers for a box (#257 slice 4b): they need its ledger, the
/// other boxes' records, the placement backend or the run's own supervisor. A box's node answers
/// every other tool itself (`nodegw`), and sends only these, by name, as [`Msg::Call`]; any other
/// name never leaves the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlTool {
    AwaitGrant,
    PendingRequests,
    SendMessage,
    AwaitMessage,
    Principals,
    Receipts,
    Spawn,
    ContinueChild,
    Delegations,
    Decide,
    Expose,
    Connect,
    Link,
    Unlink,
    Links,
    RequestCapacity,
    RequestUpdate,
    Finish,
    Hibernate,
}

impl ControlTool {
    /// The tool's name in MCP (`tools/call`'s `name`).
    pub fn name(self) -> String {
        serde_json::to_value(self).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
    }

    /// The control host's tool of this name, if it is one.
    pub fn of(name: &str) -> Option<ControlTool> {
        serde_json::from_value(serde_json::Value::String(name.into())).ok()
    }
}
/// How far apart two peers' versions may be.
pub const PROTOCOL_SKEW: u32 = 1;

/// The version two peers talk at: the lower of the two, if they are at most [`PROTOCOL_SKEW`]
/// apart. `theirs` is 0 for a peer from before protocol versions (it required the same build).
pub fn negotiate(ours: u32, theirs: u32) -> Result<u32, String> {
    if theirs == 0 {
        return Err(format!("it runs a wicket from before protocol versions (this one speaks protocol {ours})"));
    }
    // The rule itself is wicket_core::version's, which Kani checks (#325).
    wicket_core::version::talk_at(ours, theirs, PROTOCOL_SKEW)
        .ok_or_else(|| format!("it speaks protocol {theirs}, this one {ours} (at most {PROTOCOL_SKEW} apart)"))
}

// Every feature's first version is one this build speaks, and a peer at the oldest version it
// talks to still has versions (#325: what `version::talk_at`'s harnesses assume of the constants).
const _: () = {
    assert!(MESSAGE_READ <= PROTOCOL);
    assert!(STANDING <= PROTOCOL);
    assert!(PROTOCOL > PROTOCOL_SKEW);
};

/// The largest frame body: a feed snapshot (`wicket_feed::MAX_FRAME_BYTES`) plus framing.
pub const MAX_FRAME: usize = wicket_feed::MAX_FRAME_BYTES + 4096;

const KIND_MSG: u8 = 1;
const KIND_DATA: u8 = 2;
const KIND_FEED: u8 = 3;

/// Tunnel stream ids have this bit set; stdio stream ids don't.
pub const TUNNEL_BIT: u64 = 1 << 63;
/// Tunnels the control host numbers (an [`Msg::Exec`]'s) also have this bit, so they never collide
/// with the node's.
pub const CONTROL_TUNNEL_BIT: u64 = 1 << 62;

/// One frame.
#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    Msg(Msg),
    Data { stream: u64, offset: u64, bytes: Vec<u8> },
    Feed(Vec<u8>),
}

/// What a control host asks a node to run: everything `docker run` needs, the run's files, and the
/// enforcement settings the node can't learn from the feed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoxStart {
    pub run: String,
    pub tenant: String,
    pub zone: String,
    pub image: String,
    pub isolation: wicket_core::Isolation,
    pub env: Vec<(String, String)>,
    pub argv: Vec<String>,
    pub memory: String,
    pub cpus: f32,
    pub pids: u32,
    pub interactive: bool,
    /// The node kills the box itself at this deadline (seconds from start), whether or not the
    /// control host is reachable then.
    pub timeout_secs: u64,
    /// The zone's `escalation.request` (false by default for a program, #255).
    pub escalate: bool,
    /// Unused, always empty: the box's CA bundle is the installation root alone (#257 slice 5).
    /// Still sent, for nodes from before it was defaulted; to go once none can connect.
    #[serde(default)]
    pub ca_pem: String,
    /// Unused, always empty: a box's workspace is laid out by its node, never sent (#146). Still
    /// sent, for nodes from before it was defaulted; to go once none can connect.
    #[serde(default)]
    pub workspace_tar: String,
    /// Extra files under the run's state directory: (relative path, base64 contents).
    pub state_files: Vec<(String, String)>,
    /// Directories under the run's state directory the harness keeps its config in (its adapter's).
    #[serde(default)]
    pub state_dirs: Vec<String>,
    /// Volumes: (name, mount path in the box), kept per tenant and zone on the node.
    pub volumes: Vec<(String, String)>,
    /// Stream ids for stdin, stdout and stderr.
    pub streams: [u64; 3],
    /// Directories of the control host's own mounted in the box: (host path, path in the box,
    /// read-only). Only the control host's own node, which shares its filesystem, takes any (an
    /// in-place workspace, a wrapped session's directory).
    #[serde(default)]
    pub binds: Vec<(String, String, bool)>,
    /// The box's working directory, if not /workspace (a wrapped session's, on the control host's
    /// own node).
    #[serde(default)]
    pub workdir: Option<String>,
    /// The `wicket.owner` label: the control host's process supervising the box.
    #[serde(default)]
    pub owner: Option<String>,
    /// A long-lived agent's box (#70, #146): its /tmp is a directory the node keeps (not a tmpfs),
    /// so it can be moved with the rest of its state when it hibernates.
    #[serde(default)]
    pub long_lived: bool,
    /// Durable volumes of a long-lived agent: (name, mount path in the box), kept in the run's own
    /// directory on the node and moved with its state (unlike `volumes`, kept per tenant and zone).
    #[serde(default)]
    pub durable: Vec<(String, String)>,
    /// The box's Docker name (`<prefix>-<run>`), if the control host names it.
    #[serde(default)]
    pub name: Option<String>,
    /// What the run (or its long-lived agent) already spent of the zone's model budget: requests,
    /// input and output tokens. The node's model proxy starts from it (#151).
    #[serde(default)]
    pub llm_prior: (u64, u64, u64),
    /// The latest the box may be started (Unix seconds): its placed node's lease end (#395). The
    /// node refuses a start that reaches it then or later, so the control host's check at the run's
    /// start (`nodecreate::refuse_past_lease`) and the start itself can't race. None: no lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_by: Option<i64>,
    /// What the box's output may take on the node's disk (#151; the zone's `limits.output`), and
    /// whether the box is stopped when its output passes it (else the oldest output goes).
    #[serde(default = "default_output_cap")]
    pub output_cap: u64,
    #[serde(default)]
    pub output_stop: bool,
    /// The box's credential swaps, made by the node's egress proxy (#257): the box holds only each
    /// one's placeholder, and the node fetches the real credential on first use
    /// ([`Msg::SecretFetch`]), as it does injected secrets. Never a value: this is kept in the
    /// node's box record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub swaps: Vec<SwapStart>,
    /// What the node needs to decide the box's gateway tools itself (#164); without it the node
    /// relays every tool call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<Box<EdgeStart>>,
    /// The digest (`sha256:…`) the box's image must be (#192): the node refuses to start it as any
    /// other, and starts it by its id, so a retag can't swap it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_pin: Option<String>,
    /// Measure the runtime's part of the start too (#287: `WICKET_TIMINGS=1`): one more `docker
    /// inspect` for when Docker created the box and when its runtime started it. A node that
    /// doesn't know this field sends what it always measures (or nothing).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timings: bool,
    /// The zone's `limits.memory_advice` (#348), appended to the warning the node gives the agent
    /// near its memory limit. A node that doesn't know this field warns without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_advice: Option<String>,
    /// Which of [`Self::volumes`] the node keeps across runs and for how long (#377); the others
    /// are the run's own cache. None, from a control host before it: every volume is kept, as
    /// before.
    #[serde(default)]
    pub volume_life: Option<Vec<VolumeLife>>,
}

/// One credential the node swaps in for a box (#257): toward `host`, a request carrying exactly
/// `Authorization: Bearer <placeholder>` goes with the real credential instead.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SwapStart {
    /// For logs: what this credential is (never its value).
    pub name: String,
    pub host: String,
    /// What the box holds instead of the credential (it is in the box already: not a secret).
    pub placeholder: String,
    /// Where the real one comes from.
    pub real: SwapReal,
    /// Whether a bearer the box presents that isn't the placeholder goes upstream as sent
    /// (`wicket_proxy::CredentialSwap::box_bearers`).
    #[serde(default)]
    pub box_bearers: bool,
}

/// Where a swapped credential comes from. Either way the node fetches it with
/// [`Msg::SecretFetch`], under the name given here, and keeps it in memory only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapReal {
    /// A vault secret, by name: released only for the swap's hosts, if its binding covers them.
    Secret(String),
    /// A value the process that launched the agent handed the control host (a wrapped session's),
    /// fetched under this key (`swap.<n>`, never a vault secret's name).
    Value(String),
}

impl SwapReal {
    /// The name the node fetches it under.
    pub fn fetch_name(&self) -> &str {
        match self {
            SwapReal::Secret(n) | SwapReal::Value(n) => n,
        }
    }
}

/// The swaps a control host sends a node for `swaps` (the run's own): names and placeholders only.
pub fn swap_starts(swaps: &[wicket_proxy::CredentialSwap]) -> Vec<SwapStart> {
    swaps
        .iter()
        .enumerate()
        .map(|(i, s)| SwapStart {
            name: s.name.clone(),
            host: s.host.clone(),
            placeholder: s.placeholder.clone(),
            real: match &s.real {
                wicket_proxy::SwapSource::Vault(n) => SwapReal::Secret(n.clone()),
                wicket_proxy::SwapSource::Value(_) => SwapReal::Value(swap_value_key(i)),
            },
            box_bearers: s.box_bearers,
        })
        .collect()
}

/// The key a node fetches the `i`th swap's value under: a `.` is in no vault secret's name.
pub fn swap_value_key(i: usize) -> String {
    format!("swap.{i}")
}

/// What a node decides a box's gateway tools from (#164), beyond its token in the feed.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EdgeStart {
    /// Who the box is, as `whoami` shows it: its identity's stable claims (subject, agent, zone,
    /// tenant, run, parent run, principal, the chain it acts for). The identity itself (its key and
    /// signed token) stays on the control host.
    pub who: serde_json::Value,
    /// What the node decides the box's spawns from: None, they are the control host's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn: Option<EdgeSpawn>,
    /// How the box's gateway pushes incoming messages into its harness's conversation (#252), as
    /// its adapter says. None: the agent reads them with `await_message`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push: Option<wicket_agent::harness::MessagePush>,
}

/// What a node decides a box's spawns from (#164): a child within the box's authority starts on
/// the node, its token attenuated from the box's, and the control host records it when it can.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EdgeSpawn {
    /// The box's effective manifest (YAML): what a child's is planned from.
    pub manifest: String,
    /// Its base token (block 0 and its spawn links, without grants), base64url: what a child's is
    /// attenuated from.
    #[serde(default)]
    pub base: String,
    /// The keys whose grants a child's token accepts.
    #[serde(default)]
    pub grant_keys: Vec<wicket_authz::PublicKey>,
    /// Its time left when it started (seconds): a child gets no more than what is left of it.
    pub time_left_secs: u64,
    /// The box slots its children already hold (#125).
    pub slots_used: u32,
    /// Whether the org policy decides for its children as for it (#51): it reads neither the
    /// spawn depth nor the zone or its groups. Else its spawns are the control host's.
    pub org_alike: bool,
}

fn default_output_cap() -> u64 {
    64 << 20
}

/// What becomes of a box's volume (#377): kept across runs (deleted once unused for
/// `retention_secs`, if set), or the run's own cache (deleted when the run's work is collected, or
/// `retention_secs` after the run ends).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeLife {
    pub name: String,
    pub keep: bool,
    pub retention_secs: Option<u64>,
}

impl VolumeLife {
    pub fn of(m: &wicket_core::Manifest) -> Vec<VolumeLife> {
        m.zone
            .volumes
            .iter()
            .map(|v| VolumeLife { name: v.name.clone(), keep: v.keep, retention_secs: v.retention().ok().flatten().map(|d| d.as_secs()) })
            .collect()
    }
}

/// A node's size and what its running boxes take, by their limits (for bin-packing boxes onto nodes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub vcpus: f32,
    pub memory_mib: u64,
    pub used_vcpus: f32,
    pub used_memory_mib: u64,
    pub boxes: u32,
    /// The memory limit a new box may have now (#377), as the node's admission reckons it from
    /// what is actually free; None from a node before it.
    #[serde(default)]
    pub room_mib: Option<u64>,
    /// Whether the node starts no box at all now (its disk below the floor, #377).
    #[serde(default)]
    pub full: bool,
}

/// How far a box's stdio has got, as the node reports it on reconnect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunState {
    pub run: String,
    pub streams: [u64; 3],
    /// Bytes of stdin received so far (the control host resends from here).
    pub stdin_received: u64,
    /// Total bytes the box has written to stdout and stderr.
    pub stdout_total: u64,
    pub stderr_total: u64,
    /// The exit, if it has exited: (code, result.json if any).
    pub exited: Option<(i32, Option<String>)>,
    /// The oldest stdout and stderr bytes the node still holds (it drops what was acknowledged).
    #[serde(default)]
    pub stdout_start: u64,
    #[serde(default)]
    pub stderr_start: u64,
    /// When the box's authority ends (#153), as the node reads it from the box's token (Unix ms;
    /// 0: the node holds none). The node stops the box then.
    #[serde(default)]
    pub authority_until: i64,
}

/// Control messages.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "m", rename_all = "snake_case")]
pub enum Msg {
    // ---- control host → node ----
    /// First message: who is connecting, and with which protocol version (`proto`; the build is
    /// informational). `observer`: a check (`wicket dev node-feed-probe`) that only sends feed frames and reads the
    /// node's feed status; it doesn't take over the control connection.
    Hello {
        node: String,
        version: String,
        build: String,
        /// The protocol version the control host speaks (0: from before versions).
        #[serde(default)]
        proto: u32,
        #[serde(default)]
        observer: bool,
        /// The control host's handshake nonce (base64url, 32 bytes); unused by observers.
        #[serde(default)]
        nonce: String,
        /// What this connection is for (a run's id, or a link relay's): the node keeps one
        /// connection per scope, so a reconnect replaces its own older connection and no other.
        #[serde(default)]
        scope: String,
    },
    /// The control host's handshake proof, signed with the issuer key (answers [`Msg::Challenge`]).
    Prove {
        proof: wicket_identity::node::ControlProof,
    },
    /// A renewed node identity certificate for the node's key.
    NodeCert {
        cert: String,
    },
    /// Renewing the node CA (#416, protocol 14): make a new CA key and answer with its signing
    /// request ([`Msg::CaCsr`]). The key stays on the node, unused until [`Msg::NodeCa`] certifies it.
    CaRenew {},
    /// The node CA certificate for the key of the node's last [`Msg::CaCsr`] (#416).
    NodeCa {
        pem: String,
    },
    Start(Box<BoxStart>),
    /// Replay stdout and stderr from these offsets (after a reconnect).
    Resume {
        run: String,
        stdout_from: u64,
        stderr_from: u64,
    },
    /// The receiver has everything on `stream` below `upto`: the sender may drop it.
    Ack {
        stream: u64,
        upto: u64,
    },
    StdinClose {
        run: String,
    },
    /// A run's model budget slice (#152): what its node may spend of the run's model budget, offline
    /// too. Not a lease: that is a grant of capacity (#256).
    BudgetSlice {
        run: String,
        slice: Slice,
    },
    /// The answer to a [`Msg::SecretFetch`]: the secret, released for that run, or why not.
    SecretFetched {
        id: u64,
        secret: Option<Box<crate::nodesecrets::Fetched>>,
        error: Option<String>,
    },
    /// A secret the node fetched for `run` changed or was removed on the control host: the node
    /// drops the run's use of it (the next use fetches it again).
    SecretRevoke {
        run: String,
        name: String,
    },
    Kill {
        run: String,
    },
    /// The control host has the exit: the node may delete the run's files.
    Forget {
        run: String,
    },
    /// Answer to [`Msg::Ask`] and [`Msg::AskStanding`].
    Asked {
        id: u64,
        pending: Option<(String, bool)>,
        denied: Option<String>,
        error: Option<String>,
        /// For the agent, beside its answer (#572): it has asked for this before, and standing
        /// reach would save it asking again. An older node ignores it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
    },
    /// Node → control host (#257 slice 4b): one of the control host's tools for `run`'s box, with
    /// its arguments as the box gave them. Answered with [`Msg::Called`] once the tool is done (a
    /// wait, `await_grant` or `await_message`, answers when it ends).
    Call {
        id: u64,
        run: String,
        tool: ControlTool,
        args: serde_json::Value,
    },
    /// Answer to [`Msg::Call`]: the tool's text, and whether it is an error.
    Called {
        id: u64,
        text: String,
        is_error: bool,
    },
    /// Ship audit records after this node seq.
    AuditFrom {
        seq: i64,
    },
    /// Answer to [`Msg::TunnelOpen`].
    TunnelOpened {
        stream: u64,
        error: Option<String>,
    },
    /// Either way: a tunnel's writer is done.
    Close {
        stream: u64,
    },
    /// Acts on a run's box: `status` (an error unless it is running), `pause`, `unpause`, `processes`
    /// (as `user`; the answer's `out` is a JSON list of (pid, ppid, command line)), `hosts` (`arg`
    /// becomes the box's /etc/hosts) or `usage` (`out`: the bytes under tree `arg`).
    BoxCtl {
        id: u64,
        run: String,
        what: String,
        #[serde(default)]
        user: String,
        #[serde(default)]
        arg: String,
    },
    /// Runs `argv` in a run's box as `user` (`docker exec`), its stdout (and stdin, if `stdin`) joined
    /// to tunnel `stream`, which the control host numbers ([`CONTROL_TUNNEL_BIT`]). Answered with
    /// [`Msg::TunnelOpened`], then [`Msg::ExecDone`].
    Exec {
        stream: u64,
        run: String,
        user: String,
        argv: Vec<String>,
        stdin: bool,
    },
    /// Listens on unix socket `sock` in a run's socket directory (a link's relay socket, #6): each
    /// connection is offered to this connection as a tunnel to target `link:<sock>`.
    Listen {
        id: u64,
        run: String,
        sock: String,
        /// A link between two boxes on this node (#164): the node dials each connection into
        /// box `.0` at port `.1` itself, while both boxes' authority holds, instead of offering
        /// it as a tunnel; the link outlives the control connection.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dial: Option<(String, u16)>,
    },
    Unlisten {
        run: String,
        sock: String,
    },
    /// Unpacks the tar archive sent on tunnel `stream` (numbered by the control host) into one of a
    /// run's trees on the node: `workspace`, `state`, `tmp` or `volume.<name>`. Answered with
    /// [`Msg::TunnelOpened`], then [`Msg::ExecDone`] once unpacked.
    PutTree {
        stream: u64,
        run: String,
        tree: String,
    },
    /// Sends one of a run's trees on the node as a tar archive on tunnel `stream`. Answered with
    /// [`Msg::TunnelOpened`], then [`Msg::ExecDone`].
    GetTree {
        stream: u64,
        run: String,
        tree: String,
    },
    /// Whether the node has the image `digest` (`sha256:…`) names (#191). Answered with
    /// [`Msg::BoxCtlDone`], `out` `present` or `absent`.
    ImageHave {
        id: u64,
        digest: String,
    },
    /// The image `digest` names, as an OCI image layout archive on stream `stream` (numbered by
    /// the control host, [`CONTROL_TUNNEL_BIT`]), to be imported as `name` (`repository@digest`) if
    /// given (#191). Answered with [`Msg::TunnelOpened`]; then data frames, each at its offset, which
    /// the node acknowledges ([`Msg::Ack`]) as it takes them (the sender keeps a window), and a
    /// [`Msg::Close`]; then [`Msg::ImagePut`] once the node has verified and imported it, or refused
    /// it.
    PutImage {
        stream: u64,
        digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// Pull the image `digest` names from registry `from`, host-side, for `run`'s box, verify it
    /// and import it as `name` (#191). If the registry needs a credential, the node fetches its
    /// secret for `run` ([`Msg::SecretFetch`]) on this connection. Answered with
    /// [`Msg::ImagePulled`].
    PullImage {
        id: u64,
        run: String,
        digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        from: crate::registry::Source,
    },

    // ---- node → control host ----
    /// Answer to [`Msg::BoxCtl`] or [`Msg::Listen`].
    BoxCtlDone {
        id: u64,
        out: Option<String>,
        error: Option<String>,
    },
    /// An [`Msg::Exec`]'s process ended.
    ExecDone {
        stream: u64,
        code: i32,
    },
    /// The end of a [`Msg::PutImage`]: the image is verified and imported (`error` None), or why
    /// not.
    ImagePut {
        stream: u64,
        error: Option<String>,
    },
    /// Answer to [`Msg::PullImage`]: pulled, verified and imported (`error` None), or why not.
    ImagePulled {
        id: u64,
        error: Option<String>,
    },
    /// The connection that shipped audit records went away: send [`Msg::AuditFrom`] with this
    /// control host's watermark to take over.
    AuditAsk {},
    /// The node's handshake answer: its nonce, certificate and proof (answers [`Msg::Hello`]).
    Challenge {
        proof: wicket_identity::node::NodeProof,
    },
    /// Answer to [`Msg::NodeCert`]: installed, or why not.
    NodeCertInstalled {
        serial: String,
        error: Option<String>,
    },
    /// Answer to [`Msg::CaRenew`] (#416): a PEM certificate signing request for a new node CA key,
    /// or why there is none (another renewal under way, say).
    CaCsr {
        csr: Option<String>,
        error: Option<String>,
    },
    /// Answer to [`Msg::NodeCa`] (#416): the certificate (by its serial, hex) is the node's CA now,
    /// for every box it runs, or why not.
    NodeCaInstalled {
        serial: String,
        error: Option<String>,
    },
    /// Node → control host (#445): run `run`'s box has had message `id`, which the control host's
    /// `await_message` gave it: the reply that carried it is written to the box (or pushed to its
    /// session). Until this, the message is in flight, and a supervisor that takes the run over
    /// gives it again; the node drops one its box has had.
    MessageRead {
        run: String,
        id: String,
    },
    Welcome {
        node: String,
        build: String,
        /// The protocol version this connection talks ([`negotiate`]d; 0: a node from before versions).
        #[serde(default)]
        proto: u32,
        feed: wicket_feed::Hello,
        runs: Vec<RunState>,
        /// What the node has, and what its running boxes are given (for placement).
        #[serde(default)]
        capacity: Option<NodeCapacity>,
        /// Runs' directories it keeps with no record of their box (#449): not in `runs`, but
        /// `Forget` deletes them by their path.
        /// Boxed: the message enum stays small.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        orphaned: Option<Box<Vec<crate::health::OrphanedRun>>>,
    },
    /// The node won't talk to this control host (protocols too far apart, wrong node name).
    Refused {
        why: String,
    },
    Started {
        run: String,
        error: Option<String>,
        /// The image's digest as the node started it (#192).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digest: Option<String>,
        /// Where the start's time went on the node (#287), from when it took the start in.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        timings: Vec<wicket_core::timing::Span>,
    },
    Exited {
        run: String,
        code: i32,
        result: Option<String>,
        /// Why the node stopped it, if it did (#153: its authority expired).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// Where the box's own start and its end went (#287), as its node saw them: placed by the
        /// node's wall clock (`at_ms` in Unix milliseconds, `wicket_core::timing::wall_span`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        timings: Vec<wicket_core::timing::Span>,
    },
    /// An enforcement event (`wicket_proxy::Event`), for the operator's console.
    Event {
        run: String,
        event: serde_json::Value,
    },
    /// A child box this node started for `run`'s box while deciding its spawn (#164): what the
    /// control host needs to check it again and take it over (adopt it as a run of its own).
    /// Sent on `run`'s connection, at once or when it is back, until answered by
    /// [`Msg::Adopted`].
    Spawned {
        run: String,
        child: String,
        /// The child's manifest (YAML), as the node planned it.
        manifest: String,
        image: String,
        /// The child agent's session id.
        session: String,
        /// When the node started it (Unix ms, node clock).
        started_ms: i64,
        /// Its image's digest as the node started it (#192).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digest: Option<String>,
    },
    /// The control host took `child` over (`error`: it refused it, and stops it).
    Adopted {
        child: String,
        error: Option<String>,
    },
    /// Raise (or find) the pending request for this op. `queued`: raised while the control host
    /// was unreachable (#153), with its node-local id and when (Unix ms, node clock).
    Ask {
        id: u64,
        run: String,
        op: Box<wicket_core::Op>,
        why: String,
        who: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queued: Option<(String, i64)>,
        /// Every path under the op's directory, not the one path (`request_access`'s `scope:
        /// prefix`, #164).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        prefix: bool,
    },
    /// Raise (or find) `run`'s ask for standing reach (#572): `rule`, for the asking agent's later
    /// runs, in the agent's words. Answered with [`Msg::Asked`]. Sent only on a connection that
    /// talks [`STANDING`] or later.
    AskStanding {
        id: u64,
        run: String,
        rule: wicket_core::manifest::ReachRule,
        why: String,
    },
    /// A secret `run` needs now, on its first use on this node (#152): its model credential, or an
    /// injected secret. Never prefetched.
    SecretFetch {
        id: u64,
        run: String,
        name: String,
    },
    /// What the run's model proxy on the node has counted (#152): the node calls the model itself
    /// and is the counter of record; the control host takes its totals.
    Spent {
        run: String,
        spent: wicket_proxy::llm::Spent,
        /// When the box's first model request reached the node's model proxy (Unix ms, on the
        /// node's clock; #287).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_request_ms: Option<i64>,
    },
    /// Open a tunnel for `run`: a link socket (`link:<sock>`) of a box on the other side. No socket
    /// of the control host's own is a target any more (#257: `llm`, `egress` and, from protocol 13,
    /// `gateway` are gone).
    TunnelOpen {
        stream: u64,
        run: String,
        target: String,
    },
    /// The node's feed after a frame: its mode, epoch, and a refusal (with whether catch-up is needed).
    FeedStatus {
        mode: wicket_feed::Mode,
        epoch: Option<u64>,
        refused: Option<String>,
        catch_up: Option<wicket_feed::Hello>,
    },
    Audit {
        records: Vec<wicket_store::AuditRecord>,
    },
    /// The node's health (#377), every [`crate::health::REPORT_EVERY`] on each connection.
    Health {
        health: crate::health::NodeHealth,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChanError {
    #[error("frame length {0} out of range")]
    Length(usize),
    #[error("unknown frame kind {0}")]
    Kind(u8),
    #[error("short data frame")]
    Short,
    #[error("bad message: {0}")]
    Json(String),
}

impl Frame {
    /// The frame on the wire, length prefix included.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Frame::Msg(m) => {
                body.push(KIND_MSG);
                body.extend(serde_json::to_vec(m).expect("messages serialise"));
            }
            Frame::Data { stream, offset, bytes } => {
                body.push(KIND_DATA);
                body.extend(stream.to_be_bytes());
                body.extend(offset.to_be_bytes());
                body.extend(bytes);
            }
            Frame::Feed(line) => {
                body.push(KIND_FEED);
                body.extend(line);
            }
        }
        let mut out = Vec::with_capacity(body.len() + 4);
        out.extend((body.len() as u32).to_be_bytes());
        out.extend(body);
        out
    }

    /// Parses one frame body (without its length prefix).
    pub fn decode_body(body: &[u8]) -> Result<Frame, ChanError> {
        let (&kind, rest) = body.split_first().ok_or(ChanError::Length(0))?;
        match kind {
            KIND_MSG => serde_json::from_slice(rest).map(Frame::Msg).map_err(|e| ChanError::Json(e.to_string())),
            KIND_DATA => {
                if rest.len() < 16 {
                    return Err(ChanError::Short);
                }
                let stream = u64::from_be_bytes(rest[..8].try_into().expect("8 bytes"));
                let offset = u64::from_be_bytes(rest[8..16].try_into().expect("8 bytes"));
                Ok(Frame::Data { stream, offset, bytes: rest[16..].to_vec() })
            }
            KIND_FEED => Ok(Frame::Feed(rest.to_vec())),
            k => Err(ChanError::Kind(k)),
        }
    }
}

/// Reads one frame from an async reader: `None` at a clean end of stream.
pub async fn read_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Frame>> {
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    let bad = |e: ChanError| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string());
    if n == 0 || n > MAX_FRAME {
        return Err(bad(ChanError::Length(n)));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Frame::decode_body(&body).map(Some).map_err(bad)
}

/// A bounded, offset-addressed output buffer: what a sender keeps of one stream until the receiver
/// acknowledges it, so it can be replayed after a reconnect.
///
/// It holds at most `cap` bytes. When a writer outruns the cap (a box producing output while the
/// control host is unreachable for long), the **oldest** bytes are dropped: the receiver then sees a
/// gap (its resume offset is below [`OutBuf::start`]), which it reports.
pub struct OutBuf {
    start: u64,
    data: std::collections::VecDeque<u8>,
    cap: usize,
}

impl OutBuf {
    pub fn new(cap: usize) -> OutBuf {
        OutBuf { start: 0, data: Default::default(), cap }
    }

    /// An empty buffer whose next byte is at offset `at` (a stream picked up part way).
    pub fn starting_at(cap: usize, at: u64) -> OutBuf {
        OutBuf { start: at, data: Default::default(), cap }
    }

    /// The offset of the oldest byte held.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// The offset after the newest byte (total bytes ever written).
    pub fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }

    /// Appends bytes, dropping the oldest beyond the cap. Returns the offset of the first byte written.
    pub fn write(&mut self, bytes: &[u8]) -> u64 {
        let at = self.end();
        self.data.extend(bytes);
        let over = self.data.len().saturating_sub(self.cap);
        if over > 0 {
            self.data.drain(..over);
            self.start += over as u64;
        }
        at
    }

    /// Drops what the receiver has (everything below `upto`).
    pub fn ack(&mut self, upto: u64) {
        let n = upto.saturating_sub(self.start).min(self.data.len() as u64) as usize;
        self.data.drain(..n);
        self.start += n as u64;
    }

    /// Everything held from `from` on, and the offset it starts at (later than `from` if bytes were
    /// dropped).
    pub fn since(&self, from: u64) -> (u64, Vec<u8>) {
        let at = from.clamp(self.start, self.end());
        (at, self.data.iter().skip((at - self.start) as usize).copied().collect())
    }
}

/// What a receiver keeps per stream: the next offset it expects. Returns the part of `bytes` it hasn't
/// seen yet, and whether bytes were lost before it.
pub fn accept_at(next: &mut u64, offset: u64, bytes: &[u8]) -> (Vec<u8>, bool) {
    let end = offset + bytes.len() as u64;
    if end <= *next {
        return (vec![], false);
    }
    let gap = offset > *next;
    let skip = next.saturating_sub(offset) as usize;
    *next = end;
    (bytes[skip.min(bytes.len())..].to_vec(), gap)
}

/// A connection's outbound frames.
pub type Out = tokio::sync::mpsc::UnboundedSender<Frame>;

/// The tunnels open on one connection (either end): inbound bytes are handed to each tunnel's writer;
/// each tunnel's reader sends its bytes out as data frames, then a `Close`. All of them end with the
/// connection ([`Tunnels::clear`]).
#[derive(Default)]
pub struct Tunnels {
    map: std::sync::Mutex<std::collections::HashMap<u64, tokio::sync::mpsc::UnboundedSender<Option<Vec<u8>>>>>,
}

impl Tunnels {
    /// Pumps `stream` as tunnel `id` over `out`.
    pub fn attach<S>(&self, id: u64, stream: S, out: Out)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Option<Vec<u8>>>();
        self.map.lock().expect("tunnels").insert(id, tx);
        tokio::spawn(async move {
            while let Some(Some(b)) = rx.recv().await {
                if wr.write_all(&b).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.send(Frame::Data { stream: id, offset: 0, bytes: buf[..n].to_vec() }).is_err() {
                            break;
                        }
                    }
                }
            }
            // The other direction ends on the far end's own Close, or with the connection.
            let _ = out.send(Frame::Msg(Msg::Close { stream: id }));
        });
    }

    /// Bytes that arrived for tunnel `id`; false if there is no such tunnel.
    pub fn data(&self, id: u64, bytes: Vec<u8>) -> bool {
        self.map.lock().expect("tunnels").get(&id).is_some_and(|t| t.send(Some(bytes)).is_ok())
    }

    /// The far end closed tunnel `id`'s direction towards us.
    pub fn close(&self, id: u64) {
        if let Some(t) = self.map.lock().expect("tunnels").remove(&id) {
            let _ = t.send(None);
        }
    }

    /// The connection ended: every tunnel ends.
    pub fn clear(&self) {
        for (_, t) in self.map.lock().expect("tunnels").drain() {
            let _ = t.send(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #257 slice 4b: the control host's tools are a closed set, sent by their MCP names, and a call
    /// and its answer are typed messages (protocol 13, which every peer talks).
    #[test]
    fn the_control_hosts_tools_are_typed_calls() {
        assert_eq!(ControlTool::of("await_grant"), Some(ControlTool::AwaitGrant));
        assert_eq!(ControlTool::RequestCapacity.name(), "request_capacity");
        for local in ["whoami", "request_access", "spawn_agent", "anything", ""] {
            assert_eq!(ControlTool::of(local), None, "{local}: answered on the node, never sent");
        }
        let m = Msg::Call { id: 3, run: "r".into(), tool: ControlTool::Links, args: serde_json::json!({}) };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v, serde_json::json!({ "m": "call", "id": 3, "run": "r", "tool": "links", "args": {} }));
        assert!(matches!(serde_json::from_value(v).unwrap(), Msg::Call { tool: ControlTool::Links, .. }));
        let bad = serde_json::json!({ "m": "call", "id": 3, "run": "r", "tool": "whoami", "args": {} });
        assert!(serde_json::from_value::<Msg>(bad).is_err(), "a tool outside the set isn't a call");
    }

    fn samples() -> Vec<Frame> {
        let op = wicket_core::Op::egress(
            &wicket_core::TenantId::single(),
            &wicket_core::RunId("run_a".into()),
            "z",
            "GET",
            "api.example.com",
            "/x",
        );
        vec![
            Frame::Msg(Msg::Hello {
                node: "n1".into(),
                version: "0.0.1".into(),
                build: "ab".repeat(32),
                proto: PROTOCOL,
                observer: false,
                nonce: "A".repeat(43),
                scope: "run_a".into(),
            }),
            Frame::Msg(Msg::Challenge {
                proof: wicket_identity::node::NodeProof { nonce: "B".repeat(43), cert: "a.b.c".into(), proof: "d.e.f".into() },
            }),
            Frame::Msg(Msg::Ask {
                id: 7,
                run: "run_a".into(),
                op: Box::new(op),
                why: "out of reach".into(),
                who: None,
                queued: Some(("q-1".into(), 5)),
                prefix: true,
            }),
            Frame::Msg(Msg::Welcome {
                node: "n1".into(),
                build: "x".into(),
                proto: PROTOCOL,
                feed: wicket_feed::Hello::default(),
                runs: vec![RunState {
                    run: "run_a".into(),
                    streams: [1, 2, 3],
                    stdin_received: 5,
                    stdout_total: 9,
                    stderr_total: 0,
                    exited: Some((0, None)),
                    stdout_start: 2,
                    stderr_start: 0,
                    authority_until: 1,
                }],
                capacity: Some(NodeCapacity {
                    vcpus: 2.0,
                    memory_mib: 2048,
                    used_vcpus: 1.0,
                    used_memory_mib: 512,
                    boxes: 1,
                    ..Default::default()
                }),
                orphaned: Some(Box::new(vec![crate::health::OrphanedRun { run: "run_b".into(), bytes: 4096 }])),
            }),
            Frame::Msg(Msg::ImageHave { id: 3, digest: format!("sha256:{}", "a".repeat(64)) }),
            Frame::Msg(Msg::PutImage {
                stream: TUNNEL_BIT | CONTROL_TUNNEL_BIT | 5,
                digest: format!("sha256:{}", "a".repeat(64)),
                name: Some(format!("docker.io/library/x@sha256:{}", "a".repeat(64))),
            }),
            Frame::Msg(Msg::ImagePut { stream: TUNNEL_BIT | CONTROL_TUNNEL_BIT | 5, error: Some("tampered".into()) }),
            Frame::Msg(Msg::PullImage {
                id: 9,
                run: "run_a".into(),
                digest: format!("sha256:{}", "a".repeat(64)),
                name: None,
                from: crate::registry::Source {
                    host: "registry.example.com".into(),
                    repository: "team/agent".into(),
                    secret: Some("reg".into()),
                    ..Default::default()
                },
            }),
            Frame::Msg(Msg::ImagePulled { id: 9, error: None }),
            Frame::Data { stream: TUNNEL_BIT | 4, offset: 1 << 40, bytes: b"hello\0world".to_vec() },
            Frame::Data { stream: 2, offset: 0, bytes: vec![] },
            Frame::Feed(br#"{"t":"fresh","jws":"a.b.c"}"#.to_vec()),
        ]
    }

    /// Every frame `read_frame` gets from `bytes`, until the end or the first error.
    fn read_all(bytes: &[u8]) -> (Vec<Frame>, Option<String>) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let mut r = bytes;
            let mut got = vec![];
            loop {
                match read_frame(&mut r).await {
                    Ok(Some(f)) => got.push(f),
                    Ok(None) => return (got, None),
                    Err(e) => return (got, Some(e.to_string())),
                }
            }
        })
    }

    #[test]
    fn frames_round_trip_whatever_the_reads_return() {
        let wire: Vec<u8> = samples().iter().flat_map(Frame::encode).collect();
        assert_eq!(read_all(&wire), (samples(), None));
        // A reader that returns a few bytes at a time.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let got = rt.block_on(async {
            let (mut a, mut b) = tokio::io::duplex(3);
            let w = wire.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                a.write_all(&w).await.unwrap();
            });
            let mut got = vec![];
            while let Ok(Some(f)) = read_frame(&mut b).await {
                got.push(f);
                if got.len() == samples().len() {
                    break;
                }
            }
            got
        });
        assert_eq!(got, samples());
    }

    #[test]
    fn bad_lengths_and_kinds_are_errors() {
        assert!(read_all(&0u32.to_be_bytes()).1.unwrap().contains("length 0"));
        assert!(read_all(&((MAX_FRAME + 1) as u32).to_be_bytes()).1.unwrap().contains("out of range"));
        assert!(read_all(&[0, 0, 0, 9, 1]).1.is_some(), "truncated");
        assert_eq!(Frame::decode_body(&[9, 1, 2]), Err(ChanError::Kind(9)));
        assert_eq!(Frame::decode_body(&[KIND_DATA, 1, 2]), Err(ChanError::Short));
        assert!(matches!(Frame::decode_body(&[KIND_MSG, b'{']), Err(ChanError::Json(_))));
    }

    /// A deterministic mutation loop over valid frames (bit flips, truncation, splices, length
    /// rewrites, random bytes): `read_frame` must never panic, whatever it is fed.
    #[test]
    fn the_reader_never_panics_on_mutated_input() {
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let base: Vec<Vec<u8>> = samples().iter().map(Frame::encode).collect();
        for _ in 0..20_000 {
            let mut b = base[(rnd() % base.len() as u64) as usize].clone();
            for _ in 0..(rnd() % 4 + 1) {
                match rnd() % 6 {
                    0 if !b.is_empty() => {
                        let i = (rnd() % b.len() as u64) as usize;
                        b[i] ^= 1 << (rnd() % 8);
                    }
                    1 => b.truncate((rnd() % (b.len() as u64 + 1)) as usize),
                    2 => {
                        let other = &base[(rnd() % base.len() as u64) as usize];
                        let at = (rnd() % (b.len() as u64 + 1)) as usize;
                        b.splice(at..at, other.iter().copied());
                    }
                    3 if b.len() >= 4 => b[..4].copy_from_slice(&((rnd() % 64) as u32).to_be_bytes()),
                    4 => b.extend((0..rnd() % 32).map(|_| rnd() as u8)),
                    _ if b.len() > 4 => b[4] = rnd() as u8,
                    _ => {}
                }
            }
            let _ = read_all(&b);
        }
    }

    #[test]
    fn output_buffers_replay_from_an_offset_and_drop_the_oldest_past_the_cap() {
        let mut b = OutBuf::new(8);
        assert_eq!(b.write(b"abcd"), 0);
        assert_eq!(b.write(b"efgh"), 4);
        assert_eq!(b.since(2), (2, b"cdefgh".to_vec()));
        b.ack(3);
        assert_eq!((b.start(), b.end()), (3, 8));
        // Past the cap: the oldest go, and a resume from before them gets a later offset (a gap).
        b.write(b"ijklmn");
        assert_eq!((b.start(), b.end()), (6, 14));
        assert_eq!(b.since(0), (6, b"ghijklmn".to_vec()));
        assert_eq!(b.since(99), (14, vec![]));
        b.ack(1_000);
        assert_eq!((b.start(), b.end()), (14, 14));
    }

    #[test]
    fn receivers_drop_duplicates_and_notice_gaps() {
        let mut next = 0;
        assert_eq!(accept_at(&mut next, 0, b"abc"), (b"abc".to_vec(), false));
        assert_eq!(accept_at(&mut next, 0, b"abc"), (vec![], false), "a replay");
        assert_eq!(accept_at(&mut next, 2, b"cde"), (b"de".to_vec(), false), "an overlap");
        assert_eq!(accept_at(&mut next, 9, b"x"), (b"x".to_vec(), true), "a gap");
        assert_eq!(next, 10);
    }

    #[test]
    fn peers_talk_within_the_skew_at_the_lower_version() {
        assert_eq!(negotiate(5, 5), Ok(5));
        assert_eq!(negotiate(5, 4), Ok(4), "a control host at N, a node at N-1");
        assert_eq!(negotiate(4, 5), Ok(4), "a node at N, a control host rolled back to N-1");
        assert!(negotiate(5, 3).unwrap_err().contains("at most 1 apart"));
        assert!(negotiate(3, 5).is_err());
        assert!(negotiate(PROTOCOL, 0).unwrap_err().contains("before protocol versions"));
    }

    /// #256: a budget slice is `budget_slice` on the wire, from protocol 9; the old name is gone
    /// (unreleased, so no alias), and a node talking 8 is sent none.
    #[test]
    fn a_budget_slice_is_its_own_message_from_protocol_9() {
        let slice = Slice { requests: 3, output_tokens: 100, input_tokens: Some(7) };
        let v = serde_json::to_value(Msg::BudgetSlice { run: "r".into(), slice }).unwrap();
        assert_eq!(v, serde_json::json!({"m":"budget_slice","run":"r","slice":{"requests":3,"output_tokens":100,"input_tokens":7}}));
        let back: Msg = serde_json::from_value(v).unwrap();
        assert!(matches!(back, Msg::BudgetSlice { slice: s, .. } if s == slice));
        let old = serde_json::json!({"m":"lease","run":"r","lease":{"slice":{"requests":3,"output_tokens":100}}});
        assert!(serde_json::from_value::<Msg>(old).is_err(), "no alias for the old name");
    }

    /// Why this build has no checks for features of protocol 15 or before (message reads, #445,
    /// the last): a peer below 15 can't connect, so every connection talks 15 or 16, and a check for
    /// a feature of version N matters only while a peer at N - 1 can connect. 16 (standing reach,
    /// #572) keeps its check for as long as a node at 15 can connect. (`MESSAGE_READ`'s check stays
    /// until a release has removed it.)
    #[test]
    fn no_connection_talks_below_protocol_15() {
        assert_eq!((PROTOCOL, PROTOCOL_SKEW, MESSAGE_READ, STANDING), (16, 1, 15, 16));
        for theirs in 1..=PROTOCOL + 3 {
            match negotiate(PROTOCOL, theirs) {
                Ok(at) => assert!((15..=16).contains(&at) && (15..=17).contains(&theirs), "{theirs} -> {at}"),
                Err(_) => assert!(!(15..=17).contains(&theirs), "{theirs} refused"),
            }
        }
        // And a node at 16 or 17 talking to a control host at 16 from the other side.
        assert_eq!(negotiate(17, PROTOCOL), Ok(16));
        assert!(negotiate(15, PROTOCOL).unwrap() < STANDING, "a node at 15 sends no AskStanding, and gets no standing block");
        assert!(negotiate(PROTOCOL, 14).is_err() && negotiate(14, PROTOCOL).is_err());
    }

    /// #257: a box's swaps go in its start as names and placeholders, never values, and a start
    /// without them reads as having none.
    #[test]
    fn a_start_carries_its_swaps_by_name() {
        let swaps = vec![
            wicket_proxy::CredentialSwap {
                name: "account login".into(),
                host: "api.example.com".into(),
                placeholder: "wkt-placeholder".into(),
                real: wicket_proxy::SwapSource::Vault("login".into()),
                box_bearers: true,
            },
            wicket_proxy::CredentialSwap {
                name: "session".into(),
                host: "sessions.example.com".into(),
                placeholder: "wkt-other".into(),
                real: wicket_proxy::SwapSource::Value("the-real-session-token".into()),
                box_bearers: false,
            },
        ];
        let sent = swap_starts(&swaps);
        assert_eq!(sent[0].real, SwapReal::Secret("login".into()));
        assert_eq!(sent[1].real, SwapReal::Value("swap.1".into()));
        assert!(sent[0].box_bearers && !sent[1].box_bearers);
        let wire = serde_json::to_string(&sent).unwrap();
        assert!(!wire.contains("the-real-session-token"), "a value never goes in a start: {wire}");
        let v = serde_json::to_value(&sent[1]).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"name":"session","host":"sessions.example.com","placeholder":"wkt-other","real":{"value":"swap.1"},"box_bearers":false})
        );
        assert_eq!(serde_json::from_value::<SwapStart>(v).unwrap(), sent[1]);
        assert_eq!(sent[1].real.fetch_name(), "swap.1");
        assert!(!wicket_proxy::vault::Vault::new("/nonexistent".into()).has("swap.1"), "not a vault name");
    }

    #[test]
    fn a_hello_or_welcome_without_a_version_parses_as_version_0() {
        let h: Msg = serde_json::from_str(r#"{"m":"hello","node":"n1","version":"0.0.1","build":"x"}"#).unwrap();
        assert!(matches!(h, Msg::Hello { proto: 0, .. }));
        let w: Msg = serde_json::from_value(
            serde_json::json!({"m":"welcome","node":"n1","build":"x","feed":wicket_feed::Hello::default(),"runs":[]}),
        )
        .unwrap();
        assert!(matches!(w, Msg::Welcome { proto: 0, .. }));
    }

    #[test]
    fn start_timings_are_optional_both_ways() {
        // From a node before #287: no timings, no first request.
        let st: Msg = serde_json::from_str(r#"{"m":"started","run":"r","error":null}"#).unwrap();
        assert!(matches!(st, Msg::Started { ref timings, .. } if timings.is_empty()));
        let sp: Msg =
            serde_json::from_value(serde_json::json!({"m":"spent","run":"r","spent":wicket_proxy::llm::Spent::default()})).unwrap();
        assert!(matches!(sp, Msg::Spent { first_request_ms: None, .. }));
        // To one: nothing new on the wire when there is nothing to say.
        let quiet = serde_json::to_value(Msg::Started { run: "r".into(), error: None, digest: None, timings: vec![] }).unwrap();
        assert!(quiet.get("timings").is_none());
        let span = wicket_core::timing::Span { name: "docker.run".into(), at_ms: 1.0, ms: 2.0 };
        let said = Msg::Started { run: "r".into(), error: None, digest: None, timings: vec![span.clone()] };
        let back: Msg = serde_json::from_value(serde_json::to_value(&said).unwrap()).unwrap();
        assert!(matches!(back, Msg::Started { timings, .. } if timings == vec![span]));
        // The exit's timings, likewise.
        let old: Msg = serde_json::from_str(r#"{"m":"exited","run":"r","code":0,"result":null}"#).unwrap();
        assert!(matches!(old, Msg::Exited { ref timings, .. } if timings.is_empty()));
        let quiet = serde_json::to_value(Msg::Exited { run: "r".into(), code: 0, result: None, reason: None, timings: vec![] }).unwrap();
        assert!(quiet.get("timings").is_none());
    }
}

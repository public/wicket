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
//! reconnect the receiver can say where to resume and duplicates are dropped. Tunnels (a forwarded
//! CONNECT, or a connection to the run's LLM or MCP gateway socket on the control host) are numbered
//! by the node with the top bit set, and die with the connection.
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
//! - Support for version N−1 is removed only after a release that spoke N everywhere.
//!
//! Version 3 (#152, #153) adds [`Msg::Lease`] (budget slices), [`Msg::SecretFetch`],
//! [`Msg::SecretFetched`], [`Msg::SecretRevoke`] (secrets fetched by a node on first use) and
//! [`Msg::Spent`] (the node's model spend), sent only on connections that negotiated 3; a
//! version-3 control host no longer sends [`Msg::RunLease`], which a version-3 node accepts and
//! ignores (a box's authority decides when it stops). With an older peer, a node relays model calls
//! and forwards injected hosts to the control host, as before.

use serde::{Deserialize, Serialize};

/// The control/node protocol version this build speaks.
///
/// - 1: versions (#162).
/// - 2: box tokens may be minted by a certified authority issuing key, and carry its certificate
///   (`BoxAuthority::issuer_cert`, #154), which a version-1 node can't read: sent only to nodes
///   talking [`ISSUER_CERT`] or later.
/// - 3: budget slices, secrets fetched by a node on first use, and its model spend (#152, #153):
///   [`Msg::Lease`], [`Msg::SecretFetch`], [`Msg::SecretFetched`], [`Msg::SecretRevoke`] and
///   [`Msg::Spent`], sent only on connections talking [`NODE_LEASES`] or later.
pub const PROTOCOL: u32 = 3;
/// The first protocol version whose nodes take issuing-key tokens (#154).
pub const ISSUER_CERT: u32 = 2;
/// The first protocol version whose nodes and control hosts lease slices and fetch secrets (#152).
pub const NODE_LEASES: u32 = 3;
/// How far apart two peers' versions may be.
pub const PROTOCOL_SKEW: u32 = 1;

/// The version two peers talk at: the lower of the two, if they are at most [`PROTOCOL_SKEW`]
/// apart. `theirs` is 0 for a peer from before protocol versions (it required the same build).
pub fn negotiate(ours: u32, theirs: u32) -> Result<u32, String> {
    if theirs == 0 {
        return Err(format!("it runs a wicket from before protocol versions (this one speaks protocol {ours})"));
    }
    if ours.abs_diff(theirs) > PROTOCOL_SKEW {
        return Err(format!("it speaks protocol {theirs}, this one {ours} (at most {PROTOCOL_SKEW} apart)"));
    }
    Ok(ours.min(theirs))
}

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
    /// False for programs with `on_pending: fail`.
    pub escalate: bool,
    /// The box's CA bundle: the installation root (node-minted leaves) and the run's own CA (hosts the
    /// control host terminates).
    pub ca_pem: String,
    /// The workspace, as a tar archive (base64).
    pub workspace_tar: String,
    /// Extra files under the run's state directory: (relative path, base64 contents).
    pub state_files: Vec<(String, String)>,
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
    /// What the box's output may take on the node's disk (#151; the zone's `limits.output`), and
    /// whether the box is stopped when its output passes it (else the oldest output goes).
    #[serde(default = "default_output_cap")]
    pub output_cap: u64,
    #[serde(default)]
    pub output_stop: bool,
    /// Hosts whose credential the control host swaps in for the box (a remote session's login,
    /// #169): the node forwards them to the run's egress proxy, never terminating them itself, so
    /// the swap happens where the secret is. Names only. An older node ignores it and terminates
    /// them, so the box's placeholder never reaches the host and the request fails, closed.
    #[serde(default)]
    pub swap_hosts: Vec<String>,
}

fn default_output_cap() -> u64 {
    64 << 20
}

/// A node's size and what its running boxes take, by their limits (for bin-packing boxes onto nodes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub vcpus: f32,
    pub memory_mib: u64,
    pub used_vcpus: f32,
    pub used_memory_mib: u64,
    pub boxes: u32,
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
    /// Version 1 only: the control host's lease of a run. Accepted from a version-1 control host and
    /// ignored (#153: the box's authority decides when it stops).
    RunLease {
        run: String,
        until: i64,
    },
    /// A run's model budget slice (#152).
    Lease {
        run: String,
        lease: Box<crate::nodesecrets::Lease>,
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
    /// Answer to [`Msg::Ask`].
    Asked {
        id: u64,
        pending: Option<(String, bool)>,
        denied: Option<String>,
        error: Option<String>,
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
    },
    /// The node won't talk to this control host (protocols too far apart, wrong node name).
    Refused {
        why: String,
    },
    Started {
        run: String,
        error: Option<String>,
    },
    Exited {
        run: String,
        code: i32,
        result: Option<String>,
    },
    /// An enforcement event (`wicket_proxy::Event`), for the operator's console.
    Event {
        run: String,
        event: serde_json::Value,
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
    },
    /// Open a tunnel to the run's `target` socket on the control host: `egress`, `llm` or `gateway`.
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
            Frame::Msg(Msg::Ask { id: 7, run: "run_a".into(), op: Box::new(op), why: "out of reach".into(), who: None, queued: Some(("q-1".into(), 5)) }),
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
                capacity: Some(NodeCapacity { vcpus: 2.0, memory_mib: 2048, used_vcpus: 1.0, used_memory_mib: 512, boxes: 1 }),
            }),
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
}

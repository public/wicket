//! `wicket`: the proof-of-concept command line.
//!
//! `wicket run task.yaml` starts the run's enforcement points (egress proxy, LLM proxy) on unix
//! sockets, starts Claude Code in a gVisor box with no network, streams what happens, and records
//! every decision in the ledger. `wicket approve` / `wicket deny` decide pending escalations from
//! another terminal while the run waits.

mod audit_export;
mod capacity;
mod chan;
mod ci_update;
mod daemon;
mod doctor;
mod enrol;
mod hibernate;
mod image;
mod links;
mod localnode;
mod mock;
mod node;
mod nodeauth;
mod nodecall;
mod noderun;
mod nodesecrets;
mod nodesrv;
mod place;
mod policy;
mod program;
mod reap;
mod reconcile;
mod roots;
mod run;
mod s3;
mod serve;
mod spawn;
mod state;
mod statestore;
mod transcript;
mod update;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Duration;
use wicket_core::TenantId;
use wicket_proxy::vault::Vault;
use wicket_store::{Approval, Ledger};

#[derive(Parser)]
#[command(name = "wicket", version, about = "Run agents in least-privilege sandboxes (proof of concept)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Set up this installation's identity issuer: its key and its trust domain, which every agent's
    /// SPIFFE ID is under (spiffe://<domain>/t/…). The domain is fixed once set.
    Init {
        /// e.g. wicket.example.com: lowercase letters, digits, '.', '-' and '_'.
        #[arg(long)]
        trust_domain: String,
    },
    /// Print the installation issuer's public key (JWK) and trust domain: what verifiers need.
    Issuer,
    /// Verify and show the identity wicket issued for a run.
    Show { run: String },
    /// List every agent identity issued, verified.
    List,
    /// Revoke a run's identity at once (e.g. if its environment may be compromised): its box is
    /// stopped, its messages are no longer delivered, and its requests can't be approved.
    Revoke {
        run: String,
        #[arg(long, default_value = "revoked by the operator")]
        reason: String,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a task manifest: one Claude Code agent in one zone.
    Run {
        manifest: PathBuf,
        /// Copy this directory into the box's /workspace first.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// Mount this directory as the box's /workspace, read-write and in place (local runs only).
        #[arg(long)]
        workspace_dir: Option<PathBuf>,
        /// Use this task text instead of the manifest's.
        #[arg(long)]
        task: Option<String>,
        /// Agent image, overriding the manifest's agent.image (default: that, or the installation's
        /// agent image).
        #[arg(long)]
        image: Option<String>,
        /// Run the box on an enrolled node (its name; its host key is pinned), through its `wicket
        /// node serve`. Default: this host's own node, `local`.
        #[arg(long)]
        node: Option<String>,
        /// ssh identity for --node (default: the one it was enrolled with).
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// Internal: the run id to use (set by a parent starting a child agent).
        #[arg(long, hide = true)]
        run_id: Option<String>,
        /// Internal: the run that started this one (`spawn_agent`).
        #[arg(long, hide = true)]
        parent_run: Option<String>,
        /// Internal: the capacity lease this run is placed on (`spawn` with `placement: {lease}`).
        #[arg(long, hide = true)]
        lease: Option<String>,
        /// Internal: take over a child its node started (#164): `<started ms>:<session id>`.
        #[arg(long, hide = true)]
        adopt: Option<String>,
    },
    /// Send a follow-up message to a running agent, as its operator. It arrives as the agent's next
    /// turn; the session stays open for follow-ups for the agent's idle_timeout after each turn. A
    /// long-lived agent can be named by its id or any of its runs; a hibernated one is woken.
    Say { run: String, text: Vec<String> },
    /// Hibernate a long-lived agent (by run or agent id) at its next quiet point: its turn has ended
    /// and nothing but the agent runs in its box. Otherwise it stays idle (paused).
    Hibernate {
        run: String,
        /// How long to wait for the outcome (seconds).
        #[arg(long, default_value_t = 120)]
        wait: u64,
    },
    /// Wake a hibernated agent: rebuild its box, restore its state and resume its session. Runs the
    /// woken activation in the foreground, like `wicket run`. Text, if given, is the operator's
    /// message to it.
    Wake {
        agent: String,
        text: Vec<String>,
        /// What woke it (recorded and told to the agent).
        #[arg(long, hide = true)]
        by: Option<String>,
    },
    /// Long-lived agents: state, generation, current run and bundle size.
    Agents {
        #[arg(long)]
        json: bool,
    },
    /// Supervise a run again whose supervisor died (#151): what `wicket reconcile` starts for a run
    /// still running on its node.
    #[command(hide = true)]
    Attach { run: String },
    /// Run an agent command line that another program launches, inside a wicket box: e.g. as Claude
    /// Code Remote Control's CLAUDE_CODE_PROCESS_WRAPPER. Its stdin and stdout stay connected to the
    /// launcher, its credentials become placeholders swapped at the proxy, and wicket logs to a file.
    Wrap {
        #[arg(long)]
        manifest: PathBuf,
        /// Agent image, overriding the manifest's agent.image.
        #[arg(long)]
        image: Option<String>,
        /// The agent command line, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// List pending escalation requests.
    Pending,
    /// Approve a pending request. The grant is never wider than the request.
    Approve {
        id: String,
        /// Number of uses (default 1).
        #[arg(long, default_value_t = 1, conflicts_with = "unlimited")]
        uses: u32,
        /// Unlimited uses until expiry.
        #[arg(long)]
        unlimited: bool,
        /// Grant lifetime.
        #[arg(long, default_value = "10m")]
        ttl: String,
        /// Grant a path prefix of the requested path instead of the exact path.
        #[arg(long)]
        prefix: Option<String>,
        /// Don't ask for confirmation at a terminal (the request is printed either way).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Let any run in the request's zone use the grant, until it expires. By default only the
        /// run that asked may, and the grant ends with that run.
        #[arg(long)]
        zone_wide: bool,
    },
    /// Deny a pending request.
    Deny { id: String },
    /// Links between boxes (expose/connect/link), newest first.
    Links {
        #[arg(long, default_value_t = 40)]
        tail: usize,
    },
    /// Cut a link between boxes: its relay closes it and drops its connections within seconds.
    Unlink { id: String },
    /// Grants made by approvals.
    Grant {
        #[command(subcommand)]
        cmd: GrantCmd,
    },
    /// Show or verify the hash-chained audit log, or export it to the configured sinks.
    Audit {
        #[arg(long, default_value_t = 40)]
        tail: usize,
        #[arg(long)]
        verify: bool,
        /// With --verify: also check the local chain against exported records and signed
        /// checkpoints (JSON lines, or a Collector's OTLP JSON file output). Catches a rewritten
        /// or truncated chain. `store:<sink>`: what a `store` sink wrote to the state store.
        #[arg(long, requires = "verify")]
        against: Vec<PathBuf>,
        /// The issuer public key (JWK, as `wicket identity issuer` prints it) checkpoints must be
        /// signed with. Default: this installation's issuer key.
        #[arg(long, requires = "against")]
        issuer_jwk: Option<PathBuf>,
        #[command(subcommand)]
        cmd: Option<AuditCmd>,
    },
    /// Manage vault secrets (values are read from the terminal, never from arguments).
    Secret {
        #[command(subcommand)]
        cmd: SecretCmd,
    },
    /// Build the agent image (the image directory plus the in-box forwarder's source, compiled in the
    /// build). Without --dir, from the copy embedded in this binary, so the image matches it.
    Image {
        #[arg(long, default_value = "wicket/claude-code:poc")]
        tag: String,
        /// An image directory to build instead (e.g. images/claude-code, while changing it).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Serve the operator console (runs, approvals, activity; start, steer and revoke runs). Plain
    /// HTTP on loopback by default; any other address needs HTTPS (--acme-domain, or --tls-cert and
    /// --tls-key) or --behind-tls-terminator.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        /// Browser origin for WebAuthn (default: http://localhost:PORT; https://DOMAIN with ACME).
        #[arg(long)]
        origin: Option<String>,
        /// WebAuthn relying-party id (default: the origin's host).
        #[arg(long)]
        rp_id: Option<String>,
        /// Serve HTTPS with this certificate chain (PEM; re-read when it changes).
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// The certificate's private key (PEM).
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// Serve HTTPS with a certificate from an ACME CA (Let's Encrypt) for this name, validated
        /// with TLS-ALPN-01 on this listener (so listen on :443).
        #[arg(long)]
        acme_domain: Option<String>,
        /// Accept the ACME CA's terms of service (required with --acme-domain).
        #[arg(long)]
        acme_agree_tos: bool,
        /// Contact for the ACME account (mailto:...; repeatable).
        #[arg(long)]
        acme_contact: Vec<String>,
        /// Use Let's Encrypt's staging CA (untrusted certificates; for trying the setup).
        #[arg(long)]
        acme_staging: bool,
        /// Another ACME directory URL.
        #[arg(long)]
        acme_directory: Option<String>,
        /// Where the ACME account and certificate are kept (default $WICKET_HOME/acme).
        #[arg(long)]
        acme_cache: Option<PathBuf>,
        /// A TLS-terminating proxy in front serves the console's https:// --origin; listen in plain HTTP.
        #[arg(long)]
        behind_tls_terminator: bool,
        /// The proxy's address or range (repeatable): its X-Forwarded-For names the client.
        #[arg(long)]
        trusted_proxy: Vec<String>,
        /// Most simultaneous connections.
        #[arg(long, default_value_t = 256)]
        max_connections: usize,
        /// Don't print a passkey enrolment link at start when no passkey is enrolled (a system
        /// install's log may be readable by operators; root prints one with `operator enrol-link`).
        #[arg(long)]
        no_bootstrap_link: bool,
    },
    /// Programs: deterministic workloads that run without an agent.
    Program {
        #[command(subcommand)]
        cmd: ProgramCmd,
    },
    /// Operator passkeys.
    Operator {
        #[command(subcommand)]
        cmd: OperatorCmd,
    },
    /// Agent identities (design §3.2): the issuer's public key, and verified identity documents.
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Stop orphaned boxes: boxes whose `wicket run` process has died (killed hard, or crashed) and
    /// that Docker kept running with nothing behind them. Their runs end as "lost".
    Reap {
        /// Only list what would be stopped.
        #[arg(long)]
        dry_run: bool,
        /// Reap on a remote node over ssh instead (e.g. wicket@203.0.113.7).
        #[arg(long)]
        node: Option<String>,
        /// ssh identity for --node.
        #[arg(long)]
        ssh_key: Option<PathBuf>,
    },
    /// The installation's org policy in Cedar (#51): a ceiling and forbids over every zone, compiled
    /// into each box's token when it is minted.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Control-plane state off this host (#154): the state store, the ledger's stream, the recovery
    /// kit and a restore onto a standby.
    State {
        #[command(subcommand)]
        cmd: StateCmd,
    },
    /// The installation's root keys (#154).
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Make what exists agree with the ledger (#38): end runs whose process is gone, end leases past
    /// their end or whose run ended, destroy owned machines no lease needs (checking the owner tag again
    /// right before each destroy), adopt or create the ones leases need, and stop boxes whose run has
    /// ended, here and on enrolled nodes. Records every change in the audit log.
    Reconcile {
        /// Only report what would change.
        #[arg(long)]
        dry_run: bool,
        /// Keep running, one pass per interval (e.g. 30s).
        #[arg(long)]
        every: Option<String>,
    },
    /// Capacity leases (#7): nodes agents asked for with request_capacity. Approve or deny the ask with
    /// `wicket approve`/`deny` (see `wicket pending`).
    Lease {
        #[command(subcommand)]
        cmd: LeaseCmd,
    },
    /// The zone view of a manifest: for each host its reach names, whether the egress proxy inspects
    /// it (terminates TLS and decides every request) or splices it through (decides on the hostname,
    /// relays the encrypted bytes), and why (#62).
    Zone {
        /// The manifest (YAML).
        manifest: PathBuf,
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Check the environment: Docker, gVisor, image, secrets, ledger, orphaned boxes.
    Doctor {
        #[arg(long, default_value = "wicket/claude-code:poc")]
        image: String,
    },
    /// Remote sandbox nodes (#16): one-time join tokens, enrolment with a pinned ssh host key, a node
    /// key and a name-constrained node CA; listing, revoking, renewing the CA.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Nodes from a provider (#37): Vultr plans, owned nodes, create inside a money envelope with a
    /// terminal approval and enrol with the host key pinned at creation, release.
    Place {
        #[command(subcommand)]
        cmd: place::PlaceCmd,
    },
    /// Development helpers.
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
    /// Update this installation to another wicket build (#162): blue/green, with a health gate and
    /// automatic rollback, on the control host and then its nodes. Only artifacts signed by a
    /// release key this installation trusts, or whose sha256 a human approved (an agent's
    /// `request_update`), are accepted. See docs/explanation/updates.md.
    #[command(name = "self")]
    Itself {
        #[command(subcommand)]
        cmd: SelfCmd,
    },
    /// wicketd (#12): run as the wicket system user and serve other users' commands over a unix
    /// socket, letting each caller do what the policy grants its uid (from SO_PEERCRED). Approving,
    /// denying and other privileged commands need root over the socket, or a passkey in the console.
    /// Installed and started by deploy/install.sh.
    Daemon {
        #[arg(long, default_value = daemon::SOCKET_PATH)]
        socket: PathBuf,
        /// Who may read, run and revoke (YAML; default: the wicket-operators group).
        #[arg(long, default_value = daemon::policy::POLICY_PATH)]
        policy: PathBuf,
    },
}

#[derive(Subcommand)]
enum LeaseCmd {
    /// Every lease: status, holder run, node, money reserved, end.
    List,
    /// End a lease now: what runs on it stops and its node is destroyed (one reconcile pass).
    Release { id: String },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Feed the sinks in the sinks file (`audit-sinks.yaml` in the data dir, or
    /// $WICKET_AUDIT_SINKS) until stopped. Runs alongside `wicket run` and `wicket serve`, which
    /// feed the sinks too; each sink is fed by one process at a time. The only process that writes
    /// to a `path: "-"` (stdout) sink.
    Export {
        /// One pass, then exit (non-zero if a sink failed).
        #[arg(long)]
        once: bool,
        /// Send every sink a checkpoint now.
        #[arg(long)]
        checkpoint: bool,
        /// Show each sink's position and last error.
        #[arg(long)]
        status: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// The org policy's version, and the running runs minted under another.
    Show,
    /// Validate and compile an org policy without installing it.
    Check {
        file: PathBuf,
        /// The groups zones are in (Cedar entities JSON).
        #[arg(long)]
        entities: Option<PathBuf>,
    },
    /// Install an org policy, and revoke the running runs minted under an older version (their boxes
    /// stop; new runs get the new policy).
    Apply {
        file: PathBuf,
        #[arg(long)]
        entities: Option<PathBuf>,
        /// Leave running runs on the policy they were minted under until they end.
        #[arg(long)]
        keep_runs: bool,
    },
    /// A zone's policy as Cedar, generated from a manifest (what its boxes' tokens are compiled from).
    Zone { manifest: PathBuf },
}

#[derive(Subcommand)]
enum StateCmd {
    /// Where each kind of control-plane state goes (state-store.yaml).
    Check {
        /// Also write, read back and delete a probe object in the store.
        #[arg(long)]
        probe: bool,
    },
    /// Stream the ledger to the state store until stopped (Litestream): a lost control host loses
    /// at most `ledger.sync_interval`. Run it as a service beside wicketd.
    Replicate,
    /// Write a recovery kit: what a standby needs besides the state store (keys, state.key, nodes'
    /// feed keys and pinned host keys, config files, and the vault's secrets). Keep it offline.
    Kit {
        #[arg(long)]
        out: PathBuf,
        /// Leave the vault's secrets out (set them again on the standby).
        #[arg(long)]
        without_secrets: bool,
        /// Leave the roots out even if they are on this host.
        #[arg(long)]
        without_roots: bool,
    },
    /// Make this fresh host the control host: the kit's files, then the ledger from the state store
    /// (as of now, or of --at), audit records the store has beyond it, agents fenced, and each node
    /// feed set to start a new generation.
    Restore {
        #[arg(long)]
        kit: PathBuf,
        /// Restore the ledger as it was at this time (RFC 3339, UTC), discarding what came after.
        #[arg(long)]
        at: Option<String>,
        /// Replace a ledger this host already has.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Move the feed root and the authority root off this host (to removable media, say): boxes'
    /// tokens are then minted by a certified issuing key, and certificates the roots issue last
    /// --days. Nodes pin the same keys as before.
    RootsOffline {
        #[arg(long)]
        to: PathBuf,
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
    /// With the roots' directory (--roots, or WICKET_ROOTS): renew the issuing key's and every node
    /// feed's certificate for another --days (as chosen at roots-offline), and start the new
    /// generation of any feed a restore left. Installed, the wicket user must be able to read it.
    Certify {
        #[arg(long)]
        roots: Option<PathBuf>,
    },
    /// Put the roots back on this host.
    RootsOnline {
        #[arg(long)]
        from: PathBuf,
    },
}

#[derive(Subcommand)]
enum GrantCmd {
    /// Revoke a grant. A grant handed to a node is revoked there through its feed by the run that
    /// published it (at once if the node is reachable).
    Revoke { id: String },
}

#[derive(Subcommand)]
enum SelfCmd {
    /// The staged versions, which is current and previous, and the ledger's schema.
    Status,
    /// Stage an artifact (a wicket binary, or a release archive from ci/package.sh), switch the
    /// control host to it, hand its processes over, and watch it; then the nodes, a canary first.
    /// Any failed health check switches back.
    Update {
        /// The artifact: a wicket binary, or a release archive.
        #[arg(required_unless_present = "from_ci", conflicts_with = "from_ci")]
        artifact: Option<PathBuf>,
        /// A build CI signed instead (#190): a commit on main, or `latest`. Downloaded here and
        /// taken only if signed in the release environment by a trusted key, for this
        /// installation's repository (`<data dir>/ci-builds.yaml`) and that commit, on main.
        #[arg(long, value_name = "COMMIT|latest")]
        from_ci: Option<String>,
        /// The detached signature (default: <artifact>.sig).
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Also update these nodes after the control host: `all`, or names (comma-separated). The
        /// first is the canary.
        #[arg(long)]
        nodes: Option<String>,
        /// The control host already runs this build: only the nodes.
        #[arg(long, requires = "nodes")]
        only_nodes: bool,
        /// How long each new build is watched after its switch.
        #[arg(long, default_value = "30s")]
        window: String,
        /// How often within the window.
        #[arg(long, default_value = "10s")]
        interval: String,
        /// A command (sh -c) that must succeed each time; $WICKET is the new build's binary and
        /// $WICKET_UPDATE_TARGET `control` or `node:<name>`. Repeatable.
        #[arg(long)]
        check: Vec<String>,
        /// A task manifest the new build runs once on the control host; it must succeed.
        #[arg(long)]
        canary: Option<PathBuf>,
        /// The canary's image (default: the new build's own, wicket/claude-code:<build id>).
        #[arg(long)]
        image: Option<String>,
        /// Keep what the update leaves unneeded (by default it prunes as `wicket self prune` does,
        /// where it updated).
        #[arg(long)]
        no_prune: bool,
    },
    /// Update to the newest build CI signed for main, if `<data dir>/ci-builds.yaml`'s follow
    /// policy lets it now (its window, soak time, only forward along main, never across a schema
    /// contract step or a failed build). Run by the wicket-follow timer.
    Follow,
    /// Switch back to the previous version: the control host (unless --only-nodes) and these nodes.
    Rollback {
        /// `all`, or node names (comma-separated).
        #[arg(long)]
        nodes: Option<String>,
        #[arg(long, requires = "nodes")]
        only_nodes: bool,
    },
    /// Remove what no rollback or running box needs: versions other than current and previous that
    /// no process runs, their agent images unless a container uses them, and ledger snapshots
    /// beyond the newest few (always keeping the newest of the current and previous versions').
    Prune {
        /// Also these nodes: `all`, or names (comma-separated).
        #[arg(long)]
        nodes: Option<String>,
        #[arg(long, requires = "nodes")]
        only_nodes: bool,
        /// How many snapshots to keep.
        #[arg(long, default_value_t = update::KEEP_SNAPSHOTS)]
        keep_snapshots: usize,
        /// Say what would go; remove nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Trust a release public key (from `wicket self keygen`) for updates.
    TrustKey { public: PathBuf },
    /// Make a release key pair: KEY (private, keep it offline) and KEY.pub.
    Keygen { key: PathBuf },
    /// Sign an artifact with a release key: writes <artifact>.sig.
    Sign {
        #[arg(long)]
        key: PathBuf,
        artifact: PathBuf,
    },
    /// This build's version, protocol and schema (JSON).
    #[command(hide = true)]
    Describe,
    /// The health check a new build runs on itself during an update.
    #[command(hide = true)]
    Health {
        #[arg(long)]
        node: Vec<String>,
        #[arg(long)]
        canary: Option<PathBuf>,
        #[arg(long, default_value = "wicket/claude-code:poc")]
        image: String,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Print a one-time join token for a node (stored hashed; single use).
    Token {
        /// The node's name (default: a generated one, printed).
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "1h")]
        ttl: String,
    },
    /// Enrol a node over ssh: pin its host key, have it make its node key and CA key, and give it a
    /// short-lived identity certificate for its node key, a short-lived CA certificate constrained to
    /// --hosts, the feed root key and the issuer key.
    Enrol {
        /// e.g. wicket@203.0.113.7
        target: String,
        /// From `wicket node token`.
        #[arg(long)]
        token: String,
        /// The node name (must match the token's).
        #[arg(long)]
        name: Option<String>,
        /// ssh identity to log in with (remembered for later runs).
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// The node's ssh host key (`ssh-ed25519 AAAA…`) or its fingerprint (`SHA256:…`), from the
        /// provider's console, cloud-init output or the image: not from the network.
        #[arg(long, conflicts_with = "trust_first_use")]
        host_key: Option<String>,
        /// No --host-key: pin whatever key the node presents now, and print its fingerprint.
        #[arg(long)]
        trust_first_use: bool,
        /// Hosts the node's CA may mint certificates for: `api.example.com`, `*.example.org` (comma-separated).
        #[arg(long, value_delimiter = ',', required = true)]
        hosts: Vec<String>,
        /// Node CA lifetime.
        #[arg(long, default_value = "24h")]
        ca_ttl: String,
        /// Node identity certificate lifetime (renewed over the control channel at half-life).
        #[arg(long, default_value = "24h")]
        cert_ttl: String,
    },
    /// List enrolled nodes.
    List,
    /// Revoke a node: refuse it from now on (its pinned host key is deleted, its identity certificates
    /// are revoked, and runs connected to it drop it) and record its CA serials for the feed's
    /// revocation list.
    Revoke { name: String },
    /// Copy this wicket binary to an enrolled node (sha256-checked) and install the `wicket-node`
    /// systemd user service that runs `wicket node serve` there.
    Install {
        name: String,
        /// ssh identity (default: the one it was enrolled with).
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// Only copy the binary; don't install or restart the service.
        #[arg(long)]
        no_service: bool,
    },
    /// On the node: run its boxes and decide their egress locally from the signed feed (the
    /// `wicket-node` service runs this).
    Serve {
        /// The node's directory (default: $WICKET_NODE_HOME or ~/.local/share/wicket-node).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Exit after this many seconds with no boxes and no control connections (the built-in
        /// local node's `serve`, started on demand).
        #[arg(long, hide = true)]
        idle_exit: Option<u64>,
    },
    /// On the node: join stdin and stdout to `node serve`'s control socket (what the control host
    /// runs over ssh).
    #[command(hide = true)]
    Attach {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Issue a node a fresh CA certificate (and CA key, made on the node) and a fresh identity
    /// certificate for its node key, over its pinned ssh: also how a node whose identity certificate
    /// expired while it was unreachable gets back in.
    RenewCa {
        name: String,
        /// Replace the hosts it is constrained to (default: keep them).
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
        #[arg(long, default_value = "24h")]
        ca_ttl: String,
        /// Node identity certificate lifetime.
        #[arg(long, default_value = "24h")]
        cert_ttl: String,
    },
}

#[derive(Subcommand)]
enum ProgramCmd {
    /// Print a program source directory's digest (what a manifest pins to approve that exact code).
    Digest { dir: PathBuf },
}

#[derive(Subcommand)]
enum OperatorCmd {
    /// List enrolled passkeys.
    List,
    /// Host-only break-glass: revoke every passkey (and every console session), so `wicket serve`
    /// prints a fresh enrolment link.
    Reset,
    /// Print a fresh single-use link that enrols one passkey in the console (another device, or a
    /// replacement after `reset`). The only way to add a passkey: a signed-in console session can't.
    EnrolLink {
        /// How long the link stays usable (at most 1h).
        #[arg(long, default_value = "10m")]
        ttl: String,
        /// The console's origin, to print the whole link (otherwise just its path).
        #[arg(long)]
        origin: Option<String>,
    },
    /// List live console sessions (id, passkey, client address, times).
    Sessions,
    /// End console sessions now: one by its id (or a unique prefix of it), or all with --all.
    RevokeSession {
        id: Option<String>,
        #[arg(long, conflicts_with = "id")]
        all: bool,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a secret. Prompts without echo, or reads stdin when it isn't a terminal.
    Set {
        name: String,
        /// The only hosts it may be sent to (comma-separated; `*.example.com` for every host under
        /// it). Without it, the secret keeps the hosts it had; a secret with none is sent nowhere
        /// (claude-oauth defaults to api.anthropic.com).
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
    },
    /// List secret names and the hosts each may be sent to (never values).
    List,
    /// Remove a secret (a reference: only the reference). Nodes holding a copy delete it when their
    /// run's lease next reaches them, within seconds while connected (#152).
    Rm { name: String },
    /// Bind a secret to the only hosts it may be sent to, replacing its list.
    Hosts {
        name: String,
        #[arg(long, value_delimiter = ',', required = true)]
        hosts: Vec<String>,
    },
    /// Make a secret a reference to a JSON field in another file, re-read on every use (never copied).
    /// E.g. the Claude login on this host:
    /// wicket secret link claude-oauth --file ~/.claude/.credentials.json --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
    Link {
        name: String,
        #[arg(long)]
        file: String,
        /// A JSON pointer into the file (e.g. /claudeAiOauth/accessToken). Without one, the whole file
        /// is the secret, trimmed (e.g. an API key file).
        #[arg(long)]
        pointer: Option<String>,
        #[arg(long)]
        expires_pointer: Option<String>,
        /// The only hosts it may be sent to (as for `secret set`).
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
    },
}

#[derive(Subcommand)]
enum DevCmd {
    /// On a node: send `node serve` its own last freshness statement, tampered and then replayed, and
    /// print how each was refused (a check for ci/node-e2e.sh). The control connection stays up.
    NodeFeedProbe {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// A scripted stand-in for the Anthropic Messages API: the first turn runs one Bash command,
    /// the second ends the conversation. Lets the whole path be tested without an API key.
    MockLlm {
        #[arg(long, default_value = "127.0.0.1:9999")]
        listen: String,
        /// The Bash command the mock model asks the agent to run.
        #[arg(long)]
        command: String,
    },
}

pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("WICKET_HOME") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/share/wicket")
}

fn audit_export_cmd(once: bool, checkpoint: bool, status: bool) -> Result<()> {
    let cfg = audit_export::SinksConfig::load()?
        .with_context(|| format!("no audit sinks configured ({} does not exist)", audit_export::sinks_path().display()))?;
    if status {
        let l = Ledger::open(&ledger_path())?;
        let head = l.audit_head()?.map(|h| h.0).unwrap_or(0);
        for s in &cfg.sinks {
            let c = l.export_cursor(&s.name)?;
            let holder = if c.lease_until >= wicket_store::now() { c.holder.unwrap_or_default() } else { "-".into() };
            println!(
                "{:<16} at {} of {head}  last checkpoint {}  fed by {holder}{}",
                s.name,
                c.seq,
                c.checkpoint_at,
                c.error.map(|e| format!("  error: {e}")).unwrap_or_default()
            );
        }
        return Ok(());
    }
    let issuer = match issuer() {
        Ok(i) => Some(i),
        Err(e) => {
            eprintln!("wicket: no issuer key ({e}): exporting records without checkpoints");
            None
        }
    };
    let mut x = audit_export::Exporter::new(&ledger_path(), cfg, issuer)?;
    x.stdout = true;
    let mut force = checkpoint;
    loop {
        let p = x.pass(force);
        force = false;
        for (sink, e) in &p.failures {
            eprintln!("wicket: audit sink {sink}: {e}");
        }
        if once {
            for sink in &p.busy {
                eprintln!("wicket: audit sink {sink} is fed by another wicket process (see --status); left to it");
            }
        }
        if once {
            if !p.failures.is_empty() {
                bail!("{} sink(s) failed", p.failures.len());
            }
            eprintln!("exported {} record(s) and {} checkpoint(s)", p.records, p.checkpoints);
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

pub fn ledger_path() -> PathBuf {
    data_dir().join("ledger.db")
}

/// The verified identity of the agent running as `run`, for showing to humans: the identity document
/// is checked against the issuer and against the ledger's own row, so an edited row is caught.
/// `at` is the time to check validity at (now for live runs, issue time for history).
pub fn verified_identity(l: &Ledger, run: &str, at: Option<i64>) -> serde_json::Value {
    let row = match l.identity(run) {
        Ok(Some(r)) => r,
        Ok(None) => return serde_json::json!({ "verified": false, "run": run, "error": "no identity was issued for this run" }),
        Err(e) => return serde_json::json!({ "verified": false, "run": run, "error": e.to_string() }),
    };
    let check = || -> anyhow::Result<wicket_identity::AgentClaims> {
        let issuer = issuer()?;
        let c = wicket_identity::verify_identity(&row.jws, &issuer.verifying_key(), at.unwrap_or(row.issued_at))?;
        if c.run != row.run
            || c.tenant != row.tenant
            || c.zone != row.zone
            || c.agent != row.agent
            || c.sub != row.spiffe_id
            || c.parent_run != row.parent_run
        {
            anyhow::bail!("the ledger's record does not match the signed identity");
        }
        Ok(c)
    };
    match check() {
        Ok(c) => {
            if let Ok(Some((r, when, by, reason))) = l.revoked_in_chain(run) {
                let whose = if r == run { "identity".to_string() } else { format!("identity of its ancestor {r}") };
                return serde_json::json!({ "verified": false, "revoked": true, "run": run, "agent": c.agent, "zone": c.zone,
                    "error": format!("{whose} revoked by {by} at {when}: {reason}") });
            }
            let parent_agent = c.parent_run.as_deref().and_then(|p| l.identity(p).ok().flatten()).map(|p| p.agent);
            serde_json::json!({
                "verified": true, "id": c.sub, "agent": c.agent, "zone": c.zone, "tenant": c.tenant, "run": c.run,
                "parent_run": c.parent_run, "parent_agent": parent_agent, "node": c.node, "image": c.image,
                "principal": c.principal, "acting_for": c.chain(), "expires_at": c.exp,
                "manifest_sha256": c.manifest_sha256, "identity_sha256": wicket_identity::identity_digest(&row.jws),
            })
        }
        Err(e) => serde_json::json!({ "verified": false, "run": run, "agent": row.agent, "zone": row.zone, "error": e.to_string() }),
    }
}

/// A request as `wicket pending` and `wicket approve` show it: wicket's own record, with every
/// agent-written field (method, host, path, reason, attribution) stripped of terminal escapes,
/// bidi and zero-width characters (#128).
pub fn show_request(l: &Ledger, r: &wicket_store::Request) -> String {
    let clip = wicket_agent::clip;
    let age = wicket_store::now() - r.created_at;
    let mut out = format!(
        "{}  {} {}{}{}  [{}]  run {}  {}s ago{}\n    why: {}\n",
        r.id,
        clip(&r.method, 16),
        clip(&r.host, 255),
        clip(&r.path, 400),
        if r.scope_prefix { "…  (every path under it)" } else { "" },
        r.risk,
        clip(&r.run, 64),
        age,
        if r.status == "pending" { String::new() } else { format!("  ({})", clip(&r.status, 16)) },
        clip(&r.reason, 2000)
    );
    out.push_str(&format!("    agent: {}\n", clip(&identity_line(&verified_identity(l, &r.run, None)), 400)));
    for a in &r.attribution {
        out.push_str(&format!("    for: {}  (reported by the agent, unverified)\n", clip(&wicket_proxy::attribution_line(a), 240)));
    }
    out
}

/// Asks the operator at the terminal; anything but y or yes is no.
fn confirm(question: &str) -> Result<bool> {
    use std::io::Write;
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// One line for terminals.
pub fn identity_line(v: &serde_json::Value) -> String {
    let g = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_string();
    if v.get("verified").and_then(|b| b.as_bool()) == Some(true) {
        let chain = v
            .get("acting_for")
            .and_then(|c| c.as_array())
            .map(|c| c.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" → "))
            .unwrap_or_default();
        format!("{} [verified]  acting for: {chain}", g("id"))
    } else {
        format!("NOT VERIFIED: {}", g("error"))
    }
}

/// The installation's identity issuer key (design §3.2). Under WICKET_HOME when that is set.
pub fn issuer_key_path() -> PathBuf {
    if let Some(d) = std::env::var_os("WICKET_HOME") {
        return PathBuf::from(d).join("identity/issuer.key");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".config/wicket/identity/issuer.key")
}

/// The principal behind a root run: the local unix user, which is all the PoC CLI knows, unless
/// WICKET_PRINCIPAL names one. The console sets it for the runs it starts, to the passkey-signed-in
/// operator (serve::console_principal), and records the passkey assertion over it (with the run id
/// and the manifest's digest) in the audit log; that signed record is what binds operator, run and
/// principal. The variable itself carries no more assurance than $USER: anyone who can run `wicket`
/// as this user could set either. It must be a JSON object with string `type`, `id` and `via`, or
/// it is ignored.
pub fn cli_principal() -> serde_json::Value {
    if let Some(p) = principal_from_env(std::env::var("WICKET_PRINCIPAL").ok().as_deref()) {
        return p;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "operator".into());
    serde_json::json!({ "type": "human", "id": user, "via": "cli", "assurance": "unix-user" })
}

/// WICKET_PRINCIPAL's value, if it is a well-formed principal.
fn principal_from_env(v: Option<&str>) -> Option<serde_json::Value> {
    let p: serde_json::Value = serde_json::from_str(v?).ok()?;
    let is_str = |k: &str| p.get(k).is_some_and(|v| v.is_string());
    (p.is_object() && is_str("type") && is_str("id") && is_str("via")).then_some(p)
}

/// The trust domain asked for in the environment, if any. The installation's own is recorded with
/// its issuer key (`wicket identity init`); this only sets it on first use, and must match after.
pub fn trust_domain() -> Option<String> {
    std::env::var("WICKET_TRUST_DOMAIN").ok().filter(|s| !s.is_empty())
}

pub fn issuer() -> Result<wicket_identity::Issuer> {
    Ok(wicket_identity::Issuer::load(&issuer_key_path(), trust_domain().as_deref())?)
}

/// Who is deciding, for the ledger. wicketd sets WICKET_OPERATOR from the caller's peer
/// credentials for the commands it runs; without it (development mode), it is $USER, which carries
/// no assurance.
fn operator() -> String {
    if let Some(o) = std::env::var("WICKET_OPERATOR").ok().filter(|o| !o.is_empty()) {
        return o;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "operator".into());
    format!("{user}@cli (host break-glass)")
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("WICKET_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    // With wicketd installed, this user can't read wicket's data: the daemon runs the command.
    let route = daemon::policy::route(&cli.cmd);
    match daemon::client::mode() {
        daemon::client::Mode::Daemon(sock) => match route {
            daemon::policy::Route::Forward(_) => {
                let code = daemon::client::forward(&sock, &cli.cmd).await?;
                if code != 0 {
                    std::process::exit(code);
                }
                return Ok(());
            }
            daemon::policy::Route::Refuse(why) => bail!("{why}"),
            daemon::policy::Route::Local => {}
        },
        daemon::client::Mode::Missing(why) if matches!(route, daemon::policy::Route::Forward(_)) => bail!("{why}"),
        _ => {}
    }
    match cli.cmd {
        Cmd::Daemon { socket, policy } => daemon::serve(&socket, policy),
        Cmd::Run { manifest, workdir, workspace_dir, task, image, node, ssh_key, run_id, parent_run, lease, adopt } => {
            let adopt = match adopt {
                Some(a) => {
                    let (at, session) = a.split_once(':').context("--adopt <started ms>:<session id>")?;
                    Some((at.parse::<i64>().context("--adopt: started ms")?, session.to_string()))
                }
                None => None,
            };
            run::run(run::RunOpts {
                manifest: &manifest,
                workdir: workdir.as_deref(),
                workspace_dir: workspace_dir.as_deref(),
                task,
                image: image.as_deref(),
                node: node.as_deref(),
                ssh_key: ssh_key.as_deref(),
                run_id,
                parent_run,
                lease,
                wrap: None,
                wake: None,
                attach: false,
                adopt,
            })
            .await
        }
        Cmd::Wrap { manifest, image, argv } => {
            run::run(run::RunOpts {
                manifest: &manifest,
                workdir: None,
                workspace_dir: None,
                task: None,
                image: image.as_deref(),
                node: None,
                ssh_key: None,
                run_id: None,
                parent_run: None,
                lease: None,
                wrap: Some(argv),
                wake: None,
                attach: false,
                adopt: None,
            })
            .await
        }
        Cmd::Attach { run } => run::run(run::RunOpts {
            manifest: std::path::Path::new("(the run's record)"),
            workdir: None,
            workspace_dir: None,
            task: None,
            image: None,
            node: None,
            ssh_key: None,
            run_id: Some(run.clone()),
            parent_run: None,
            lease: None,
            wrap: None,
            wake: None,
            attach: true,
            adopt: None,
        })
        .await
        .inspect_err(|e| run::attach_failed(&run, e)),
        Cmd::Say { run, text } => {
            let text = text.join(" ");
            if text.trim().is_empty() {
                bail!("nothing to say");
            }
            let l = Ledger::open(&ledger_path())?;
            // A long-lived agent is reached through its current run; a hibernated one is woken, and
            // the message is its first turn.
            let mut run = run;
            if l.run_status(&run)?.as_deref() != Some("running") {
                if let Ok(a) = hibernate::resolve(&l, &run) {
                    match a.state.as_str() {
                        "hibernated" if a.restorable => {
                            if let Some(why) = hibernate::exhausted(&a) {
                                bail!("agent {} is hibernated and can't be woken: {why}", a.id);
                            }
                            l.add_operator_message(&a.id, &text, &operator())?;
                            l.audit(
                                &TenantId::single(),
                                None,
                                "operator.message",
                                &serde_json::json!({ "by": operator(), "chars": text.len(), "agent": a.id, "wakes": true }),
                            )?;
                            hibernate::trigger_wake(&a.id, &format!("wicket say by {}", operator()));
                            println!(
                                "agent {} is hibernated: waking it; the message is its first turn (log: {})",
                                a.id,
                                hibernate::agent_dir(&a.id).join("wake.log").display()
                            );
                            return Ok(());
                        }
                        "active" | "idle" | "waking" | "hibernating" => run = a.run,
                        s => bail!("agent {} is {s}", a.id),
                    }
                }
            }
            match l.run_status(&run)?.as_deref() {
                Some("running") => {}
                Some(s) => bail!("{run} is {s}, not running"),
                None => bail!("no run {run}"),
            }
            l.add_operator_message(&run, &text, &operator())?;
            l.audit(
                &TenantId::single(),
                Some(&wicket_core::RunId(run.clone())),
                "operator.message",
                &serde_json::json!({ "by": operator(), "chars": text.len() }),
            )?;
            println!("queued for {run}: the agent gets it within a second (as its next turn, or queued behind the current one)");
            Ok(())
        }
        Cmd::Hibernate { run, wait } => hibernate::hibernate(&run, wait).await,
        Cmd::Wake { agent, text, by } => {
            let text = text.join(" ");
            hibernate::wake(&agent, (!text.trim().is_empty()).then_some(text), by).await
        }
        Cmd::Agents { json } => hibernate::list(json),
        Cmd::Pending => {
            let l = Ledger::open(&ledger_path())?;
            let p = l.pending(&TenantId::single())?;
            if p.is_empty() {
                println!("no pending requests");
            }
            for r in p {
                print!("{}", show_request(&l, &r));
            }
            Ok(())
        }
        Cmd::Approve { id, uses, unlimited, ttl, prefix, yes, zone_wide } => {
            let ttl = humantime::parse_duration(&ttl).context("bad --ttl")?;
            if ttl > Duration::from_secs(24 * 3600) {
                bail!("grants are capped at 24h in the PoC");
            }
            let mut l = Ledger::open(&ledger_path())?;
            let req = l.request(&id)?;
            // What is approved is what wicket recorded, shown before the grant exists: a hint printed
            // from a node's or an agent's text can name the wrong request (#121).
            print!("{}", show_request(&l, &req));
            if !yes && std::io::stdin().is_terminal() && !confirm(&format!("approve {id} as shown above?"))? {
                bail!("not approved");
            }
            let lease = capacity::lease_of_request(&l, &req)?;
            let a = Approval { uses: if unlimited { None } else { Some(uses) }, ttl, path_prefix: prefix.clone(), decided_by: operator() };
            let gid = if zone_wide { l.approve_zone_wide(&id, &a)? } else { l.approve(&id, &a)? };
            // A grant exists only if its approval is on the record (fail closed).
            if let Err(e) = l.audit(
                &TenantId::single(),
                None,
                "decision",
                &serde_json::json!({
                    "request": id, "decision": "approve", "grant": gid, "by": operator(),
                    "method": req.method, "host": req.host, "path": req.path,
                    "requested_by": req.attribution.iter().flat_map(wicket_proxy::attributed_agents).collect::<Vec<_>>(),
                    "agent_identity": verified_identity(&l, &req.run, None),
                    "uses": if unlimited { None } else { Some(uses) }, "ttl_secs": ttl.as_secs(), "prefix": prefix,
                    "scope": if zone_wide { "zone" } else { "run" }, "run": req.run, "zone": req.zone,
                }),
            ) {
                let _ = l.revoke_grant(&gid);
                return Err(anyhow::Error::from(e).context("the approval could not be recorded in the audit log, so its grant was revoked"));
            }
            println!(
                "approved {id} → grant {gid}: {} {}{} ({}, {}, {})",
                wicket_agent::clip(&req.method, 16),
                wicket_agent::clip(&req.host, 255),
                wicket_agent::clip(&prefix.as_deref().map(|p| format!("{p}* [prefix]")).unwrap_or(req.path), 400),
                if unlimited { "unlimited uses".into() } else { format!("{uses} use(s)") },
                humantime::format_duration(ttl),
                if zone_wide { format!("any run in zone {}", wicket_agent::clip(&req.zone, 64)) } else { format!("run {} only", req.run) }
            );
            if let Some(lease) = lease.as_deref() {
                // A capacity ask: provision now rather than at the next pass of a running reconciler.
                drop(l);
                println!("provisioning lease {lease} (one reconcile pass)");
                reconcile::print(&reconcile::pass(false).await?, false);
                if let Some(x) = Ledger::open(&ledger_path())?.lease(lease)? {
                    println!("lease {lease}: {} {}", x.status, x.node_name.or(x.detail).unwrap_or_default());
                }
            }
            Ok(())
        }
        Cmd::Links { tail } => {
            let l = Ledger::open(&ledger_path())?;
            let rows = l.links(&TenantId::single(), tail)?;
            if rows.is_empty() {
                println!("no links");
            }
            for r in rows {
                println!(
                    "{}  {:6}  {} → {}.{}:{} ({})  opened by {} ({}){}",
                    r.id,
                    r.status,
                    r.from_run,
                    r.name,
                    wicket_core::link::DOMAIN,
                    r.port,
                    r.to_run,
                    r.by_run,
                    r.basis,
                    r.close_reason.map(|c| format!("; closed: {c}")).unwrap_or_default()
                );
            }
            Ok(())
        }
        Cmd::Unlink { id } => {
            let l = Ledger::open(&ledger_path())?;
            let r = l.link(&id)?.with_context(|| format!("no link {id}"))?;
            if l.close_link(&id, &operator(), "cut by the operator")? {
                l.audit(
                    &TenantId::single(),
                    None,
                    "link.cut",
                    &serde_json::json!({ "id": id, "by": operator(), "from": r.from_run, "to": r.to_run, "port": r.port }),
                )?;
                println!("cut {id}; its relay closes it within a few seconds");
            } else {
                println!("{id} was already closed");
            }
            Ok(())
        }
        Cmd::Deny { id } => {
            let l = Ledger::open(&ledger_path())?;
            l.deny(&id, &operator())?;
            l.audit(&TenantId::single(), None, "decision", &serde_json::json!({ "request": id, "decision": "deny", "by": operator() }))?;
            let req = l.request(&id)?;
            if let Some(lease) = capacity::lease_of_request(&l, &req)?.as_deref() {
                l.lease_ended(lease, "denied", &format!("request {id} denied by {}", operator()), None)?;
                println!("lease {lease} denied: its reservation is released");
            }
            println!("denied {id}");
            Ok(())
        }
        Cmd::Grant { cmd: GrantCmd::Revoke { id } } => {
            let l = Ledger::open(&ledger_path())?;
            let g = l.grant(&id)?.with_context(|| format!("no grant {id}"))?;
            l.revoke_grant(&id)?;
            l.audit(&TenantId::single(), None, "grant.revoked", &serde_json::json!({ "grant": id, "by": operator(), "node": g.node }))?;
            match &g.node {
                Some(n) => println!("revoked {id}; its run pushes the revocation to node {n}"),
                None => println!("revoked {id}"),
            }
            Ok(())
        }
        Cmd::Identity { cmd } => {
            let l = Ledger::open(&ledger_path())?;
            match cmd {
                IdentityCmd::Init { trust_domain } => {
                    let i = wicket_identity::Issuer::load(&issuer_key_path(), Some(&trust_domain))?;
                    println!("issuer ready: {} (key {})", i.issuer_id(), wicket_identity::key_id(&i.verifying_key()));
                }
                IdentityCmd::Issuer => {
                    let i = issuer()?;
                    let mut jwk = i.public_jwk();
                    jwk["trust_domain"] = i.trust_domain.clone().into();
                    println!("{}", serde_json::to_string_pretty(&jwk)?);
                }
                IdentityCmd::Show { run } => println!("{}", serde_json::to_string_pretty(&verified_identity(&l, &run, None))?),
                IdentityCmd::Revoke { run, reason } => {
                    if l.identity(&run)?.is_none() {
                        bail!("no identity was issued for {run}");
                    }
                    let fresh = l.revoke(&run, &operator(), &reason)?;
                    l.audit(
                        &TenantId::single(),
                        Some(&wicket_core::RunId(run.clone())),
                        "identity.revoked",
                        &serde_json::json!({ "run": run, "by": operator(), "reason": reason }),
                    )?;
                    println!(
                        "{} {run}: its runner stops the box within seconds; its messages and approvals are refused",
                        if fresh { "revoked" } else { "already revoked" }
                    );
                }
                IdentityCmd::List => {
                    for row in l.identities()? {
                        let status = l.run_status(&row.run)?.unwrap_or_default();
                        println!("{}  {:<10} {}", row.run, status, identity_line(&verified_identity(&l, &row.run, None)));
                    }
                }
            }
            Ok(())
        }
        Cmd::Audit { tail, verify, against, issuer_jwk, cmd } => {
            if let Some(AuditCmd::Export { once, checkpoint, status }) = cmd {
                // The exporter blocks (its own runtime, file and HTTP writes): off the async runtime.
                return std::thread::spawn(move || audit_export_cmd(once, checkpoint, status))
                    .join()
                    .map_err(|_| anyhow::anyhow!("the audit exporter panicked"))?;
            }
            let l = Ledger::open(&ledger_path())?;
            if verify {
                let n = l.verify_audit_versions()?;
                let v1 = if n.v1 > 0 {
                    format!(" ({} written before v2 hash only their prev, kind and body; the exported copies check the rest)", n.v1)
                } else {
                    String::new()
                };
                println!("audit chain OK: {} records{v1}", n.total());
                let (ok, bad) = verify_signed_decisions(&l)?;
                println!("passkey-signed decisions and console actions: {ok} verified offline, {bad} failed");
                let (iok, ibad) = verify_identities_and_messages(&l)?;
                println!("agent identities and signed messages: {iok} verified offline, {ibad} failed");
                for n in l.verify_node_audit()? {
                    let restarts =
                        if n.restarts > 0 { format!(" ({} restart(s): the node's data was wiped)", n.restarts) } else { String::new() };
                    println!("node {} audit chain OK: {} records shipped{restarts}", n.node, n.records);
                }
                let mut against_bad = 0;
                if !against.is_empty() {
                    let key = match &issuer_jwk {
                        Some(p) => wicket_identity::verifying_key_from_jwk(&serde_json::from_slice(&std::fs::read(p)?)?)?,
                        None => issuer()?.verifying_key(),
                    };
                    let mut objs = Vec::new();
                    for p in &against {
                        // `store:<sink>`: what that sink wrote to the state store (#154).
                        match p.to_str().and_then(|s| s.strip_prefix("store:")) {
                            Some(sink) => objs.extend(audit_export::stored_objects(sink)?),
                            None => objs.extend(audit_export::exported_objects(
                                &std::fs::read_to_string(p).with_context(|| p.display().to_string())?,
                            )),
                        }
                    }
                    let a = audit_export::verify_against(&l, &objs, &key)?;
                    println!("against the exported copies: {} signed checkpoint(s) and {} record(s) match", a.checkpoints, a.records);
                    if a.superseded > 0 {
                        println!("  ({} exported before a restore to an earlier point, which discarded them: not compared)", a.superseded);
                    }
                    for p in a.problems.iter().take(20) {
                        println!("  MISMATCH: {p}");
                    }
                    if a.checkpoints == 0 && a.records > 0 {
                        println!("  (no signed checkpoints found: only exported records were compared)");
                    }
                    against_bad = a.problems.len();
                }
                if bad + ibad > 0 {
                    bail!("{} record(s) failed verification", bad + ibad);
                }
                if against_bad > 0 {
                    bail!("the local audit chain does not match its exported copies ({against_bad} problem(s)): it was rewritten or truncated here");
                }
                return Ok(());
            }
            for (seq, ts, kind, run, body) in l.audit_tail(tail)? {
                println!("{seq:>6} {ts} {kind:<9} {} {body}", run.unwrap_or_else(|| "-".into()));
            }
            Ok(())
        }
        Cmd::Secret { cmd } => {
            let v = Vault::new(Vault::default_dir());
            match cmd {
                SecretCmd::Set { name, hosts } => {
                    let value = if std::io::stdin().is_terminal() {
                        rpassword::prompt_password(format!("value for {name} (not echoed): "))?
                    } else {
                        let mut s = String::new();
                        std::io::stdin().read_to_string(&mut s)?;
                        s
                    };
                    if value.trim().is_empty() {
                        bail!("empty value");
                    }
                    v.set(&name, &value)?;
                    if !hosts.is_empty() {
                        v.set_hosts(&name, &hosts)?;
                    }
                    println!("stored secret {name}; {}", secret_hosts_line(&v, &name));
                }
                SecretCmd::Link { name, file, pointer, expires_pointer, hosts } => {
                    v.link(&name, &file, pointer.as_deref(), expires_pointer.as_deref())?;
                    if !hosts.is_empty() {
                        v.set_hosts(&name, &hosts)?;
                    }
                    println!(
                        "secret {name} now refers to {file}{} (read at each use; never copied); {}",
                        pointer.as_deref().map(|p| format!("#{p}")).unwrap_or_default(),
                        secret_hosts_line(&v, &name)
                    );
                }
                SecretCmd::Hosts { name, hosts } => {
                    if !v.has(&name) {
                        bail!("no secret {name}");
                    }
                    v.set_hosts(&name, &hosts)?;
                    println!("secret {name}: {}", secret_hosts_line(&v, &name));
                }
                SecretCmd::Rm { name } => {
                    if !v.has(&name) {
                        bail!("no secret {name}");
                    }
                    v.remove(&name)?;
                    println!("secret {name} removed");
                }
                SecretCmd::List => {
                    for n in v.list() {
                        let base = n.strip_suffix(" (reference)").unwrap_or(&n);
                        println!("{n}  {}", secret_hosts_line(&v, base));
                    }
                }
            }
            Ok(())
        }
        Cmd::Image { tag, dir } => {
            let ctx = match &dir {
                Some(d) => image::context(d)?,
                None => image::embedded_context()?,
            };
            wicket_sandbox::Docker::from_env().build_image(&tag, &ctx.dir).await?;
            println!("built {tag}");
            Ok(())
        }
        Cmd::Doctor { image } => doctor::doctor(&image).await,
        Cmd::Zone { manifest, json } => {
            let m = wicket_core::Manifest::from_yaml(
                &std::fs::read_to_string(&manifest).with_context(|| format!("reading {}", manifest.display()))?,
            )?;
            print!("{}", zone_view(&m.zone, json));
            Ok(())
        }
        Cmd::Policy { cmd } => match cmd {
            PolicyCmd::Show => policy::show(),
            PolicyCmd::Check { file, entities } => {
                policy::sanity(&file)?;
                policy::check(&file, entities.as_deref())
            }
            PolicyCmd::Apply { file, entities, keep_runs } => {
                policy::sanity(&file)?;
                policy::apply(&file, entities.as_deref(), keep_runs).await
            }
            PolicyCmd::Zone { manifest } => policy::zone(&manifest),
        },
        Cmd::State { cmd } => {
            // Litestream and the store client block: off the async runtime.
            std::thread::spawn(move || match cmd {
                StateCmd::Check { probe } => state::check(probe),
                StateCmd::Replicate => state::replicate(),
                StateCmd::Kit { out, without_secrets, without_roots } => state::kit(&out, !without_secrets, !without_roots),
                StateCmd::Restore { kit, at, force } => state::restore(&kit, at.as_deref(), force),
            })
            .join()
            .map_err(|_| anyhow::anyhow!("wicket state panicked"))?
        }
        Cmd::Keys { cmd } => match cmd {
            KeysCmd::RootsOffline { to, days } => roots::roots_offline(&to, days).await,
            KeysCmd::Certify { roots: dir } => {
                if let Some(d) = dir {
                    std::env::set_var("WICKET_ROOTS", d);
                }
                roots::certify()
            }
            KeysCmd::RootsOnline { from } => roots::roots_online(&from),
        },
        Cmd::Reconcile { dry_run, every } => {
            let every = every.as_deref().map(humantime::parse_duration).transpose().context("bad --every")?;
            reconcile::command(dry_run, every).await
        }
        Cmd::Lease { cmd: LeaseCmd::List } => capacity::list(),
        Cmd::Lease { cmd: LeaseCmd::Release { id } } => {
            let l = Ledger::open(&ledger_path())?;
            let x = l.lease(&id)?.with_context(|| format!("no lease {id}"))?;
            let why = format!("released by {}", operator());
            match x.status.as_str() {
                "active" => {
                    l.set_lease_not_after(&id, wicket_store::now())?;
                }
                "pending" | "approved" => {
                    l.lease_ended(&id, "withdrawn", &why, None)?;
                }
                s => bail!("lease {id} is {s}"),
            }
            l.audit(&TenantId::single(), None, "lease.released", &serde_json::json!({ "lease": id, "by": operator() }))?;
            drop(l);
            reconcile::print(&reconcile::pass(false).await?, false);
            Ok(())
        }
        Cmd::Reap { dry_run, node, ssh_key } => {
            let docker = match node {
                Some(n) => wicket_sandbox::Docker::over_ssh(enrol::resolve_installed(&n, ssh_key.as_deref())?.ssh_prefix()),
                None => wicket_sandbox::Docker::from_env(),
            };
            let l = Ledger::open(&ledger_path())?;
            let all = reap::reap(&docker, &l, dry_run).await?;
            let mut stopped = 0;
            for r in &all {
                let run = r.run.as_deref().unwrap_or("?");
                match &r.verdict {
                    reap::Verdict::Live => {}
                    reap::Verdict::Orphan(why) => {
                        stopped += 1;
                        println!("{} {} (run {run}): {why}", if dry_run { "would stop" } else { "stopped" }, r.name);
                    }
                    reap::Verdict::Unknown(why) => println!("left alone {} (run {run}): {why}", r.name),
                }
            }
            println!("{} box(es), {stopped} orphaned{}", all.len(), if dry_run { " (dry run: nothing stopped)" } else { "" });
            Ok(())
        }
        Cmd::Node { cmd } => match cmd {
            NodeCmd::Token { name, ttl } => enrol::token(name, humantime::parse_duration(&ttl)?),
            NodeCmd::Enrol { target, token, name, ssh_key, host_key, trust_first_use, hosts, ca_ttl, cert_ttl } => {
                enrol::enrol(enrol::EnrolOpts {
                    target,
                    token,
                    name,
                    ssh_key,
                    host_key,
                    trust_first_use,
                    hosts,
                    ca_ttl: humantime::parse_duration(&ca_ttl)?,
                    cert_ttl: humantime::parse_duration(&cert_ttl)?,
                })
                .await
            }
            NodeCmd::List => enrol::list(),
            NodeCmd::Revoke { name } => {
                let mut l = Ledger::open(&ledger_path())?;
                let serials = enrol::revoke(&mut l, &enrol::Paths::installation().nodes_dir, &name)?;
                println!("revoked node {name}; its CA serials {} go on the feed's revocation list", serials.join(", "));
                Ok(())
            }
            NodeCmd::RenewCa { name, hosts, ca_ttl, cert_ttl } => {
                enrol::renew_ca(&name, hosts, humantime::parse_duration(&ca_ttl)?, humantime::parse_duration(&cert_ttl)?).await
            }
            NodeCmd::Install { name, ssh_key, no_service } => enrol::install(&name, ssh_key.as_deref(), no_service).await,
            NodeCmd::Serve { dir, idle_exit } => nodesrv::serve(dir, idle_exit).await,
            NodeCmd::Attach { dir } => nodesrv::attach(dir).await,
        },
        Cmd::Place { cmd } => place::run(cmd).await,
        Cmd::Itself { cmd } => match cmd {
            SelfCmd::Status => update::status(),
            SelfCmd::Follow => ci_update::follow().await,
            SelfCmd::Update { artifact, from_ci, sig, nodes, only_nodes, window, interval, check, canary, image, no_prune } => {
                let gate = update::Gate {
                    window: humantime::parse_duration(&window).context("bad --window")?,
                    interval: humantime::parse_duration(&interval).context("bad --interval")?.max(Duration::from_secs(1)),
                    checks: check,
                    canary,
                    image,
                };
                match (from_ci, artifact) {
                    (Some(target), _) => ci_update::update_from_ci(&target, nodes, only_nodes, gate, !no_prune).await,
                    (None, Some(artifact)) => {
                        update::update(update::UpdateOpts { artifact, sig, nodes, only_nodes, gate, prune: !no_prune, ci: None }).await
                    }
                    (None, None) => unreachable!("clap requires one"),
                }
            }
            SelfCmd::Rollback { nodes, only_nodes } => update::rollback(nodes, only_nodes).await,
            SelfCmd::Prune { nodes, only_nodes, keep_snapshots, dry_run } => {
                update::prune(nodes, only_nodes, keep_snapshots, dry_run).await
            }
            SelfCmd::TrustKey { public } => update::trust_key(&public),
            SelfCmd::Keygen { key } => update::keygen(&key),
            SelfCmd::Sign { key, artifact } => update::sign(&key, &artifact),
            SelfCmd::Describe => {
                println!("{}", serde_json::to_string(&update::describe()?)?);
                Ok(())
            }
            SelfCmd::Health { node, canary, image } => update::health(node, canary, image).await,
        },
        c @ Cmd::Serve { .. } => {
            let (opts, no_bootstrap_link) = serve_opts(c).expect("a serve command");
            serve::serve(opts, !no_bootstrap_link).await
        }
        Cmd::Program { cmd: ProgramCmd::Digest { dir } } => {
            println!("{}", program::digest_dir(&dir)?);
            Ok(())
        }
        Cmd::Operator { cmd } => {
            let l = Ledger::open(&ledger_path())?;
            match cmd {
                OperatorCmd::List => {
                    for c in l.operator_credentials(&TenantId::single())? {
                        println!("{}  {}  sign count {}", c.id, c.name, c.sign_count);
                    }
                }
                OperatorCmd::EnrolLink { ttl, origin } => {
                    let ttl = humantime::parse_duration(&ttl).context("bad --ttl")?;
                    if ttl.is_zero() || ttl > Duration::from_secs(3600) {
                        bail!("--ttl must be more than 0 and at most 1h");
                    }
                    let token = serve::issue_enrol_link(&l, &TenantId::single(), ttl.as_secs() as i64, &operator())?;
                    let origin = origin.as_deref().map(|o| o.trim_end_matches('/')).unwrap_or("");
                    println!("open within {} (single use) to enrol a passkey:", humantime::format_duration(ttl));
                    println!("  {origin}/enrol?t={token}");
                    if origin.is_empty() {
                        println!("(prefix the console's origin, e.g. https://console.example.com)");
                    }
                }
                OperatorCmd::Sessions => {
                    let now = wicket_store::now();
                    let ago = |t: i64| humantime::format_duration(Duration::from_secs((now - t).max(0) as u64)).to_string();
                    for s in l.console_sessions(&TenantId::single(), now)? {
                        println!(
                            "{}  {}  {}  from {}  signed in {} ago, last seen {} ago",
                            &s.id[..16],
                            s.kind,
                            s.credential.as_deref().unwrap_or("-"),
                            s.client,
                            ago(s.created_at),
                            ago(s.last_seen_at)
                        );
                    }
                }
                OperatorCmd::RevokeSession { id, all } => {
                    let t = TenantId::single();
                    let prefix = match (&id, all) {
                        (Some(p), false) if !p.is_empty() => {
                            let n = l.console_sessions(&t, wicket_store::now())?.iter().filter(|s| s.id.starts_with(p.as_str())).count();
                            if n != 1 {
                                bail!("{p:?} matches {n} live sessions (see wicket operator sessions)");
                            }
                            Some(p.as_str())
                        }
                        (None, true) => None,
                        _ => bail!("give a session id (wicket operator sessions) or --all"),
                    };
                    let ids = l.revoke_console_sessions(&t, prefix, &operator())?;
                    l.audit(
                        &t,
                        None,
                        "operator.sessions_revoked",
                        &serde_json::json!({ "sessions": ids, "by": operator(), "via": "host" }),
                    )?;
                    println!("ended {} console session(s)", ids.len());
                }
                OperatorCmd::Reset => {
                    let n = l.reset_operator_credentials(&TenantId::single())?;
                    l.revoke_console_sessions(&TenantId::single(), None, &operator())?;
                    l.audit(
                        &TenantId::single(),
                        None,
                        "operator.reset",
                        &serde_json::json!({ "removed": n, "by": operator(), "via": "host break-glass" }),
                    )?;
                    println!(
                        "revoked {n} passkey(s) (public keys kept for audit verification); enrol a new one with `wicket operator enrol-link`"
                    );
                }
            }
            Ok(())
        }
        Cmd::Dev { cmd: DevCmd::MockLlm { listen, command } } => mock::serve(&listen, &command).await,
        Cmd::Dev { cmd: DevCmd::NodeFeedProbe { dir } } => {
            for r in nodesrv::probe_tamper(dir).await? {
                println!("{r}");
            }
            Ok(())
        }
    }
}

/// Verifies every issued identity (at its issue time) and every stored envelope (at its send time).
fn verify_identities_and_messages(l: &Ledger) -> Result<(usize, usize)> {
    let (mut ok, mut bad) = (0, 0);
    let key = issuer()?.verifying_key();
    // Every document ever issued, rotations included, each at its own issue time (plus current
    // documents from ledgers that predate the history table).
    let mut docs = l.identity_history()?;
    for row in l.identities()? {
        if !docs.iter().any(|(_, j, _)| j == &row.jws) {
            docs.push((row.run.clone(), row.jws.clone(), row.issued_at));
        }
    }
    for (run, jws, at) in docs {
        match wicket_identity::verify_identity(&jws, &key, at) {
            Ok(c) if c.run == run => ok += 1,
            Ok(_) => {
                println!("  identity of {run} issued at {at}: FAILED: names another run");
                bad += 1;
            }
            Err(e) => {
                println!("  identity of {run} issued at {at}: FAILED: {e}");
                bad += 1;
            }
        }
    }
    for (id, env, at) in l.envelopes()? {
        // Each message at the time wicket recorded it: the sender's identity must have been valid then.
        match wicket_identity::verify_envelope(&env, &key, at) {
            Ok((_, p)) if p.get("jti").and_then(|j| j.as_str()) == Some(id.as_str()) => ok += 1,
            Ok(_) => {
                println!("  message {id}: FAILED: id does not match its envelope");
                bad += 1;
            }
            Err(e) => {
                println!("  message {id}: FAILED: {e}");
                bad += 1;
            }
        }
    }
    Ok((ok, bad))
}

/// Re-verifies every passkey-signed record in the audit log (decisions and the console's other
/// actions) from the stored public keys alone: the signature must cover exactly what was recorded.
fn verify_signed_decisions(l: &Ledger) -> Result<(usize, usize)> {
    use wicket_auth::{decision_challenge, unb64u, Credential, RelyingParty};
    let keys = l.operator_credentials_all(&TenantId::single())?;
    let (mut ok, mut bad) = (0, 0);
    for (seq, _, kind, run, body) in l.audit_tail(usize::MAX >> 1)? {
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let Some(s) = v.get("signed") else { continue };
        let get = |k: &str| s.get(k).and_then(|x| x.as_str()).unwrap_or("");
        let result = (|| -> Result<()> {
            let key = keys.iter().find(|k| k.id == get("credential")).ok_or_else(|| anyhow::anyhow!("unknown credential"))?;
            let rp = RelyingParty { rp_id: get("rp_id").into(), origin: get("origin").into() };
            let signed_json = if kind == "decision" { get("decision_json") } else { get("action_json") };
            let challenge = decision_challenge(&unb64u(get("nonce"))?, signed_json);
            let decided: serde_json::Value = serde_json::from_str(signed_json)?;
            // The record must say what was signed: the same request and decision, or the same action
            // on the same run (and, for a started run, the same manifest bytes).
            let same = |k: &str| decided.get(k) == v.get(k);
            let matches = if kind == "decision" {
                same("request") && same("decision")
            } else {
                same("action")
                    && same("run")
                    && run.as_deref() == decided.get("run").and_then(|r| r.as_str())
                    && (kind != "run.console_start" || (same("manifest_sha256") && same("principal") && same("task")))
            };
            if !matches {
                bail!("record does not match the signed {}", if kind == "decision" { "decision" } else { "action" });
            }
            let cred = Credential { id: unb64u(&key.id)?, x: key.x, y: key.y, sign_count: 0 };
            rp.verify_assertion(
                &challenge,
                &cred,
                &unb64u(get("client_data_json"))?,
                &unb64u(get("authenticator_data"))?,
                &unb64u(get("signature"))?,
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => ok += 1,
            Err(e) => {
                println!("  seq {seq}: FAILED: {e}");
                bad += 1;
            }
        }
    }
    Ok((ok, bad))
}

/// A `serve` command's options, and whether it prints no enrolment link at start.
fn serve_opts(c: Cmd) -> Option<(serve::ServeOpts, bool)> {
    let Cmd::Serve {
        listen,
        origin,
        rp_id,
        tls_cert,
        tls_key,
        acme_domain,
        acme_agree_tos,
        acme_contact,
        acme_staging,
        acme_directory,
        acme_cache,
        behind_tls_terminator,
        trusted_proxy,
        max_connections,
        no_bootstrap_link,
    } = c
    else {
        return None;
    };
    Some((
        serve::ServeOpts {
            listen,
            origin,
            rp_id,
            tls_cert,
            tls_key,
            acme_domain,
            acme_contact,
            acme_directory,
            acme_staging,
            acme_agree_tos,
            acme_cache,
            behind_tls_terminator,
            trusted_proxy,
            max_connections,
        },
        no_bootstrap_link,
    ))
}

/// Where a secret may be sent, for terminals.
fn secret_hosts_line(v: &Vault, name: &str) -> String {
    let h = v.hosts(name);
    if h.is_empty() {
        format!("sent to no host (bind it: wicket secret hosts {name} --hosts HOST[,HOST])")
    } else {
        format!("sent only to {}", h.join(", "))
    }
}

/// The zone view (`wicket zone`): each host the zone's reach names, spliced or inspected, and why.
fn zone_view(zone: &wicket_core::ZoneSpec, json: bool) -> String {
    use wicket_core::splice::Inspection;
    let rows = wicket_core::splice::view(zone);
    if json {
        let v: Vec<serde_json::Value> = rows
            .iter()
            .map(|(h, i)| match i {
                Inspection::Spliced { rule } => serde_json::json!({ "host": h, "mode": "spliced", "rule": rule }),
                Inspection::Inspected(why) => serde_json::json!({ "host": h, "mode": "inspected", "why": why }),
            })
            .collect();
        return format!("{}\n", serde_json::to_string_pretty(&serde_json::json!({ "zone": zone.name, "hosts": v })).unwrap_or_default());
    }
    let mut out = format!("zone {}: egress over HTTPS (HTTP/3 is always terminated and inspected)\n", zone.name);
    let w = rows.iter().map(|(h, _)| h.len()).max().unwrap_or(0);
    for (h, i) in &rows {
        match i {
            Inspection::Spliced { rule } => out.push_str(&format!(
                "  {h:<w$}  SPLICED    reach rule {rule} allows every method and path: decided at connect, not inspected\n"
            )),
            Inspection::Inspected(why) => out.push_str(&format!("  {h:<w$}  INSPECTED  {why}\n")),
        }
    }
    if rows.iter().any(|(_, i)| i.is_spliced()) {
        out.push_str("  Spliced on the control host, and on a node while its policy is fresh (else inspected there).\n");
        out.push_str("  Spliced hosts get one audit row per connection, no per-request decisions or header filtering,\n");
        out.push_str("  and on a shared CDN may reach other sites behind it. Add a forbid rule to inspect one.\n");
    }
    if rows.is_empty() {
        out.push_str("  (reach names no hosts)\n");
    }
    out
}

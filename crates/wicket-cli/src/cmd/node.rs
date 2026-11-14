//! `wicket node`, `place`, `lease` and `reconcile`: nodes, capacity and cleanup.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
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
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum NodeCmd {
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
pub enum LeaseCmd {
    /// Every lease: status, holder run, node, money reserved, end.
    List,
    /// End a lease now: what runs on it stops and its node is destroyed (one reconcile pass).
    Release { id: String },
}

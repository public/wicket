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
mod cli_reference;
mod cmd;
mod daemon;
mod doctor;
mod enrol;
mod exitcause;
mod hibernate;
mod image;
mod images_policy;
mod links;
mod localnode;
mod mock;
mod node;
mod nodeauth;
mod nodecall;
mod noderun;
mod nodesecrets;
mod nodesrv;
mod oci;
mod registry;
mod pin;
mod place;
mod policy;
mod program;
mod reap;
mod reconcile;
mod roots;
mod run;
mod s3;
mod serve;
mod settings;
mod spawn;
mod state;
mod statestore;
mod transcript;
mod update;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
pub(crate) use cmd::approve::GrantCmd;
// Re-verifies signed console actions offline; the console's tests check their records with it.
#[cfg(test)]
pub(crate) use cmd::audit::verify_signed_decisions;
pub(crate) use cmd::audit::AuditCmd;
pub(crate) use cmd::dev::DevCmd;
pub(crate) use cmd::identity::IdentityCmd;
pub(crate) use cmd::image::ImageCmd;
pub(crate) use cmd::itself::SelfCmd;
pub(crate) use cmd::node::LeaseCmd;
pub(crate) use cmd::node::NodeCmd;
pub(crate) use cmd::operator::OperatorCmd;
pub(crate) use cmd::operator::ProgramCmd;
pub(crate) use cmd::policy::KeysCmd;
pub(crate) use cmd::policy::PolicyCmd;
pub(crate) use cmd::policy::StateCmd;
pub(crate) use cmd::secret::SecretCmd;
pub(crate) use cmd::zone::ZoneCmd;
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
    #[command(args_conflicts_with_subcommands = true)]
    Image {
        #[command(subcommand)]
        cmd: Option<ImageCmd>,
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
    #[command(args_conflicts_with_subcommands = true)]
    Zone {
        #[command(subcommand)]
        cmd: Option<ZoneCmd>,
        /// The manifest (YAML).
        manifest: Option<PathBuf>,
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

pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("WICKET_HOME") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/share/wicket")
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
        c @ (Cmd::Run { .. }
        | Cmd::Wrap { .. }
        | Cmd::Attach { .. }
        | Cmd::Say { .. }
        | Cmd::Hibernate { .. }
        | Cmd::Wake { .. }
        | Cmd::Agents { .. }) => cmd::run::dispatch(c).await,
        c @ (Cmd::Pending | Cmd::Approve { .. } | Cmd::Deny { .. } | Cmd::Grant { .. } | Cmd::Links { .. } | Cmd::Unlink { .. }) => {
            cmd::approve::dispatch(c).await
        }
        c @ Cmd::Identity { .. } => cmd::identity::dispatch(c).await,
        c @ Cmd::Audit { .. } => cmd::audit::dispatch(c).await,
        c @ Cmd::Secret { .. } => cmd::secret::dispatch(c).await,
        c @ (Cmd::Image { .. } | Cmd::Doctor { .. }) => cmd::image::dispatch(c).await,
        c @ Cmd::Zone { .. } => cmd::zone::dispatch(c).await,
        c @ (Cmd::Policy { .. } | Cmd::State { .. } | Cmd::Keys { .. }) => cmd::policy::dispatch(c).await,
        c @ (Cmd::Node { .. } | Cmd::Place { .. } | Cmd::Lease { .. } | Cmd::Reap { .. } | Cmd::Reconcile { .. }) => {
            cmd::node::dispatch(c).await
        }
        c @ Cmd::Itself { .. } => cmd::itself::dispatch(c).await,
        c @ (Cmd::Serve { .. } | Cmd::Operator { .. } | Cmd::Program { .. }) => cmd::operator::dispatch(c).await,
        c @ Cmd::Dev { .. } => cmd::dev::dispatch(c).await,
    }
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

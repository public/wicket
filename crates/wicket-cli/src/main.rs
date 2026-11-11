//! `wicket`: the proof-of-concept command line.
//!
//! `wicket run task.yaml` starts the run's enforcement points (egress proxy, LLM proxy) on unix
//! sockets, starts Claude Code in a gVisor box with no network, streams what happens, and records
//! every decision in the ledger. `wicket approve` / `wicket deny` decide pending escalations from
//! another terminal while the run waits.

mod mock;
mod node;
mod program;
mod reap;
mod run;
mod serve;
mod spawn;

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
    /// Print the installation issuer's public key (JWK): what verifiers need.
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
        /// Agent image.
        #[arg(long, default_value = "wicket/claude-code:poc")]
        image: String,
        /// Run the box on a remote node over ssh (e.g. wicket@203.0.113.7). The node gets no secrets.
        #[arg(long)]
        node: Option<String>,
        /// ssh identity for --node.
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// Internal: the run id to use (set by a parent starting a child agent).
        #[arg(long, hide = true)]
        run_id: Option<String>,
        /// Internal: the run that started this one (`spawn_agent`).
        #[arg(long, hide = true)]
        parent_run: Option<String>,
    },
    /// Send a follow-up message to a running agent, as its operator. It arrives as the agent's next
    /// turn; the session stays open for follow-ups for the agent's idle_timeout after each turn.
    Say { run: String, text: Vec<String> },
    /// Run an agent command line that another program launches, inside a wicket box: e.g. as Claude
    /// Code Remote Control's CLAUDE_CODE_PROCESS_WRAPPER. Its stdin and stdout stay connected to the
    /// launcher, its credentials become placeholders swapped at the proxy, and wicket logs to a file.
    Wrap {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "wicket/claude-code:poc")]
        image: String,
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
    },
    /// Deny a pending request.
    Deny { id: String },
    /// Show or verify the hash-chained audit log.
    Audit {
        #[arg(long, default_value_t = 40)]
        tail: usize,
        #[arg(long)]
        verify: bool,
    },
    /// Manage vault secrets (values are read from the terminal, never from arguments).
    Secret {
        #[command(subcommand)]
        cmd: SecretCmd,
    },
    /// Build the agent image.
    Image {
        #[arg(long, default_value = "wicket/claude-code:poc")]
        tag: String,
        #[arg(long, default_value = "images/claude-code")]
        dir: PathBuf,
    },
    /// Serve the operator console (runs, pending approvals, activity) on loopback.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        /// Allow a non-loopback listen address (put it behind a tailnet or tunnel anyway).
        #[arg(long)]
        allow_remote: bool,
        /// Browser origin for WebAuthn (default http://localhost:PORT).
        #[arg(long)]
        origin: Option<String>,
        /// WebAuthn relying-party id (default localhost).
        #[arg(long)]
        rp_id: Option<String>,
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
    /// Check the environment: Docker, gVisor, image, secrets, ledger, orphaned boxes.
    Doctor {
        #[arg(long, default_value = "wicket/claude-code:poc")]
        image: String,
    },
    /// Development helpers.
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
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
    /// Host-only break-glass: revoke every passkey, so `wicket serve` prints a fresh enrolment link.
    Reset,
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a secret. Prompts without echo, or reads stdin when it isn't a terminal.
    Set { name: String },
    /// List secret names (never values).
    List,
    /// Make a secret a reference to a JSON field in another file, re-read on every use (never copied).
    /// E.g. the Claude login on this host:
    /// wicket secret link claude-oauth --file ~/.claude/.credentials.json --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
    Link {
        name: String,
        #[arg(long)]
        file: String,
        #[arg(long)]
        pointer: String,
        #[arg(long)]
        expires_pointer: Option<String>,
    },
}

#[derive(Subcommand)]
enum DevCmd {
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

/// The principal behind a run started from this CLI: the local unix user. That is all the PoC CLI
/// knows; runs started from the console would carry the passkey-authenticated operator instead.
pub fn cli_principal() -> serde_json::Value {
    let user = std::env::var("USER").unwrap_or_else(|_| "operator".into());
    serde_json::json!({ "type": "human", "id": user, "via": "cli", "assurance": "unix-user" })
}

pub fn trust_domain() -> String {
    std::env::var("WICKET_TRUST_DOMAIN").unwrap_or_else(|_| "wicket.local".into())
}

pub fn issuer() -> Result<wicket_identity::Issuer> {
    Ok(wicket_identity::Issuer::load_or_create(&issuer_key_path(), &trust_domain())?)
}

fn operator() -> String {
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
    match cli.cmd {
        Cmd::Run { manifest, workdir, workspace_dir, task, image, node, ssh_key, run_id, parent_run } => {
            run::run(run::RunOpts {
                manifest: &manifest,
                workdir: workdir.as_deref(),
                workspace_dir: workspace_dir.as_deref(),
                task,
                image: &image,
                node: node.as_deref(),
                ssh_key: ssh_key.as_deref(),
                run_id,
                parent_run,
                wrap: None,
            })
            .await
        }
        Cmd::Wrap { manifest, image, argv } => {
            run::run(run::RunOpts {
                manifest: &manifest,
                workdir: None,
                workspace_dir: None,
                task: None,
                image: &image,
                node: None,
                ssh_key: None,
                run_id: None,
                parent_run: None,
                wrap: Some(argv),
            })
            .await
        }
        Cmd::Say { run, text } => {
            let text = text.join(" ");
            if text.trim().is_empty() {
                bail!("nothing to say");
            }
            let l = Ledger::open(&ledger_path())?;
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
        Cmd::Pending => {
            let l = Ledger::open(&ledger_path())?;
            let p = l.pending(&TenantId::single())?;
            if p.is_empty() {
                println!("no pending requests");
            }
            for r in p {
                let age = wicket_store::now() - r.created_at;
                println!(
                    "{}  {} {}{}{}  [{}]  run {}  {}s ago\n    why: {}",
                    r.id,
                    r.method,
                    r.host,
                    r.path,
                    if r.scope_prefix { "*  (every path under it)" } else { "" },
                    r.risk,
                    r.run,
                    age,
                    r.reason
                );
                println!("    agent: {}", identity_line(&verified_identity(&l, &r.run, None)));
                for a in &r.attribution {
                    println!(
                        "    for: {}  (reported by the agent, unverified)",
                        wicket_agent::clip(&wicket_proxy::attribution_line(a), 240)
                    );
                }
            }
            Ok(())
        }
        Cmd::Approve { id, uses, unlimited, ttl, prefix } => {
            let ttl = humantime::parse_duration(&ttl).context("bad --ttl")?;
            if ttl > Duration::from_secs(24 * 3600) {
                bail!("grants are capped at 24h in the PoC");
            }
            let mut l = Ledger::open(&ledger_path())?;
            let req = l.request(&id)?;
            let gid = l.approve(
                &id,
                &Approval { uses: if unlimited { None } else { Some(uses) }, ttl, path_prefix: prefix.clone(), decided_by: operator() },
            )?;
            l.audit(
                &TenantId::single(),
                None,
                "decision",
                &serde_json::json!({
                    "request": id, "decision": "approve", "grant": gid, "by": operator(),
                    "method": req.method, "host": req.host, "path": req.path,
                    "requested_by": req.attribution.iter().flat_map(wicket_proxy::attributed_agents).collect::<Vec<_>>(),
                    "agent_identity": verified_identity(&l, &req.run, None),
                    "uses": if unlimited { None } else { Some(uses) }, "ttl_secs": ttl.as_secs(), "prefix": prefix,
                }),
            )?;
            println!(
                "approved {id} → grant {gid}: {} {}{} ({}, {})",
                req.method,
                req.host,
                prefix.as_deref().map(|p| format!("{p}* [prefix]")).unwrap_or(req.path),
                if unlimited { "unlimited uses".into() } else { format!("{uses} use(s)") },
                humantime::format_duration(ttl)
            );
            Ok(())
        }
        Cmd::Deny { id } => {
            let l = Ledger::open(&ledger_path())?;
            l.deny(&id, &operator())?;
            l.audit(&TenantId::single(), None, "decision", &serde_json::json!({ "request": id, "decision": "deny", "by": operator() }))?;
            println!("denied {id}");
            Ok(())
        }
        Cmd::Identity { cmd } => {
            let l = Ledger::open(&ledger_path())?;
            match cmd {
                IdentityCmd::Issuer => println!("{}", serde_json::to_string_pretty(&issuer()?.public_jwk())?),
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
        Cmd::Audit { tail, verify } => {
            let l = Ledger::open(&ledger_path())?;
            if verify {
                let n = l.verify_audit()?;
                println!("audit chain OK: {n} records");
                let (ok, bad) = verify_signed_decisions(&l)?;
                println!("passkey-signed decisions: {ok} verified offline, {bad} failed");
                let (iok, ibad) = verify_identities_and_messages(&l)?;
                println!("agent identities and signed messages: {iok} verified offline, {ibad} failed");
                if bad + ibad > 0 {
                    bail!("{} record(s) failed verification", bad + ibad);
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
                SecretCmd::Set { name } => {
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
                    println!("stored secret {name}");
                }
                SecretCmd::Link { name, file, pointer, expires_pointer } => {
                    v.link(&name, &file, &pointer, expires_pointer.as_deref())?;
                    println!("secret {name} now refers to {file}#{pointer} (read at each use; never copied)");
                }
                SecretCmd::List => {
                    for n in v.list() {
                        println!("{n}");
                    }
                }
            }
            Ok(())
        }
        Cmd::Image { tag, dir } => {
            wicket_sandbox::Docker::from_env().build_image(&tag, &dir).await?;
            println!("built {tag}");
            Ok(())
        }
        Cmd::Doctor { image } => doctor(&image).await,
        Cmd::Reap { dry_run, node, ssh_key } => {
            let docker = match node {
                Some(n) => wicket_sandbox::Docker::over_ssh(node::Node::new(&n, ssh_key.as_deref()).ssh_prefix()),
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
        Cmd::Serve { listen, allow_remote, origin, rp_id } => serve::serve(&listen, allow_remote, origin, rp_id).await,
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
                OperatorCmd::Reset => {
                    let n = l.reset_operator_credentials(&TenantId::single())?;
                    l.audit(
                        &TenantId::single(),
                        None,
                        "operator.reset",
                        &serde_json::json!({ "removed": n, "by": operator(), "via": "host break-glass" }),
                    )?;
                    println!(
                        "revoked {n} passkey(s) (public keys kept for audit verification); restart `wicket serve` for an enrolment link"
                    );
                }
            }
            Ok(())
        }
        Cmd::Dev { cmd: DevCmd::MockLlm { listen, command } } => mock::serve(&listen, &command).await,
    }
}

/// Re-verifies every passkey-signed decision in the audit log from the stored public keys alone: the
/// signature must cover exactly the recorded decision.
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

fn verify_signed_decisions(l: &Ledger) -> Result<(usize, usize)> {
    use wicket_auth::{decision_challenge, unb64u, Credential, RelyingParty};
    let keys = l.operator_credentials_all(&TenantId::single())?;
    let (mut ok, mut bad) = (0, 0);
    for (seq, _, kind, _, body) in l.audit_tail(usize::MAX >> 1)? {
        if kind != "decision" {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let Some(s) = v.get("signed") else { continue };
        let get = |k: &str| s.get(k).and_then(|x| x.as_str()).unwrap_or("");
        let result = (|| -> Result<()> {
            let key = keys.iter().find(|k| k.id == get("credential")).ok_or_else(|| anyhow::anyhow!("unknown credential"))?;
            let rp = RelyingParty { rp_id: get("rp_id").into(), origin: get("origin").into() };
            let challenge = decision_challenge(&unb64u(get("nonce"))?, get("decision_json"));
            let decided: serde_json::Value = serde_json::from_str(get("decision_json"))?;
            if decided.get("request") != v.get("request") || decided.get("decision") != v.get("decision") {
                bail!("record does not match the signed decision");
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

async fn doctor(image: &str) -> Result<()> {
    let d = wicket_sandbox::Docker::from_env();
    let mut ok = true;
    match d.runtimes().await {
        Ok(rt) => {
            println!("docker: ok (runtimes: {})", rt.join(", "));
            if !rt.iter().any(|r| r == "runsc") {
                println!("  gVisor (runsc) is not registered: zones default to isolation: gvisor");
                ok = false;
            }
        }
        Err(e) => {
            println!("docker: NOT OK ({e})");
            ok = false;
        }
    }
    match d.image_exists(image).await {
        Ok(true) => println!("image {image}: present"),
        _ => {
            println!("image {image}: missing (run: wicket image)");
            ok = false;
        }
    }
    let v = Vault::new(Vault::default_dir());
    let names = v.list();
    println!("vault: {} secret(s){}", names.len(), if names.is_empty() { String::new() } else { format!(": {}", names.join(", ")) });
    if !v.has("claude-oauth") {
        println!("  no 'claude-oauth' secret: real runs need your Claude subscription token");
        println!("  (run `claude setup-token`, then: wicket secret set claude-oauth)");
    }
    let l = Ledger::open(&ledger_path())?;
    println!("ledger: {} (audit chain OK, {} records)", ledger_path().display(), l.verify_audit()?);
    if let Ok(all) = reap::reap(&d, &l, true).await {
        let orphans: Vec<_> = all.iter().filter(|r| matches!(r.verdict, reap::Verdict::Orphan(_))).map(|r| r.name.as_str()).collect();
        if orphans.is_empty() {
            println!("boxes: {} running, none orphaned", all.len());
        } else {
            println!("boxes: {} orphaned, with nothing behind them: {} (run: wicket reap)", orphans.len(), orphans.join(", "));
        }
    }
    if !ok {
        bail!("environment not ready");
    }
    Ok(())
}

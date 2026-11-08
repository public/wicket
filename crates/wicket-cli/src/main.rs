//! `wicket`: the proof-of-concept command line.
//!
//! `wicket run task.yaml` starts the run's enforcement points (egress proxy, LLM proxy) on unix
//! sockets, starts Claude Code in a gVisor box with no network, streams what happens, and records
//! every decision in the ledger. `wicket approve` / `wicket deny` decide pending escalations from
//! another terminal while the run waits.

mod mock;
mod node;
mod program;
mod run;
mod serve;

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
enum Cmd {
    /// Run a task manifest: one Claude Code agent in one zone.
    Run {
        manifest: PathBuf,
        /// Copy this directory into the box's /workspace first.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// Agent image.
        #[arg(long, default_value = "wicket/claude-code:poc")]
        image: String,
        /// Run the box on a remote node over ssh (e.g. wicket@203.0.113.7). The node gets no secrets.
        #[arg(long)]
        node: Option<String>,
        /// ssh identity for --node.
        #[arg(long)]
        ssh_key: Option<PathBuf>,
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
    /// Check the environment: Docker, gVisor, image, secrets, ledger.
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
        Cmd::Run { manifest, workdir, image, node, ssh_key } => run::run(&manifest, workdir.as_deref(), &image, node.as_deref(), ssh_key.as_deref()).await,
        Cmd::Pending => {
            let l = Ledger::open(&ledger_path())?;
            let p = l.pending(&TenantId::single())?;
            if p.is_empty() {
                println!("no pending requests");
            }
            for r in p {
                let age = wicket_store::now() - r.created_at;
                println!("{}  {} {}{}  [{}]  run {}  {}s ago\n    why: {}", r.id, r.method, r.host, r.path, r.risk, r.run, age, r.reason);
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
            let gid = l.approve(&id, &Approval { uses: if unlimited { None } else { Some(uses) }, ttl, path_prefix: prefix.clone(), decided_by: operator() })?;
            l.audit(&TenantId::single(), None, "decision", &serde_json::json!({
                "request": id, "decision": "approve", "grant": gid, "by": operator(),
                "method": req.method, "host": req.host, "path": req.path,
                "uses": if unlimited { None } else { Some(uses) }, "ttl_secs": ttl.as_secs(), "prefix": prefix,
            }))?;
            println!("approved {id} → grant {gid}: {} {}{} ({}, {})", req.method, req.host, prefix.as_deref().map(|p| format!("{p}* [prefix]")).unwrap_or(req.path), if unlimited { "unlimited uses".into() } else { format!("{uses} use(s)") }, humantime::format_duration(ttl));
            Ok(())
        }
        Cmd::Deny { id } => {
            let l = Ledger::open(&ledger_path())?;
            l.deny(&id, &operator())?;
            l.audit(&TenantId::single(), None, "decision", &serde_json::json!({ "request": id, "decision": "deny", "by": operator() }))?;
            println!("denied {id}");
            Ok(())
        }
        Cmd::Audit { tail, verify } => {
            let l = Ledger::open(&ledger_path())?;
            if verify {
                let n = l.verify_audit()?;
                println!("audit chain OK: {n} records");
                let (ok, bad) = verify_signed_decisions(&l)?;
                println!("passkey-signed decisions: {ok} verified offline, {bad} failed");
                if bad > 0 {
                    bail!("{bad} signed decision(s) failed verification");
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
                    l.audit(&TenantId::single(), None, "operator.reset", &serde_json::json!({ "removed": n, "by": operator(), "via": "host break-glass" }))?;
                    println!("revoked {n} passkey(s) (public keys kept for audit verification); restart `wicket serve` for an enrolment link");
                }
            }
            Ok(())
        }
        Cmd::Dev { cmd: DevCmd::MockLlm { listen, command } } => mock::serve(&listen, &command).await,
    }
}

/// Re-verifies every passkey-signed decision in the audit log from the stored public keys alone: the
/// signature must cover exactly the recorded decision.
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
            rp.verify_assertion(&challenge, &cred, &unb64u(get("client_data_json"))?, &unb64u(get("authenticator_data"))?, &unb64u(get("signature"))?)?;
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
    if !ok {
        bail!("environment not ready");
    }
    Ok(())
}

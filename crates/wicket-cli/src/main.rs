//! `wicket`: the proof-of-concept command line.
//!
//! `wicket run task.yaml` starts the run's enforcement points (egress proxy, LLM proxy) on unix
//! sockets, starts Claude Code in a gVisor box with no network, streams what happens, and records
//! every decision in the ledger. `wicket approve` / `wicket deny` decide pending escalations from
//! another terminal while the run waits.

// say! and say_err!, from wicket-home (#219), for every module here.
#[macro_use]
extern crate wicket_home;
mod out;

// The control/node channel and the modules its messages carry: a crate of their own (#219), under
// their old names here.
use wicket_chan::{chan, health};
// The installation's paths, its identity issuer and who is calling: a crate of their own (#219),
// under their old names here.
#[cfg(test)]
use wicket_home::principal_from_env;
use wicket_home::{
    confirm, data_dir, identity_line, issuer, issuer_key_path, ledger_path, operator, show_request, trust_domain, verified_identity,
};

// Modules that need only wicket-home's helpers moved with them (#219), under their old names here.
use wicket_home::{audit_export, control, owner, program, s3, statestore};
// The node, `wicket node serve` and its gateway (#219), under its old name here.
use wicket_node::nodesrv;
// The control host's core, a run's supervisor and what it needs (#219), under their old names here.
#[cfg(test)]
use wicket_control::spawn;
use wicket_control::{
    capacity, effect, enrol, grant, hibernate, image, localnode, node, nodecall, nodecreate, noderun, operators, policy, roots, run,
    snapstore, storegc, transcript,
};

mod apply_update;
mod ci_update;
mod cli_reference;
mod cmd;
mod daemon;
mod doctor;
mod intake;
mod invariants;
mod mock;
mod names_view;
mod pin;
mod reconcile;
mod rootcopy;
mod serve;
mod session;
mod state;
mod statesync;
mod top;
mod units;
mod update;
mod webauthn;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
pub(crate) use cmd::approve::GrantCmd;
pub(crate) use cmd::approve::RequestCmd;
pub(crate) use cmd::capacity::CapacityCmd;
// Re-verifies signed console actions offline; the console's tests check their records with it.
#[cfg(test)]
pub(crate) use cmd::audit::verify_signed_decisions;
pub(crate) use cmd::audit::AuditCmd;
pub(crate) use cmd::dev::DevCmd;
pub(crate) use cmd::identity::IdentityCmd;
pub(crate) use cmd::image::ImageCmd;
pub(crate) use cmd::itself::SelfCmd;
pub(crate) use cmd::message::MessageCmd;
pub(crate) use cmd::names::NamesCmd;
pub(crate) use cmd::node::LeaseCmd;
pub(crate) use cmd::node::NodeCmd;
pub(crate) use cmd::operator::OperatorCmd;
pub(crate) use cmd::operator::ProgramCmd;
pub(crate) use cmd::policy::KeysCmd;
pub(crate) use cmd::policy::PolicyCmd;
pub(crate) use cmd::policy::StateCmd;
pub(crate) use cmd::secret::SecretCmd;
pub(crate) use cmd::service::ServiceCmd;
pub(crate) use cmd::standing::StandingCmd;
pub(crate) use cmd::trigger::TriggerCmd;
pub(crate) use cmd::zone::ZoneCmd;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Duration;
use wicket_core::TenantId;
use wicket_proxy::vault::Vault;
use wicket_store::Ledger;

/// `wicket --help`'s commands, by area (#574): what an operator does daily first. Every visible
/// command is in one area; a test holds it to that.
const AREAS: &[(&str, &[&str])] = &[
    (
        "Runs and agents",
        &["run", "session", "message", "top", "agents", "hibernate", "trigger", "wrap", "links", "unlink", "zone", "program", "image"],
    ),
    ("Approvals and grants", &["pending", "request", "approve", "deny", "grant", "capacity", "standing", "names", "authority", "audit"]),
    ("Nodes and placement", &["node", "lease", "service", "why-here", "reconcile"]),
    (
        "The installation",
        &["serve", "operator", "secret", "identity", "policy", "state", "keys", "doctor", "self", "daemon", "dev", "help"],
    ),
];

/// The command line's parser: [`Cli`]'s, with `wicket --help` listing the commands by [`AREAS`]
/// (clap lists a command's subcommands under one heading).
pub(crate) fn command() -> clap::Command {
    let mut c = <Cli as clap::CommandFactory>::command();
    c.build();
    let (h, lit) = (c.get_styles().get_header(), c.get_styles().get_literal());
    let width = AREAS.iter().flat_map(|(_, names)| names.iter().map(|n| n.len())).max().unwrap_or(0);
    let mut areas = String::new();
    for (area, names) in AREAS {
        areas.push_str(&format!("{}{area}:{}\n", h.render(), h.render_reset()));
        for n in *names {
            let about = c.find_subcommand(n).and_then(|s| s.get_about()).map(|a| a.to_string()).unwrap_or_default();
            areas.push_str(&format!("  {}{n}{}{:pad$}  {about}\n", lit.render(), lit.render_reset(), "", pad = width - n.len()));
        }
        areas.push('\n');
    }
    let options = format!("{}Options:{}", h.render(), h.render_reset());
    c.help_template(format!("{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{areas}{options}\n{{options}}{{after-help}}"))
}

#[derive(Parser)]
#[command(name = "wicket", version, about = "Run agents in least-privilege boxes (proof of concept)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a task manifest: one workload (an agent, or a program) in one zone.
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
        /// node serve`. Default: where the scheduler places it among the enrolled nodes, this host's
        /// own (`local`) among them; with --workspace-dir, this host's own.
        #[arg(long)]
        node: Option<String>,
        /// ssh identity for --node (default: the one it was enrolled with).
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// Internal: the run id to use (set by the console starting a run).
        #[arg(long, hide = true)]
        run_id: Option<String>,
        /// Without --node: how long to wait in the queue when no node may take it now (#579); 0:
        /// fail at once.
        #[arg(long, default_value = "0", value_parser = wicket_core::time::duration_arg)]
        wait: Duration,
    },
    /// Open a running agent's session in this terminal: watch it, and send it prompts.
    ///
    /// Open a running agent's session in this terminal, as its operator: what it says and does, live.
    /// An ACP agent's whole session shows, as on the console's session page; a Claude Code agent's
    /// messages, tool calls and turn ends. Each line typed is a prompt, the agent's next turn; `/stop`
    /// cancels an ACP agent's running turn; Ctrl-C or the end of input leaves, and the agent goes on.
    /// With TEXT, sends it as one prompt and exits when that turn ends. A long-lived agent can be named
    /// by its id or any of its runs; a hibernated one is woken.
    Session {
        run: String,
        /// A prompt to send; then only its turn shows.
        text: Vec<String>,
        /// With TEXT: queue it and exit at once.
        #[arg(long)]
        no_wait: bool,
        /// With TEXT: stop following its turn after this long (it stays queued). Seconds, or a
        /// duration (`90s`, `5m`).
        #[arg(long, value_parser = wicket_core::time::duration_arg)]
        timeout: Option<Duration>,
    },
    /// Messages with agents: send, read your inbox, follow receipts.
    ///
    /// Messages with agents (#252), as an operator: the same signed envelopes, rules and receipts
    /// agents have with each other. You may write to an agent that acts for you, whose accept_from
    /// names you, or that wrote to you; an agent may write to you if it acts for you. A message is
    /// data and grants nothing: `wicket session` prompts an agent.
    Message {
        #[command(subcommand)]
        cmd: MessageCmd,
    },
    /// Hibernate a long-lived agent at its next quiet point.
    ///
    /// Hibernate a long-lived agent (by run or agent id) at its next quiet point: its turn has ended
    /// and nothing but the agent runs in its box. What else runs is stopped after the zone's
    /// limits.exit_grace.
    Hibernate {
        run: String,
        /// How long to wait for the outcome: seconds, or a duration (`90s`, `5m`).
        #[arg(long, default_value = "120s", value_parser = wicket_core::time::duration_arg)]
        wait: Duration,
    },
    /// Internal: wake a hibernated agent (rebuild its box, restore its state, resume its harness
    /// session) and run the woken activation in the foreground. What a message to the agent, or
    /// `wicket session <agent>`, starts (#249): an operator wakes an agent that way. Text, if given,
    /// is the operator's message to it.
    #[command(hide = true)]
    Wake {
        agent: String,
        text: Vec<String>,
        /// What woke it (recorded and told to the agent).
        #[arg(long, hide = true)]
        by: Option<String>,
        /// How long to wait in the queue when no node may take it now (#579); 0: fail at once.
        #[arg(long, default_value = "30m", value_parser = wicket_core::time::duration_arg)]
        wait: Duration,
    },
    /// A live view of nodes, runs, pending requests and leases (read-only).
    ///
    /// A live view of what wicket is doing across its nodes (read-only): nodes (connected, boxes,
    /// what their boxes are given), runs (node, agent, status, uptime, model usage), pending
    /// requests and active leases. Redrawn every 2 s; q or Ctrl-C quits. On a node, `wicket node top`.
    Top {
        /// Print one frame and exit (also what a stdout that isn't a terminal gets, every 2 s, without it).
        #[arg(long)]
        once: bool,
        /// One frame as JSON, then exit (implies --once).
        #[arg(long)]
        json: bool,
    },
    /// Long-lived agents: state, generation, current run and bundle size.
    Agents {
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Why a run's box went on the node it did, or why it went nowhere.
    ///
    /// Why a run's box went on the node it did, or why it went nowhere (#579): what it asked for,
    /// the nodes it may go on in order, and every reason each other node was out.
    WhyHere {
        run: String,
        #[arg(long)]
        json: bool,
    },
    /// A run's authority now: its token as its node's feed holds it, and its grants.
    ///
    /// A run's authority (#173), as the console's view of it (#713): its status, node and org policy
    /// version, its deadline and what its node holds for it, and its token as the node's feed holds
    /// it now: what its zone may reach and never reach, each block decoded (zone, grant or spawn;
    /// who signed it, and whether it is revoked) and each grant with who approved it. No token,
    /// signature, secret value or key is printed.
    Authority {
        run: String,
        #[arg(long)]
        json: bool,
    },
    /// Supervise a run again whose supervisor died (#151): what `wicket reconcile` starts for a run
    /// still running on its node.
    #[command(hide = true)]
    Attach { run: String },
    /// Run an agent command line that another program launches, inside a wicket box.
    ///
    /// Run an agent command line that another program launches, inside a wicket box: the harness's
    /// wrapped mode (e.g. its Remote Control sessions' process wrapper). Its stdin and stdout stay connected to the
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
    /// List pending requests: what boxes asked for, waiting for a decision.
    ///
    /// List pending requests: what boxes asked for that their zones don't allow, waiting for a grant
    /// or a denial.
    Pending {
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
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
        #[arg(long, default_value = "10m", value_parser = wicket_core::time::duration_arg)]
        ttl: std::time::Duration,
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
    /// Pending requests: `wicket request list` is `wicket pending`.
    Request {
        #[command(subcommand)]
        cmd: RequestCmd,
    },
    /// Links between boxes (expose/connect/link), newest first.
    Links {
        #[arg(long, default_value_t = 40)]
        tail: usize,
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Cut a link between boxes: its relay closes it and drops its connections within seconds.
    Unlink { id: String },
    /// Grants made by approvals.
    Grant {
        #[command(subcommand)]
        cmd: GrantCmd,
    },
    /// Names for boxes: internal names, and the public names a human approves.
    ///
    /// Names for boxes (#575): internal names, and the public names a human approves.
    Names {
        #[command(subcommand)]
        cmd: NamesCmd,
    },
    /// Standing reach: a reach rule an agent asked for once, approved once for its later runs.
    ///
    /// Standing reach (#572): a reach rule an agent asked for once, approved once for its later runs.
    Standing {
        #[command(subcommand)]
        cmd: StandingCmd,
    },
    /// Triggers: when a schedule or timer comes due, wake or message an agent.
    ///
    /// Triggers (#578): when a schedule or timer comes due, wake or message an agent.
    Trigger {
        #[command(subcommand)]
        cmd: TriggerCmd,
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
        /// The records as JSON instead of text.
        #[arg(long, conflicts_with = "verify")]
        json: bool,
        #[command(subcommand)]
        cmd: Option<AuditCmd>,
    },
    /// Manage vault secrets (values are read from the terminal, never from arguments).
    Secret {
        #[command(subcommand)]
        cmd: SecretCmd,
    },
    /// Build the agent image.
    ///
    /// Build the agent image (the image directory plus the in-box forwarder's source, compiled in the
    /// build). Without --dir, from the copy embedded in this binary, so the image matches it.
    #[command(args_conflicts_with_subcommands = true)]
    Image {
        #[command(subcommand)]
        cmd: Option<ImageCmd>,
        /// The tag to build, kept as given [default: this installation's own image: the default
        /// harness's image repository, tagged with the build id on an installed version, else its
        /// default tag].
        #[arg(long)]
        tag: Option<String>,
        /// An image directory to build instead (e.g. one under images/, while changing it). If its
        /// Dockerfile declares `ARG BASE`, BASE is this installation's own agent image.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Serve the operator console.
    ///
    /// Serve the operator console (runs, approvals, activity; start, steer and revoke runs). Plain
    /// HTTP on loopback by default; any other address needs HTTPS (--acme-domain, or --tls-cert and
    /// --tls-key) or --behind-tls-terminator.
    Serve {
        #[command(flatten)]
        opts: serve::ServeOpts,
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
    /// Agent identities: the issuer's public key, and verified identity documents.
    ///
    /// Agent identities (design §3.2): the issuer's public key, and verified identity documents.
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// The installation's org policy (Cedar): a ceiling and forbids over every zone.
    ///
    /// The installation's org policy in Cedar (#51): a ceiling and forbids over every zone, compiled
    /// into each box's token when it is minted.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Control-plane state off this host: the state store, the recovery kit, a restore.
    ///
    /// Control-plane state off this host (#154): the state store, the ledger's stream, the recovery
    /// kit and a restore onto a standby.
    State {
        #[command(subcommand)]
        cmd: StateCmd,
    },
    /// The installation's root keys.
    ///
    /// The installation's root keys (#154).
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Make what exists agree with the ledger: runs, leases, machines, boxes and public names.
    ///
    /// Make what exists agree with the ledger (#38): end runs whose process is gone, end leases past
    /// their end or whose run ended, destroy owned machines no lease needs (checking the owner tag again
    /// right before each destroy), adopt or create the ones leases need, and stop boxes whose run has
    /// ended, here and on enrolled nodes. With `names.public` in wicket.yaml, also make the boxes zone's
    /// records that wicket owns agree with the live public names, through its DNS provider (#575; the
    /// noop provider only records the plan). Records every change in the audit log.
    Reconcile {
        /// Only report what would change.
        #[arg(long)]
        dry_run: bool,
        /// Keep running, one pass per interval (e.g. 30s).
        #[arg(long, value_parser = wicket_core::time::duration_arg)]
        every: Option<std::time::Duration>,
    },
    /// Capacity leases: the nodes agents asked for.
    ///
    /// Capacity leases (#7): nodes agents asked for with request_capacity. Approve or deny the
    /// request with `wicket approve`/`deny` (see `wicket pending`).
    Lease {
        #[command(subcommand)]
        cmd: LeaseCmd,
    },
    /// Capacity grants: what a principal may lease without asking.
    ///
    /// Standing capacity grants (#256): a principal may lease nodes within a grant's terms (how many
    /// at once, money an hour and a day, plans and regions) without asking, until it lapses. The
    /// console's Capacity card, from the host (#713).
    Capacity {
        #[command(subcommand)]
        cmd: CapacityCmd,
    },
    /// How a manifest's zone treats each host it reaches: inspected or spliced, and why.
    ///
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
    /// Per-node services: programs kept running on every node whose boxes use them.
    ///
    /// Per-node services (#579): programs kept running on every node whose boxes use them.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Check the environment: Docker, gVisor, image, secrets, ledger, orphaned boxes.
    Doctor {
        /// The agent image to check [default: the default harness's agent image].
        #[arg(long)]
        image: Option<String>,
        /// Instead, check this installation's ledger for #321's invariants (#326): every allowed
        /// egress request had a reach rule or a live grant, no run's model spend passed its budget,
        /// no node ran past its lease, no node was released with a run's work on it uncollected, and
        /// no message was pushed to a box twice (#324). Read only; exits non-zero on any violation.
        #[arg(long)]
        invariants: bool,
        /// With --invariants: how long past a lease's end a run or the lease may still have ended
        /// (the reconciler's cadence), in seconds.
        #[arg(long, default_value_t = 600, requires = "invariants")]
        lease_grace: i64,
    },
    /// Nodes, the machines that run boxes: leased from a provider, or your own.
    ///
    /// Nodes (#16, #37), machines that run boxes: leased from a provider (create, release, plans) or
    /// your own (one-time join tokens, enrolment with a pinned ssh host key, a node key and a
    /// name-constrained node CA); listing with leases and cost, revoking, renewing the CA.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Development helpers.
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
    /// Update this installation to another wicket build, with a health gate and rollback.
    ///
    /// Update this installation to another wicket build (#162): blue/green, with a health gate and
    /// automatic rollback, on the control host and then its nodes. Only artifacts signed by a
    /// release key this installation trusts, or whose sha256 an operator approved (an agent's
    /// `request_update`), are accepted. See docs/explanation/updates.md.
    #[command(name = "self")]
    Itself {
        #[command(subcommand)]
        cmd: SelfCmd,
    },
    /// wicketd: serve other users' commands over a unix socket, as the policy allows.
    ///
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

fn main() {
    let first = std::env::args().nth(1);
    let rt = runtime(first.as_deref()).expect("a tokio runtime");
    if let Err(e) = rt.block_on(run()) {
        // As a `main` returning the error would print it (not a run's own status, which its run
        // has told already), then the code for its kind (#574).
        if e.downcast_ref::<wicket_home::exit::Status>().is_none() {
            let _ = std::io::Write::write_fmt(&mut std::io::stderr(), format_args!("Error: {e:?}\n"));
        }
        std::process::exit(exit_code(&e));
    }
}

/// The commands that supervise a run for its whole life, one process each (`wicket run`, `attach`,
/// `wrap`, and `wake`, which supervises the woken agent): what a host runs hundreds of at once.
fn supervises(first_arg: Option<&str>) -> bool {
    matches!(first_arg, Some("run" | "attach" | "wrap" | "wake"))
}

/// Worker threads a supervisor's runtime has (#582 step 4), unless `WICKET_SUPERVISOR_WORKERS`
/// says otherwise. Its work is relaying sockets and waiting on its box. Any multi-thread runtime
/// runs `block_in_place` (one worker would too); the second worker is a spare, so a task that is
/// slow on one doesn't stall the relays, without one thread per core per supervisor.
pub(crate) const SUPERVISOR_WORKERS: usize = 2;

/// The most `WICKET_SUPERVISOR_WORKERS` may ask for.
pub(crate) const SUPERVISOR_WORKERS_MAX: usize = 64;

/// The most blocking-pool threads a supervisor may have at once; idle ones end after tokio's
/// keep-alive. They do its ledger and file work, and each `block_in_place` takes one while it
/// lasts: a worker that blocks (`wicket_proxy`'s wait for a granted request's audit commit) hands
/// its place to a pool thread. Those waits are milliseconds, on the audit writer's own thread, so
/// one that finds the pool full only runs with a worker fewer until a wait ends: it can't deadlock.
pub(crate) const SUPERVISOR_BLOCKING: usize = 32;

/// `WICKET_SUPERVISOR_WORKERS` read: the workers to run, and a warning if the value was refused
/// (not a number, 0) or capped.
fn supervisor_workers(v: Option<&str>) -> (usize, Option<String>) {
    let Some(v) = v else { return (SUPERVISOR_WORKERS, None) };
    match v.trim().parse::<usize>() {
        Ok(0) | Err(_) => (
            SUPERVISOR_WORKERS,
            Some(format!(
                "WICKET_SUPERVISOR_WORKERS={v:?} isn't a number of workers (1 to {SUPERVISOR_WORKERS_MAX}): using {SUPERVISOR_WORKERS}"
            )),
        ),
        Ok(n) if n > SUPERVISOR_WORKERS_MAX => (
            SUPERVISOR_WORKERS_MAX,
            Some(format!("WICKET_SUPERVISOR_WORKERS={n} is over {SUPERVISOR_WORKERS_MAX}: using {SUPERVISOR_WORKERS_MAX}")),
        ),
        Ok(n) => (n, None),
    }
}

/// The runtime for this process: a small one for a supervisor, tokio's default (a worker per core)
/// for everything else.
fn runtime(first_arg: Option<&str>) -> std::io::Result<tokio::runtime::Runtime> {
    let mut b = tokio::runtime::Builder::new_multi_thread();
    if supervises(first_arg) {
        let (workers, warning) = supervisor_workers(std::env::var("WICKET_SUPERVISOR_WORKERS").ok().as_deref());
        if let Some(w) = warning {
            eprintln!("wicket: {w}");
        }
        b.worker_threads(workers).max_blocking_threads(SUPERVISOR_BLOCKING);
    }
    b.enable_all().build()
}

/// The exit code for `e` (#574; docs/reference/cli.md lists them): [`wicket_home::exit::status_of`],
/// the one classifier.
fn exit_code(e: &anyhow::Error) -> i32 {
    wicket_home::exit::status_of(e)
}

async fn run() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("WICKET_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    // Root runs only its own copies of wicket (#261).
    rootcopy::refuse_untrusted_exe()?;
    let cli = <Cli as clap::FromArgMatches>::from_arg_matches(&command().get_matches()).unwrap_or_else(|e| e.exit());
    // Root's link behind the build wicket's services run: one line, on stderr (not for
    // `self update`, `self admit` and `self rollback`, which are how it catches up).
    if !matches!(&cli.cmd, Cmd::Itself { cmd: SelfCmd::Update { .. } | SelfCmd::Admit { .. } | SelfCmd::Rollback { .. } }) {
        rootcopy::warn_if_skewed();
    }
    // With wicketd installed, this user can't read wicket's data: the daemon runs the command.
    let route = daemon::policy::route(&cli.cmd);
    match daemon::client::mode() {
        daemon::client::Mode::Daemon(sock) => match route {
            daemon::policy::Route::Forward(_) => {
                let around = rootcopy::Around::before(&cli.cmd)?;
                let code = daemon::client::forward(&sock, &cli.cmd).await?;
                around.after(code);
                if code != 0 {
                    std::process::exit(code);
                }
                return Ok(());
            }
            daemon::policy::Route::Refuse(why) => return Err(wicket_home::exit::refused(why)),
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
        | Cmd::Session { .. }
        | Cmd::Hibernate { .. }
        | Cmd::Wake { .. }
        | Cmd::Agents { .. }
        | Cmd::WhyHere { .. }) => cmd::run::dispatch(c).await,
        Cmd::Authority { run, json } => cmd::authority::run(&run, json),
        Cmd::Capacity { cmd } => cmd::capacity::dispatch(cmd).await,
        Cmd::Top { once, json } => top::control_top(once, json).await,
        c @ (Cmd::Pending { .. } | Cmd::Approve { .. } | Cmd::Deny { .. } | Cmd::Grant { .. } | Cmd::Links { .. } | Cmd::Unlink { .. }) => {
            cmd::approve::dispatch(c).await
        }
        Cmd::Request { cmd: RequestCmd::List { json } } => cmd::approve::dispatch(Cmd::Pending { json }).await,
        Cmd::Names { cmd } => cmd::names::dispatch(cmd).await,
        Cmd::Message { cmd } => cmd::message::dispatch(cmd).await,
        Cmd::Standing { cmd } => cmd::standing::dispatch(cmd).await,
        Cmd::Trigger { cmd } => cmd::trigger::dispatch(cmd).await,
        c @ Cmd::Identity { .. } => cmd::identity::dispatch(c).await,
        c @ Cmd::Audit { .. } => cmd::audit::dispatch(c).await,
        c @ Cmd::Secret { .. } => cmd::secret::dispatch(c).await,
        c @ (Cmd::Image { .. } | Cmd::Doctor { .. }) => cmd::image::dispatch(c).await,
        c @ Cmd::Zone { .. } => cmd::zone::dispatch(c).await,
        c @ Cmd::Service { .. } => cmd::service::dispatch(c).await,
        c @ (Cmd::Policy { .. } | Cmd::State { .. } | Cmd::Keys { .. }) => cmd::policy::dispatch(c).await,
        c @ (Cmd::Node { .. } | Cmd::Lease { .. } | Cmd::Reconcile { .. }) => cmd::node::dispatch(c).await,
        c @ Cmd::Itself { .. } => cmd::itself::dispatch(c).await,
        c @ (Cmd::Serve { .. } | Cmd::Operator { .. } | Cmd::Program { .. }) => cmd::operator::dispatch(c).await,
        c @ Cmd::Dev { .. } => cmd::dev::dispatch(c).await,
    }
}

#[cfg(test)]
mod tests {
    /// Threads this process has now (Linux: its tasks).
    fn threads() -> usize {
        std::fs::read_dir("/proc/self/task").map(|d| d.count()).unwrap_or(0)
    }

    /// The threads a runtime adds once every worker has run (no blocking work yet), and its
    /// workers as tokio counts them.
    fn threads_added(build: impl FnOnce() -> tokio::runtime::Runtime) -> (usize, usize) {
        let before = threads();
        let rt = build();
        let workers = rt.metrics().num_workers();
        let added = rt.block_on(async {
            let tasks: Vec<_> = (0..256).map(|_| tokio::spawn(async { tokio::task::yield_now().await })).collect();
            for t in tasks {
                t.await.unwrap();
            }
            threads() - before
        });
        drop(rt);
        (added, workers)
    }

    /// #582 step 4: a supervisor's runtime has two workers (and at most 32 blocking threads), not
    /// one worker per core and up to 512 blocking threads: what it costs doesn't grow with the
    /// host's cores. Other commands keep tokio's default.
    #[test]
    fn a_supervisor_runs_a_small_runtime() {
        assert!(crate::supervises(Some("run")) && crate::supervises(Some("attach")) && crate::supervises(Some("wake")));
        assert!(!crate::supervises(Some("serve")) && !crate::supervises(Some("reconcile")) && !crate::supervises(None));
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let (small, small_workers) = threads_added(|| crate::runtime(Some("run")).unwrap());
        let (default, default_workers) = threads_added(|| crate::runtime(Some("serve")).unwrap());
        assert_eq!(small_workers, crate::SUPERVISOR_WORKERS);
        assert_eq!(crate::supervisor_workers(None), (crate::SUPERVISOR_WORKERS, None));
        assert_eq!(crate::supervisor_workers(Some("4")), (4, None));
        for bad in ["0", "many", "-1", ""] {
            let (n, w) = crate::supervisor_workers(Some(bad));
            assert_eq!(n, crate::SUPERVISOR_WORKERS, "{bad:?}");
            assert!(w.unwrap().contains("isn't a number of workers"), "{bad:?}");
        }
        let (n, w) = crate::supervisor_workers(Some("1000"));
        assert_eq!(n, crate::SUPERVISOR_WORKERS_MAX);
        assert!(w.unwrap().contains("is over"));
        assert_eq!(default_workers, cores);
        // The threads each added are printed, not asserted: a runtime's threads end after it is
        // dropped, so a count taken around another runtime can be off by a few.
        eprintln!("worker threads: supervisor runtime {small_workers} (added {small}), default runtime {default_workers} (added {default}), on {cores} cores");
    }

    /// #574: `wicket --help` lists every visible command once, in its area, and nothing else.
    #[test]
    fn every_command_is_in_one_area() {
        let mut c = <crate::Cli as clap::CommandFactory>::command();
        c.build();
        let mut visible: Vec<&str> = c.get_subcommands().filter(|s| !s.is_hide_set()).map(|s| s.get_name()).collect();
        let mut listed: Vec<&str> = crate::AREAS.iter().flat_map(|(_, n)| n.iter().copied()).collect();
        visible.sort();
        listed.sort();
        assert_eq!(listed, visible);
        let help = crate::command().render_help().to_string();
        assert!(help.contains("Runs and agents:\n  run ") && help.contains("Approvals and grants:\n  pending "), "{help}");
        assert!(!help.contains("Commands:"), "{help}");
        // Every line of the list fits in about 100 columns.
        let long: Vec<&str> = help.lines().filter(|l| l.chars().count() > 100).collect();
        assert!(long.is_empty(), "{long:#?}");
    }

    /// #574: the flags that took seconds take a duration too, and a number is still seconds.
    #[test]
    fn seconds_flags_take_durations_too() {
        let wait = |args: &[&str]| match <crate::Cli as clap::Parser>::try_parse_from(args).unwrap().cmd {
            crate::Cmd::Hibernate { wait, .. } => wait,
            _ => unreachable!(),
        };
        assert_eq!(wait(&["wicket", "hibernate", "a"]), std::time::Duration::from_secs(120));
        assert_eq!(wait(&["wicket", "hibernate", "a", "--wait", "90"]), std::time::Duration::from_secs(90));
        assert_eq!(wait(&["wicket", "hibernate", "a", "--wait", "5m"]), std::time::Duration::from_secs(300));
        assert!(<crate::Cli as clap::Parser>::try_parse_from(["wicket", "hibernate", "a", "--wait", "5q"]).is_err());
        // wake's --wait too: 0 still means don't wait.
        let wake = |args: &[&str]| match <crate::Cli as clap::Parser>::try_parse_from(args).unwrap().cmd {
            crate::Cmd::Wake { wait, .. } => wait,
            _ => unreachable!(),
        };
        assert_eq!(wake(&["wicket", "wake", "a"]), std::time::Duration::from_secs(1800));
        assert_eq!(wake(&["wicket", "wake", "a", "--wait", "0"]), std::time::Duration::ZERO);
        assert_eq!(wake(&["wicket", "wake", "a", "--wait", "90"]), std::time::Duration::from_secs(90));
    }

    /// #574: one name for one thing, the old one kept as an alias.
    #[test]
    fn the_old_names_still_parse() {
        use clap::Parser;
        for (old, new) in [
            (&["wicket", "secret", "rm", "x"][..], &["wicket", "secret", "remove", "x"][..]),
            (&["wicket", "pending", "--json"], &["wicket", "request", "list", "--json"]),
            (&["wicket", "pending"], &["wicket", "request", "list"]),
            (&["wicket", "standing", "approve", "s-1", "--lasts", "7d"], &["wicket", "standing", "approve", "s-1", "--ttl", "7d"]),
            (&["wicket", "standing", "renew", "s-1", "--lasts", "forever"], &["wicket", "standing", "renew", "s-1", "--ttl", "forever"]),
        ] {
            let (a, b) = (crate::Cli::try_parse_from(old).unwrap().cmd, crate::Cli::try_parse_from(new).unwrap().cmd);
            assert_eq!(crate::daemon::policy::route(&a), crate::daemon::policy::route(&b), "{old:?}");
            assert_eq!(fields(a), fields(b), "{old:?}");
        }
        // What each parsed to, field by field.
        fn fields(c: crate::Cmd) -> String {
            use crate::{Cmd, RequestCmd, SecretCmd, StandingCmd};
            match c {
                Cmd::Pending { json } | Cmd::Request { cmd: RequestCmd::List { json } } => format!("pending json={json}"),
                Cmd::Secret { cmd: SecretCmd::Rm { name } } => format!("secret remove {name}"),
                Cmd::Standing { cmd: StandingCmd::Approve { id, bound, lasts, narrow, yes } } => {
                    format!("standing approve {id} for={bound} ttl={lasts} narrow={narrow} yes={yes}")
                }
                Cmd::Standing { cmd: StandingCmd::Renew { id, lasts } } => format!("standing renew {id} ttl={lasts}"),
                _ => unreachable!("not one of the renamed commands"),
            }
        }
        assert_eq!(
            fields(crate::Cli::try_parse_from(["wicket", "standing", "renew", "s-1", "--lasts", "5d"]).unwrap().cmd),
            "standing renew s-1 ttl=5d"
        );
    }

    /// #574: each kind of failure has its code, whichever crate it comes from.
    #[test]
    fn errors_exit_with_the_code_for_their_kind() {
        use wicket_home::exit;
        let code = |e: anyhow::Error| crate::exit_code(&e);
        assert_eq!(code(anyhow::anyhow!("anything")), 1);
        assert_eq!(code(exit::usage("x")), 2);
        assert_eq!(code(exit::refused("x")), 3);
        assert_eq!(code(exit::not_found("x")), 4);
        assert_eq!(code(exit::needs_approval("x")), 5);
        assert_eq!(code(exit::Exit { code: exit::Code::TryAgain, msg: "moving".into() }.into()), 75);
        assert_eq!(code(wicket_store::StoreError::NoSuchRequest("r-1".into()).into()), 4);
        assert_eq!(code(anyhow::Error::from(wicket_store::StoreError::NotPending("r-1".into(), "denied".into())).context("deciding")), 3);
        assert_eq!(code(wicket_store::StoreError::Refused("x".into()).into()), 3);
        assert_eq!(code(wicket_placement::PlacementError::Undecided("nobody decided".into()).into()), 5);
        assert_eq!(code(wicket_placement::PlacementError::NotApproved("request r-1 is denied".into()).into()), 3);
        assert_eq!(code(wicket_placement::PlacementError::ApprovalFailed("the ledger".into()).into()), 1);
        // The innermost says: a decision refused (3) because there was no such request (4) is 4.
        let refused_unknown = anyhow::Error::from(wicket_store::StoreError::NoSuchRequest("r-nope".into()))
            .context(exit::Exit::refused("refused (the refusal is on the audit record)"));
        assert_eq!(code(refused_unknown), 4);
        assert_eq!(code(anyhow::anyhow!("outside its authority").context(exit::Exit::refused("refused"))), 3);
        // A tag over a store error that says otherwise: the store's, innermost.
        assert_eq!(code(anyhow::Error::from(wicket_store::StoreError::NoSuchRequest("r-1".into())).context("x")), 4);
        assert_eq!(code(wicket_placement::PlacementError::NoCapacity("none".into()).into()), 1);
    }

    /// `wicket run --image` is parsed, and without it nothing is named: no default that would hide
    /// the manifest's agent.image (wicket-control's `run::box_image` applies it).
    #[test]
    fn the_image_flag_names_no_default() {
        let parse = |args: &[&str]| match <crate::Cli as clap::Parser>::try_parse_from(args).unwrap().cmd {
            crate::Cmd::Run { image, .. } => image,
            _ => unreachable!(),
        };
        assert_eq!(parse(&["wicket", "run", "m.yaml"]), None, "no default that would hide the manifest's");
        assert_eq!(parse(&["wicket", "run", "--image", "img:other", "m.yaml"]).as_deref(), Some("img:other"));
    }
}

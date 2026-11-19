//! `wicket node`, `lease` and `reconcile`: nodes, capacity and cleanup.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Reconcile { dry_run, every } => {
            let every = every.as_deref().map(wicket_core::time::parse_duration).transpose().context("bad --every")?;
            reconcile::command(dry_run, every).await
        }
        Cmd::Lease { cmd: LeaseCmd::List } => capacity::list(),
        Cmd::Lease { cmd: LeaseCmd::Release { id } } => {
            let l = Ledger::open(&ledger_path())?;
            let x = l.lease(&id)?.ok_or_else(|| wicket_home::exit::not_found(format!("no lease {id}")))?;
            let why = format!("released by {}", operator());
            match x.status.as_str() {
                "active" => {
                    l.set_lease_not_after(&id, wicket_store::now())?;
                }
                "pending" | "approved" => {
                    l.lease_ended(&id, "withdrawn", &why, None)?;
                }
                s => return Err(wicket_home::exit::refused(format!("lease {id} is {s}"))),
            }
            l.audit(&TenantId::single(), None, "lease.released", &serde_json::json!({ "lease": id, "by": operator() }))?;
            drop(l);
            reconcile::print(&reconcile::pass(false).await?, false);
            Ok(())
        }
        Cmd::Node { cmd } => match cmd {
            NodeCmd::Token { name, ttl } => enrol::token(name, wicket_core::time::parse_duration(&ttl)?),
            NodeCmd::Enrol { target, token, name, ssh_key, host_key, trust_first_use, hosts, ca_ttl, cert_ttl } => {
                enrol::enrol(enrol::EnrolOpts {
                    target,
                    token,
                    name,
                    ssh_key,
                    host_key,
                    trust_first_use,
                    hosts,
                    ca_ttl: wicket_core::time::parse_duration(&ca_ttl)?,
                    cert_ttl: wicket_core::time::parse_duration(&cert_ttl)?,
                })
                .await
            }
            NodeCmd::List { provider, common } => {
                enrol::list()?;
                if provider {
                    println!();
                    nodecreate::list_provider(&common).await?;
                }
                Ok(())
            }
            NodeCmd::Create(args) => nodecreate::create(*args).await,
            NodeCmd::Release { common, id } => nodecreate::release(common, id).await,
            NodeCmd::Plans { common, region, plan_type } => nodecreate::plans(common, region, plan_type).await,
            NodeCmd::Revoke { name } => {
                let mut l = Ledger::open(&ledger_path())?;
                let serials = enrol::revoke(&mut l, &enrol::Paths::installation().nodes_dir, &name)?;
                println!("revoked node {name}; its CA serials {} go on the feed's revocation list", serials.join(", "));
                Ok(())
            }
            NodeCmd::RenewCa { name, hosts, ca_ttl, cert_ttl } => {
                enrol::renew_ca(&name, hosts, wicket_core::time::parse_duration(&ca_ttl)?, wicket_core::time::parse_duration(&cert_ttl)?)
                    .await
            }
            NodeCmd::Set { name, ca_hosts, labels, taints } => set(&name, ca_hosts.as_deref(), &labels, &taints),
            NodeCmd::Install { name, ssh_key, no_service } => crate::update::install(&name, ssh_key.as_deref(), no_service).await,
            NodeCmd::Serve { dir, idle_exit } => nodesrv::serve(dir, idle_exit).await,
            NodeCmd::Attach { dir } => nodesrv::attach(dir).await,
            NodeCmd::Top { dir, once, json } => crate::top::node_top(dir, once, json).await,
            NodeCmd::Forget { run, force } => noderun::forget_command(&run, force, &operator()).await,
        },
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

/// What `--label` and `--taint` say: set or remove, by key.
#[derive(Debug, PartialEq)]
enum Mark {
    Label(String, Option<String>),
    Taint(String, Option<wicket_core::placement::Taint>),
}

/// `key=value` sets a label and `key-` removes it; `key` or `key=value` taints, `key-` removes.
fn marks(labels: &[String], taints: &[String]) -> Result<Vec<Mark>> {
    use wicket_core::placement::{check_key, check_value, Taint};
    let mut out = vec![];
    for l in labels {
        out.push(match (l.split_once('='), l.strip_suffix('-')) {
            (Some((k, v)), _) => {
                check_key(k).and_then(|_| check_value(v)).map_err(|e| anyhow::anyhow!("--label {l}: {e}"))?;
                Mark::Label(k.into(), Some(v.into()))
            }
            (None, Some(k)) => {
                check_key(k).map_err(|e| anyhow::anyhow!("--label {l}: {e}"))?;
                Mark::Label(k.into(), None)
            }
            (None, None) => bail!("--label {l}: key=value sets a label, key- removes it"),
        });
    }
    for t in taints {
        out.push(match t.strip_suffix('-').filter(|_| !t.contains('=')) {
            Some(k) => {
                check_key(k).map_err(|e| anyhow::anyhow!("--taint {t}: {e}"))?;
                Mark::Taint(k.into(), None)
            }
            None => {
                let parsed = Taint::parse(t).map_err(|e| anyhow::anyhow!("--taint {t}: {e}"))?;
                Mark::Taint(parsed.key.clone(), Some(parsed))
            }
        });
    }
    Ok(out)
}

/// `wicket node set`: a node's CA policy, labels and taints, each change audited. Everything is
/// parsed before anything is written.
fn set(name: &str, ca_hosts: Option<&str>, labels: &[String], taints: &[String]) -> Result<()> {
    anyhow::ensure!(ca_hosts.is_some() || !labels.is_empty() || !taints.is_empty(), "say what to set: --ca-hosts, --label or --taint");
    let policy = ca_hosts.map(|c| wicket_store::CaHosts::parse(c).map_err(anyhow::Error::msg)).transpose()?;
    let marks = marks(labels, taints)?;
    let l = Ledger::open(&ledger_path())?;
    if l.node(name)?.is_none() {
        return Err(wicket_home::exit::not_found(format!("node {name} is not enrolled")));
    }
    let tenant = wicket_core::TenantId::single();
    if let Some(policy) = policy {
        l.set_node_ca_policy_audited(name, &policy, &operator())?;
        println!(
            "node {name}: its CA is widened at runtime {}",
            match &policy {
                wicket_store::CaHosts::Fixed => "never (its hosts change only with wicket node renew-ca)".to_string(),
                wicket_store::CaHosts::Auto => "to every inspected host its boxes need".to_string(),
                wicket_store::CaHosts::Allowed(h) => format!("to the hosts its boxes need that match {}", h.join(", ")),
            }
        );
    }
    if marks.is_empty() {
        return Ok(());
    }
    let mut changed = false;
    for m in &marks {
        changed |= match m {
            Mark::Label(k, v) => l.set_node_label(name, k, v.as_deref())?,
            Mark::Taint(_, Some(t)) => l.set_node_taint(name, t)?,
            Mark::Taint(k, None) => l.remove_node_taint(name, k)?,
        };
    }
    let (labels, taints) = (l.node_labels(name)?, l.node_taints(name)?);
    if changed {
        let body = serde_json::json!({ "name": name, "labels": labels, "taints": taints, "by": operator() });
        l.audit(&tenant, None, "node.labels", &body)?;
    }
    let show = |xs: Vec<String>| if xs.is_empty() { "none".to_string() } else { xs.join(", ") };
    println!(
        "node {name}: labels {}; taints {}",
        show(labels.iter().map(|(k, v)| format!("{k}={v}")).collect()),
        show(taints.iter().map(|t| t.to_string()).collect())
    );
    Ok(())
}

#[cfg(test)]
mod set_tests {
    use super::*;
    use wicket_core::placement::Taint;

    #[test]
    fn labels_and_taints_parse_as_set_or_remove() {
        let s = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            marks(&s(&["gpu=a100", "zone-", "empty="]), &s(&["dedicated=ci", "spot", "old-"])).unwrap(),
            vec![
                Mark::Label("gpu".into(), Some("a100".into())),
                Mark::Label("zone".into(), None),
                Mark::Label("empty".into(), Some(String::new())),
                Mark::Taint("dedicated".into(), Some(Taint::parse("dedicated=ci").unwrap())),
                Mark::Taint("spot".into(), Some(Taint::parse("spot").unwrap())),
                Mark::Taint("old".into(), None),
            ]
        );
        assert_eq!(
            marks(&[], &s(&["k=v-"])).unwrap(),
            vec![Mark::Taint("k".into(), Some(Taint::parse("k=v-").unwrap()))],
            "a value may end in -"
        );
        for (l, t) in [(vec!["gpu"], vec![]), (vec!["Bad=x"], vec![]), (vec![], vec!["a b"]), (vec![], vec!["-"])] {
            assert!(marks(&s(&l), &s(&t)).is_err(), "{l:?} {t:?}");
        }
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
    /// Enrol a machine you already have, over ssh: pin its host key, have it make its node key and CA key, and give it a
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
        /// Host names the node's CA may mint certificates for: `api.example.com`, `*.example.org` (comma-separated).
        #[arg(long, value_delimiter = ',', required = true)]
        hosts: Vec<String>,
        /// Node CA lifetime.
        #[arg(long, default_value = "24h")]
        ca_ttl: String,
        /// Node identity certificate lifetime (renewed over the control channel at half-life).
        #[arg(long, default_value = "24h")]
        cert_ttl: String,
    },
    /// List nodes: each enrolled node, and each node's lease, provider and cost if it has them (a
    /// node from `wicket node create` or a capacity lease), with any leased node not enrolled.
    List {
        /// Also ask the provider (Vultr) for this installation's instances by owner tag: their state,
        /// cost and next paid hour, and any this ledger doesn't record.
        #[arg(long)]
        provider: bool,
        #[command(flatten)]
        common: nodecreate::Common,
    },
    /// Lease a machine from a provider (Vultr) and enrol it, with its ssh host key generated here and
    /// pinned at creation. Its money is reserved first against placement.yaml's limits (with every
    /// lease's); then its spend is a CAPACITY request from you: approved at once by a capacity grant
    /// of yours that covers it, otherwise waiting for an operator.
    Create(Box<nodecreate::CreateArgs>),
    /// Destroy a node `wicket node create` made, now (refusing anything without the owner tag), and
    /// revoke its enrolment.
    Release {
        #[command(flatten)]
        common: nodecreate::Common,
        /// The provider's instance id, or the node's name.
        id: String,
    },
    /// List a provider's (Vultr's) plans in a region, with their hourly price.
    Plans {
        #[command(flatten)]
        common: nodecreate::Common,
        #[arg(long, default_value = "lhr")]
        region: String,
        #[arg(long, default_value = "vc2")]
        plan_type: String,
    },
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
    /// On the node, as its `wicket` user: a live view of the node (read-only): its identity and CA,
    /// its control connections, feed, load, memory and disk; each box's state, uptime, CPU and
    /// memory, model use and budget slice left, egress counts and queued asks; and the last egress
    /// decisions. Redrawn every 2 s; q or Ctrl-C quits.
    Top {
        /// The node's directory (default: $WICKET_NODE_HOME or ~/.local/share/wicket-node).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Print one frame and exit (also what a stdout that isn't a terminal gets, every 2 s, without it).
        #[arg(long)]
        once: bool,
        /// Print the node's status once, as JSON.
        #[arg(long, conflicts_with = "once")]
        json: bool,
    },
    /// Let a run's node delete the run's files, its workspace among them. Refused while the run's
    /// work hasn't been collected (its files fetched, its outbox taken, a push or a hibernation
    /// bundle), unless --force; a forced delete is audited.
    Forget {
        /// The run.
        run: String,
        /// Delete them even though the run's work was never collected.
        #[arg(long)]
        force: bool,
    },
    /// On the node: join stdin and stdout to `node serve`'s control socket (what the control host
    /// runs over ssh).
    #[command(hide = true)]
    Attach {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Set what placement and the control host know of an enrolled node: its labels and taints
    /// (#579), and how its CA may be widened at runtime (#573). A box goes on a node only if the
    /// node has every label the box's `placement.node_selector` names, and the box tolerates every
    /// taint the node has. A CA widening is a renewal over the run's channel, audited as
    /// `node.ca_widened`.
    Set {
        name: String,
        /// `fixed` (never: its hosts change only with renew-ca), `auto` (to every inspected host its
        /// boxes' reach or grants need), or a comma-separated list of hosts it may be widened to
        /// (`api.example.com,*.example.org`).
        #[arg(long)]
        ca_hosts: Option<String>,
        /// `key=value` sets a label, `key-` removes it. Repeatable.
        #[arg(long = "label")]
        labels: Vec<String>,
        /// `key` or `key=value` taints the node (one taint per key), `key-` removes it. Repeatable.
        #[arg(long = "taint")]
        taints: Vec<String>,
    },
    /// Issue a node a fresh CA certificate (and CA key, made on the node) and a fresh identity
    /// certificate for its node key, over its pinned ssh: also how a node whose identity certificate
    /// expired while it was unreachable gets back in.
    RenewCa {
        name: String,
        /// Replace the host names it is constrained to (default: keep them).
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

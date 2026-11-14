//! `wicket place`: nodes from a provider, through the placement interface (`wicket-placement`, #37).
//!
//! `create` runs the whole path for one Vultr node: the money envelope and a terminal approval, a
//! tagged instance whose cloud-init runs `deploy/vultr/node-setup.sh` with an ssh host key generated
//! here and pinned before boot, the wait for it to be active and set up, and `wicket node enrol` with
//! that key (no trust on first use). Then the boot host key is scrubbed from the instance's user data.
//! `release` destroys an owned node and revokes its enrolment. `list` and `plans` only read.
//!
//! The Vultr API key comes from the vault (`wicket secret set vultr-api-key`) and goes only into the
//! API's Authorization header.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;
use wicket_core::TenantId;
use wicket_placement::boot::{self, SCRUBBED_USER_DATA};
use wicket_placement::model::Boot;
use wicket_placement::vultr::{ApiKey, Client, VultrConfig, VultrProvider};
use wicket_placement::*;
use wicket_proxy::vault::Vault;
use wicket_store::Ledger;

#[derive(clap::Args, Clone)]
pub struct Common {
    /// The vault secret holding the Vultr API key.
    #[arg(long, default_value = "vultr-api-key")]
    api_key_secret: String,
    /// The owner tag's installation name (default: this installation's trust domain, else "wicket").
    /// Garbage collection only ever touches instances carrying it, so keep it stable.
    #[arg(long)]
    owner: Option<String>,
}

// Parsed once per process; boxing `Create` would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand)]
pub enum PlaceCmd {
    /// List Vultr plans in a region with their hourly price.
    Plans {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value = "lhr")]
        region: String,
        #[arg(long, default_value = "vc2")]
        plan_type: String,
    },
    /// List this installation's nodes (by owner tag) with their paid time.
    List {
        #[command(flatten)]
        common: Common,
    },
    /// Create a Vultr node inside a money envelope, after approval on this terminal, and enrol it with
    /// its host key pinned at creation.
    Create {
        #[command(flatten)]
        common: Common,
        /// Node name (hostname, label and enrolled name).
        #[arg(long)]
        name: String,
        /// Hosts the node's CA may issue for, as for `wicket node enrol --hosts`.
        #[arg(long, value_delimiter = ',', required_unless_present = "no_enrol")]
        hosts: Vec<String>,
        #[arg(long, default_value = "lhr")]
        region: String,
        /// A plan id (e.g. vc2-1c-2gb); otherwise the cheapest that fits --vcpus and --memory-mib.
        #[arg(long)]
        plan: Option<String>,
        #[arg(long, default_value_t = 1)]
        vcpus: u32,
        #[arg(long, default_value_t = 2048)]
        memory_mib: u64,
        /// How long the node is needed: its worst-case cost is reserved for this long, and its lease
        /// ends at minute 50 of the last hour.
        #[arg(long, default_value = "1h")]
        lifetime: String,
        /// Most this node may cost per hour, in dollars.
        #[arg(long)]
        max_node_hourly: Option<String>,
        /// Envelope: most all owned nodes together may cost per hour, in dollars.
        #[arg(long)]
        max_hourly: String,
        /// Envelope: most all owned nodes together may cost through their leases, in dollars.
        #[arg(long)]
        max_total: String,
        /// Id of an ssh key already in the Vultr account (installed for root, copied to `wicket`).
        #[arg(long = "ssh-key-id", required = true)]
        ssh_key_ids: Vec<String>,
        /// The private half of that key, on this host.
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// Vultr os_id (default: Ubuntu 24.04 x64).
        #[arg(long, default_value_t = wicket_placement::vultr::UBUNTU_2404_OS_ID)]
        os_id: u32,
        /// Make a retried create return the same node (default: derived from --name).
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Create and wait, but don't enrol.
        #[arg(long)]
        no_enrol: bool,
        #[arg(long, default_value = "24h")]
        ca_ttl: String,
        /// Give up on the node, and release it, if nothing answers on its ssh port for this long (every
        /// connect times out or is unreachable). Once the port answers (accepted or refused), wait up to
        /// 15 minutes for setup.
        #[arg(long, default_value = "4m")]
        give_up_silent: String,
    },
    /// Destroy an owned node now (refusing anything without the owner tag) and revoke its enrolment.
    Release {
        #[command(flatten)]
        common: Common,
        /// The Vultr instance id.
        id: String,
    },
}

fn owner(c: &Common) -> Owner {
    let name = c.owner.clone().or_else(|| crate::issuer().ok().map(|i| i.trust_domain)).unwrap_or_else(|| "wicket".into());
    Owner::new(&name)
}

fn provider(c: &Common, config: VultrConfig) -> Result<VultrProvider> {
    let key = Vault::new(Vault::default_dir()).get(&c.api_key_secret)?;
    Ok(VultrProvider::new(Client::new(ApiKey::new(key))?, config))
}

fn dollars(s: &str) -> Result<MicroUsd> {
    MicroUsd::parse_dollars(s).with_context(|| format!("{s:?} is not a dollar amount"))
}

fn fmt_time(t: i64) -> String {
    humantime::format_rfc3339_seconds(std::time::UNIX_EPOCH + Duration::from_secs(t.max(0) as u64)).to_string()
}

/// Asks on the terminal. Without one, nothing is approved.
///
/// Through wicketd (an installed host) the command runs in the daemon, which has no controlling
/// terminal: there the caller's own stdin and stderr, passed over the socket, are the terminal when
/// both are one. Piped input is never taken as an approval.
struct TerminalApprover;

/// The caller's terminal: /dev/tty, else stdin (read) and stderr (write) when both are terminals.
fn approval_terminal() -> Option<(Box<dyn std::io::Read + Send>, Box<dyn std::io::Write + Send>)> {
    use std::io::IsTerminal;
    if let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        let w = tty.try_clone().ok()?;
        return Some((Box::new(tty), Box::new(w)));
    }
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        return Some((Box::new(std::io::stdin()), Box::new(std::io::stderr())));
    }
    None
}

impl SpendApprover for TerminalApprover {
    async fn approve(&self, r: &SpendRequest) -> Approval {
        let r = r.clone();
        tokio::task::spawn_blocking(move || {
            let Some((tty, mut w)) = approval_terminal() else {
                return Approval::Denied("no terminal to ask on".into());
            };
            let _ = writeln!(
                w,
                "\nspend approval: {} node {:?} for {:?}\n  plan {} in {}: {}/h, for {} (worst case {})\n  already committed: {}/h, {} (envelope: {}/h, {} total)",
                r.backend,
                r.node_name,
                r.purpose,
                r.plan,
                r.region.as_deref().unwrap_or("?"),
                r.hourly,
                humantime::format_duration(Duration::from_secs(r.lifetime_secs.max(0) as u64)),
                r.worst_case,
                r.committed_hourly,
                r.committed_total,
                r.max_hourly,
                r.max_total
            );
            let _ = write!(w, "approve? type yes: ");
            let _ = w.flush();
            let mut line = String::new();
            let _ = std::io::BufReader::new(tty).read_line(&mut line);
            if line.trim() == "yes" {
                Approval::Approved
            } else {
                Approval::Denied("the operator did not type yes".into())
            }
        })
        .await
        .unwrap_or(Approval::Denied("approval prompt failed".into()))
    }
}

pub async fn run(cmd: PlaceCmd) -> Result<()> {
    match cmd {
        PlaceCmd::Plans { common, region, plan_type } => {
            let p = provider(&common, VultrConfig::default())?;
            let mut plans: Vec<_> =
                p.client().list_plans(&plan_type).await?.into_iter().filter(|p| p.locations.contains(&region)).collect();
            plans.sort_by_key(|p| (p.hourly_rate(), p.id.clone()));
            for p in plans {
                println!("{:<24} {:>2} vCPU {:>6} MB  {}/h  (${}/month)", p.id, p.vcpu_count, p.ram, p.hourly_rate(), p.monthly_cost);
            }
            Ok(())
        }
        PlaceCmd::List { common } => {
            let o = owner(&common);
            let p = Placer::new(
                provider(&common, VultrConfig::default())?,
                envelope::DenyAll,
                o.clone(),
                MoneyEnvelope { max_hourly: MicroUsd::ZERO, max_total: MicroUsd::ZERO },
            );
            let nodes = p.list().await?;
            for n in &nodes {
                println!(
                    "{}  {:<16} {:<14} {:<4} {:?}  {}  {}/h  created {}  lease until {}  next paid hour {}",
                    n.id,
                    n.name,
                    n.plan.as_deref().unwrap_or("?"),
                    n.region.as_deref().unwrap_or("?"),
                    n.state,
                    n.ssh_target.as_deref().unwrap_or("-"),
                    n.billing.hourly_rate(),
                    fmt_time(n.created_at),
                    n.lease_until.map(fmt_time).unwrap_or_else(|| "-".into()),
                    p.next_paid_hour_at(n).map(fmt_time).unwrap_or_else(|| "-".into()),
                );
            }
            println!("{} node(s) tagged {}", nodes.len(), o.tag());
            Ok(())
        }
        PlaceCmd::Create {
            common,
            name,
            hosts,
            region,
            plan,
            vcpus,
            memory_mib,
            lifetime,
            max_node_hourly,
            max_hourly,
            max_total,
            ssh_key_ids,
            ssh_key,
            os_id,
            idempotency_key,
            no_enrol,
            ca_ttl,
            give_up_silent,
        } => {
            crate::enrol::validate_name(&name)?;
            if !no_enrol {
                wicket_proxy::ca::permitted_dns_subtrees(&hosts)?;
            }
            // Before anything is created or spent: the node is reached with this key now and on every
            // later run (enrolment records its path), by whoever runs wicket here. Through wicketd that is
            // the wicket user, which can't read a key in the caller's home.
            if let Some(k) = &ssh_key {
                std::fs::File::open(k).with_context(|| {
                    format!(
                        "reading the ssh key {} (on an installed host wicket reaches nodes as the wicket user: keep the key where it can read it, e.g. /var/lib/wicket/ssh/, owned by wicket, mode 0600)",
                        k.display()
                    )
                })?;
            }
            let lifetime = humantime::parse_duration(&lifetime)?;
            let ca_ttl = humantime::parse_duration(&ca_ttl)?;
            let o = owner(&common);
            let config = VultrConfig { os_id, sshkey_ids: ssh_key_ids, default_region: region.clone(), ..VultrConfig::default() };
            let envelope = MoneyEnvelope { max_hourly: dollars(&max_hourly)?, max_total: dollars(&max_total)? };
            let placer = Placer::new(provider(&common, config)?, TerminalApprover, o.clone(), envelope);

            let host_key = boot::generate_host_key(&format!("wicket-node-{name}")).await?;
            let user_data = boot::cloud_config(boot::NODE_SETUP, &host_key)?;
            let pinned = host_key.public.clone();
            drop(host_key);
            let req = CapacityRequest {
                resources: Resources { vcpus, memory_mib },
                min_isolation: IsolationTier::Gvisor,
                region_hint: Some(region),
                plan_hint: plan,
                max_hourly: max_node_hourly.as_deref().map(dollars).transpose()?,
                lifetime_secs: lifetime.as_secs() as i64,
                idempotency_key: idempotency_key.unwrap_or_else(|| format!("place-create:{name}")),
                name: name.clone(),
                purpose: format!("wicket place create {name}"),
                boot: Some(Boot { user_data, host_key: pinned.clone() }),
            };
            let n = placer.acquire(&req).await?;
            println!(
                "created {} ({}), {}/h, lease until {}",
                n.id,
                name,
                n.billing.hourly_rate(),
                n.lease_until.map(fmt_time).unwrap_or_default()
            );
            if n.host_key.as_deref() != Some(pinned.as_str()) {
                bail!(
                    "{} already existed for this idempotency key and its pinned host key isn't known here: enrol it with `wicket node enrol` and a key from elsewhere, or release it",
                    n.id
                );
            }

            Ledger::open(&crate::ledger_path())?.audit(
                &TenantId::single(),
                None,
                "placement.node_created",
                &serde_json::json!({ "backend": n.backend, "id": n.id.0, "name": name, "plan": n.plan, "region": n.region,
                                     "hourly_usd_micros": n.billing.hourly_rate().0, "lease_until": n.lease_until, "owner": o.tag() }),
            )?;
            let hosts = (!no_enrol).then_some(hosts);
            let wait = boot::ReadyWait { silent_limit: humantime::parse_duration(&give_up_silent)?, ..boot::ReadyWait::default() };
            let ready = bring_up_or_release::<_, boot::SshProbe>(
                &placer,
                &crate::ledger_path(),
                &n,
                &name,
                &pinned,
                ssh_key,
                hosts,
                ca_ttl,
                &wait,
                None,
            )
            .await?;
            if let Some(next) = placer.next_paid_hour_at(&ready) {
                println!("next paid hour starts {}; release before then: wicket place release {}", fmt_time(next), n.id);
            }
            Ok(())
        }
        PlaceCmd::Release { common, id } => {
            let o = owner(&common);
            let p = Placer::new(
                provider(&common, VultrConfig::default())?,
                envelope::DenyAll,
                o,
                MoneyEnvelope { max_hourly: MicroUsd::ZERO, max_total: MicroUsd::ZERO },
            );
            let id = NodeId(id);
            let node = p.get(&id).await?;
            match p.release(&id, ReleaseMode::Now).await? {
                Released::AlreadyGone => println!("{id} is already gone"),
                r => println!("{id}: {r:?}"),
            }
            let mut ledger = Ledger::open(&crate::ledger_path())?;
            if let Some(n) = node {
                ledger.audit(&TenantId::single(), None, "placement.node_released", &serde_json::json!({ "id": id.0, "name": n.name }))?;
                let enrolled =
                    ledger.node(&n.name)?.filter(|r| r.status != "revoked" && n.ssh_target.as_deref() == Some(r.target.as_str()));
                if enrolled.is_some() {
                    crate::enrol::revoke(&mut ledger, &crate::enrol::Paths::installation().nodes_dir, &n.name)?;
                    println!("revoked node {}", n.name);
                }
            }
            Ok(())
        }
    }
}

/// After a Vultr node is created: waits until it is active and its setup has finished (logging in with
/// only `pinned` accepted), enrols it under `name` with that key pinned (unless `hosts` is None), and
/// replaces its user data so the boot host key leaves the metadata service. Returns the node as it is
/// now and its ssh target. Errors say the node is still billing, except [`boot::Unreachable`] (nothing
/// ever answered on its ssh port within `wait.silent_limit`): the caller releases the node for that.
#[allow(clippy::too_many_arguments)]
pub async fn bring_up(
    p: &VultrProvider,
    id: &NodeId,
    name: &str,
    pinned: &str,
    ssh_key: Option<PathBuf>,
    hosts: Option<Vec<String>>,
    ca_ttl: Duration,
    wait: &boot::ReadyWait,
) -> Result<(NodeHandle, String)> {
    bring_up_with::<boot::SshProbe>(p, id, name, pinned, ssh_key, hosts, ca_ttl, wait, None).await
}

/// [`bring_up`], with `probe` (tests) in place of the TCP connect and pinned ssh login.
#[allow(clippy::too_many_arguments)]
async fn bring_up_with<Q: boot::Probe>(
    p: &VultrProvider,
    id: &NodeId,
    name: &str,
    pinned: &str,
    ssh_key: Option<PathBuf>,
    hosts: Option<Vec<String>>,
    ca_ttl: Duration,
    wait: &boot::ReadyWait,
    probe: Option<&Q>,
) -> Result<(NodeHandle, String)> {
    let ready = match p.wait_active(id, wait.poll.min(Duration::from_secs(5)), Duration::from_secs(600)).await {
        Ok(r) => r,
        Err(e) => return Err(e.context(format!("{id} is still billing: `wicket place release {id}`"))),
    };
    let target = ready.ssh_target.clone().context("no address")?;
    println!(
        "{id} is active at {target}; waiting for node setup (host key pinned: {pinned}; giving up after {} without any answer on port {})",
        humantime::format_duration(wait.silent_limit),
        wait.port
    );
    let r = match probe {
        Some(q) => boot::wait_ready(q, &target, wait).await,
        None => boot::wait_ssh_ready(&target, pinned, ssh_key.as_deref(), wait).await,
    };
    if let Err(e) = r {
        if e.downcast_ref::<boot::Unreachable>().is_some() {
            return Err(e);
        }
        return Err(e.context(format!("{id} is still billing: `wicket place release {id}`")));
    }
    if let Some(hosts) = hosts {
        let ledger = Ledger::open(&crate::ledger_path())?;
        let token = ledger.create_node_token(&TenantId::single(), name, 600)?;
        ledger.audit(&TenantId::single(), None, "node.token", &serde_json::json!({ "name": name, "ttl_secs": 600, "by": "place" }))?;
        drop(ledger); // enrol opens its own
        crate::enrol::enrol(crate::enrol::EnrolOpts {
            target: target.clone(),
            token,
            name: Some(name.to_string()),
            ssh_key,
            host_key: Some(pinned.to_string()),
            trust_first_use: false,
            hosts,
            ca_ttl,
            cert_ttl: std::time::Duration::from_secs(wicket_identity::node::NODE_CERT_TTL_SECS as u64),
        })
        .await?;
    }
    // The private host key no longer needs to be in the metadata service.
    if let Err(e) = p.client().set_user_data(&id.0, SCRUBBED_USER_DATA).await {
        eprintln!("warning: could not replace {id}'s user data (it still holds the boot host key): {e:#}");
    }
    Ok((ready, target))
}

/// A node that never answered on the network: releases it through `placer` (which checks it is ours
/// and not protected), audits `placement.node_unreachable` with why, and returns the error to report.
/// Its lease's money leaves the envelope with it.
pub async fn give_up_unreachable<A: envelope::SpendApprover>(
    placer: &Placer<VultrProvider, A>,
    ledger: &Ledger,
    node: &NodeHandle,
    why: &boot::Unreachable,
) -> anyhow::Error {
    let id = &node.id;
    let released = placer.release(id, ReleaseMode::Now).await;
    let outcome = match &released {
        Ok(r) => format!("{r:?}"),
        Err(e) => format!("not released: {e}"),
    };
    let audited = ledger.audit(
        &TenantId::single(),
        None,
        "placement.node_unreachable",
        &serde_json::json!({ "backend": node.backend, "id": id.0, "name": node.name, "target": why.target, "port": why.port,
                             "silent_secs": why.after.as_secs(), "released": released.is_ok(), "outcome": outcome,
                             "reason": why.to_string() }),
    );
    if let Err(e) = audited {
        eprintln!("warning: could not audit giving up on {id}: {e:#}");
    }
    match released {
        Ok(_) => anyhow::anyhow!("{why}: released {id} ({}) rather than leave it billing", node.name),
        Err(e) => anyhow::anyhow!("{why}, and releasing it failed ({e}): {id} is still billing: `wicket place release {id}`"),
    }
}

/// [`bring_up`], and on [`boot::Unreachable`] [`give_up_unreachable`].
#[allow(clippy::too_many_arguments)]
async fn bring_up_or_release<A: envelope::SpendApprover, Q: boot::Probe>(
    placer: &Placer<VultrProvider, A>,
    ledger_path: &std::path::Path,
    n: &NodeHandle,
    name: &str,
    pinned: &str,
    ssh_key: Option<PathBuf>,
    hosts: Option<Vec<String>>,
    ca_ttl: Duration,
    wait: &boot::ReadyWait,
    probe: Option<&Q>,
) -> Result<NodeHandle> {
    match bring_up_with(placer.provider(), &n.id, name, pinned, ssh_key, hosts, ca_ttl, wait, probe).await {
        Ok((ready, _)) => Ok(ready),
        Err(e) => match e.downcast_ref::<boot::Unreachable>() {
            Some(u) => {
                let ledger = Ledger::open(ledger_path)?;
                Err(give_up_unreachable(placer, &ledger, n, u).await)
            }
            None => Err(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wicket_placement::envelope::{Approval, SpendApprover, SpendRequest};
    use wicket_placement::mock::{serve, Shared, KEY};

    /// When the mock's instances were created (2026-11-11T10:00:00Z); the placer's clock is a minute later.
    const CREATED: i64 = 1_794_391_200;
    const PINNED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePlaceholderKeyDataxxxxxxxxxxxxxxxxxxx wicket-node";

    struct Yes;

    impl SpendApprover for Yes {
        async fn approve(&self, _r: &SpendRequest) -> Approval {
            Approval::Approved
        }
    }

    /// A node whose ssh port first answers after `answers_after` (never if None) and whose setup is
    /// done `ready_after` from the start.
    struct Node {
        start: tokio::time::Instant,
        answers_after: Option<Duration>,
        ready_after: Duration,
        logins: AtomicUsize,
    }

    impl boot::Probe for Node {
        async fn reach(&self, _t: &str, _port: u16) -> boot::Reach {
            match self.answers_after {
                Some(a) if self.start.elapsed() >= a => boot::Reach::Answered,
                _ => boot::Reach::Silent,
            }
        }
        async fn ready(&self, _t: &str) -> anyhow::Result<Option<String>> {
            self.logins.fetch_add(1, Ordering::SeqCst);
            Ok((self.start.elapsed() < self.ready_after).then(|| "Permission denied (publickey)".to_string()))
        }
    }

    fn node(answers_after: Option<u64>, ready_after: u64) -> Node {
        Node {
            start: tokio::time::Instant::now(),
            answers_after: answers_after.map(Duration::from_millis),
            ready_after: Duration::from_millis(ready_after),
            logins: AtomicUsize::new(0),
        }
    }

    /// Short waits: no answer for 300 ms means no network; setup may take up to 3 s.
    fn wait() -> boot::ReadyWait {
        boot::ReadyWait {
            poll: Duration::from_millis(20),
            timeout: Duration::from_secs(3),
            silent_limit: Duration::from_millis(300),
            port: 22,
        }
    }

    /// Room in the envelope for one node at a time ($0.014/h, worst case $0.02 each).
    fn placer(base: &str) -> Placer<VultrProvider, Yes> {
        let client = Client::with_base(base, ApiKey::new(KEY)).unwrap();
        let config = VultrConfig { sshkey_ids: vec!["k1".into()], ..VultrConfig::default() };
        Placer::new(
            VultrProvider::new(client, config),
            Yes,
            Owner::new("example"),
            MoneyEnvelope { max_hourly: MicroUsd::parse_dollars("0.05").unwrap(), max_total: MicroUsd::parse_dollars("0.03").unwrap() },
        )
        .with_clock(std::sync::Arc::new(|| CREATED + 60))
    }

    fn request(name: &str) -> CapacityRequest {
        CapacityRequest {
            resources: Resources { vcpus: 1, memory_mib: 2048 },
            min_isolation: IsolationTier::Gvisor,
            region_hint: Some("lhr".into()),
            plan_hint: None,
            max_hourly: MicroUsd::parse_dollars("0.02"),
            lifetime_secs: 3600,
            idempotency_key: format!("place-create:{name}"),
            name: name.into(),
            purpose: format!("wicket place create {name}"),
            boot: Some(Boot { user_data: "#cloud-config\n{}\n".into(), host_key: PINNED.into() }),
        }
    }

    fn ledger_path(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-place-{tag}-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("ledger.db")
    }

    fn deletes(st: &Shared) -> Vec<String> {
        st.lock().unwrap().seen.iter().filter(|s| s.method == "DELETE").map(|s| s.path.clone()).collect()
    }

    #[tokio::test]
    async fn a_node_that_never_answers_is_released_early_audited_and_its_money_freed() {
        let (base, st) = serve().await;
        let p = placer(&base);
        let n = p.acquire(&request("n1")).await.unwrap();
        // The envelope holds one node: a second is refused while the first is billing.
        assert!(matches!(p.acquire(&request("n2")).await, Err(PlacementError::Envelope(_))));

        let path = ledger_path("silent");
        let probe = node(None, 0);
        let t0 = tokio::time::Instant::now();
        let e = bring_up_or_release(&p, &path, &n, "n1", PINNED, None, None, Duration::from_secs(60), &wait(), Some(&probe))
            .await
            .unwrap_err()
            .to_string();
        // Given up at the silent limit, not the timeout, and without a single ssh login.
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        assert_eq!(probe.logins.load(Ordering::SeqCst), 0);
        assert!(e.contains("never answered on port 22") && e.contains(&format!("released {}", n.id)), "{e}");
        assert!(!e.contains("still billing"), "{e}");

        assert_eq!(deletes(&st), vec![format!("/v2/instances/{}", n.id)]);
        assert!(st.lock().unwrap().instances.is_empty());
        let audit = Ledger::open(&path).unwrap().audit_of_kind("placement.node_unreachable").unwrap();
        assert_eq!(audit.len(), 1);
        let body: serde_json::Value = serde_json::from_str(&audit[0].body).unwrap();
        assert_eq!(body["id"], n.id.0.as_str());
        assert_eq!(body["released"], true);
        assert_eq!(body["port"], 22);
        assert!(body["reason"].as_str().unwrap().contains("never answered"), "{body}");

        // Its committed money left the envelope with it: the next node fits.
        let n2 = p.acquire(&request("n2")).await.unwrap();
        assert_ne!(n2.id, n.id);
    }

    #[tokio::test]
    async fn a_node_that_answers_and_finishes_setup_late_is_kept() {
        let (base, st) = serve().await;
        let p = placer(&base);
        let n = p.acquire(&request("n1")).await.unwrap();
        let path = ledger_path("late");
        // The port answers (refused, then accepted) at 100 ms; setup finishes at 800 ms, well past the
        // 300 ms silent limit and inside the 3 s timeout.
        let probe = node(Some(100), 800);
        let ready =
            bring_up_or_release(&p, &path, &n, "n1", PINNED, None, None, Duration::from_secs(60), &wait(), Some(&probe)).await.unwrap();
        assert_eq!(ready.id, n.id);
        assert!(probe.start.elapsed() >= Duration::from_millis(800));
        assert!(probe.logins.load(Ordering::SeqCst) > 1);
        assert!(deletes(&st).is_empty());
        assert_eq!(st.lock().unwrap().instances.len(), 1);
        assert!(Ledger::open(&path).unwrap().audit_of_kind("placement.node_unreachable").unwrap().is_empty());
        // The boot host key was scrubbed from its user data as before.
        assert!(st.lock().unwrap().seen.iter().any(|s| s.method == "PATCH" && s.body["user_data"].is_string()));
    }

    #[tokio::test]
    async fn a_node_that_answers_but_never_finishes_waits_the_whole_timeout_and_is_kept() {
        let (base, st) = serve().await;
        let p = placer(&base);
        let n = p.acquire(&request("n1")).await.unwrap();
        let path = ledger_path("stuck");
        let probe = node(Some(0), 60_000);
        let w = boot::ReadyWait { timeout: Duration::from_millis(900), ..wait() };
        let e = bring_up_or_release(&p, &path, &n, "n1", PINNED, None, None, Duration::from_secs(60), &w, Some(&probe)).await.unwrap_err();
        let e = format!("{e:#}");
        assert!(e.contains("still billing") && e.contains("not ready after"), "{e}");
        assert!(probe.start.elapsed() >= Duration::from_millis(850));
        assert!(deletes(&st).is_empty());
        assert!(Ledger::open(&path).unwrap().audit_of_kind("placement.node_unreachable").unwrap().is_empty());
    }
}

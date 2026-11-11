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
struct TerminalApprover;

impl SpendApprover for TerminalApprover {
    async fn approve(&self, r: &SpendRequest) -> Approval {
        let r = r.clone();
        tokio::task::spawn_blocking(move || {
            let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") else {
                return Approval::Denied("no terminal to ask on".into());
            };
            let mut w = &tty;
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
            let _ = std::io::BufReader::new(&tty).read_line(&mut line);
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
        } => {
            crate::enrol::validate_name(&name)?;
            if !no_enrol {
                wicket_proxy::ca::permitted_dns_subtrees(&hosts)?;
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
            let (ready, _) = bring_up(placer.provider(), &n.id, &name, &pinned, ssh_key, hosts, ca_ttl).await?;
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
/// now and its ssh target. Errors say the node is still billing.
pub async fn bring_up(
    p: &VultrProvider,
    id: &NodeId,
    name: &str,
    pinned: &str,
    ssh_key: Option<PathBuf>,
    hosts: Option<Vec<String>>,
    ca_ttl: Duration,
) -> Result<(NodeHandle, String)> {
    let ready = match p.wait_active(id, Duration::from_secs(5), Duration::from_secs(600)).await {
        Ok(r) => r,
        Err(e) => return Err(e.context(format!("{id} is still billing: `wicket place release {id}`"))),
    };
    let target = ready.ssh_target.clone().context("no address")?;
    println!("{id} is active at {target}; waiting for node setup (host key pinned: {pinned})");
    boot::wait_ssh_ready(&target, pinned, ssh_key.as_deref(), Duration::from_secs(10), Duration::from_secs(900))
        .await
        .with_context(|| format!("{id} is still billing: `wicket place release {id}`"))?;
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
        })
        .await?;
    }
    // The private host key no longer needs to be in the metadata service.
    if let Err(e) = p.client().set_user_data(&id.0, SCRUBBED_USER_DATA).await {
        eprintln!("warning: could not replace {id}'s user data (it still holds the boot host key): {e:#}");
    }
    Ok((ready, target))
}

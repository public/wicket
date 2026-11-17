//! `wicket node create`, `release` and `plans`: nodes leased from a provider, through the placement
//! interface (`wicket-placement`, #37), and the provider half of `wicket node list`.
//!
//! `create` runs the whole path for one Vultr node: the money envelope and a CAPACITY request
//! ([`CapacityApprover`]: approved by a capacity grant that covers it, else by an operator), a
//! tagged instance whose cloud-init runs `deploy/vultr/node-setup.sh` with an ssh host key generated
//! here and pinned before boot, the wait for it to be active and set up, and `wicket node enrol` with
//! that key (no trust on first use). Then the boot host key is scrubbed from the instance's user data.
//! `release` destroys an owned node and revokes its enrolment. `plans` and the provider half of
//! `list` only read.
//!
//! **Its lease is enforced (#294).** `create` records the node in the ledger
//! ([`wicket_store::PlacedNodeRow`]) with its lease end (minute 50 of the last paid hour of
//! `--lifetime`). At that time the reconciler releases it if no run is placed on it, and audits why;
//! if a run still is, it keeps it, audits that once, and `list` and the console flag it as past its
//! lease (a renewal decision is #56; until then it is a warning). `list` marks every node past its lease.
//!
//! The Vultr API key comes from the vault (`wicket secret set vultr-api-key`) and goes only into the
//! API's Authorization header.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::time::Duration;
use wicket_core::TenantId;
pub use wicket_node::past_lease;
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

/// `wicket node create`'s arguments.
#[derive(clap::Args, Clone)]
pub struct CreateArgs {
    #[command(flatten)]
    common: Common,
    /// Node name (hostname, label and enrolled name).
    #[arg(long)]
    name: String,
    /// Host names the node's CA may issue for, as for `wicket node enrol --hosts`.
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
    /// How long to wait for an operator when none of your capacity grants covers the node (the
    /// request is pending meanwhile, on the console and in `wicket pending`); 0: don't wait.
    #[arg(long, default_value = "15m")]
    wait: String,
}

fn owner_name(c: &Common) -> String {
    c.owner.clone().or_else(|| crate::issuer().ok().map(|i| i.trust_domain)).unwrap_or_else(|| "wicket".into())
}

fn owner(c: &Common) -> Owner {
    Owner::new(&owner_name(c))
}

fn provider(c: &Common, config: VultrConfig) -> Result<VultrProvider> {
    vultr_with_secret(&c.api_key_secret, config)
}

fn vultr_with_secret(secret: &str, config: VultrConfig) -> Result<VultrProvider> {
    let key = Vault::new(Vault::default_dir()).get(secret)?;
    Ok(VultrProvider::new(Client::new(ApiKey::new(key))?, config))
}

/// A placer that can only read and release (it approves no spend), for placed nodes made under
/// `owner` with the API key in `secret`: what the reconciler releases them with.
pub fn release_placer(owner: &str, secret: &str) -> Result<Placer<VultrProvider, envelope::DenyAll>> {
    Ok(Placer::new(
        vultr_with_secret(secret, VultrConfig::default())?,
        envelope::DenyAll,
        Owner::new(owner),
        MoneyEnvelope { max_hourly: MicroUsd::ZERO, max_total: MicroUsd::ZERO },
    ))
}

/// Refuses a new run on a placed node past its lease (#294, #324): one started there would hold
/// the node, so it would go on billing past its lease for as long as new runs came. A run already
/// on it keeps it until it ends; the reconciler releases it then. Returns the lease's end, if the
/// node has one: the run's box start carries it (`BoxStart::start_by`), and the node refuses a start
/// that reaches it later (#395: this check and the start are seconds apart).
pub fn refuse_past_lease(ledger: &Ledger, node: &str, now: i64) -> Result<Option<i64>> {
    let Some(p) = ledger.placed_nodes(&["active"])?.into_iter().find(|p| p.name == node) else { return Ok(None) };
    if p.lease_until <= now {
        bail!("{}", past_lease(node, p.lease_until));
    }
    Ok(Some(p.lease_until))
}

/// After a placed node is released: revokes its enrolment, if it is still enrolled under its name
/// at its address. Returns whether it revoked.
pub fn retire_enrolment(ledger: &mut Ledger, n: &NodeHandle) -> Result<bool> {
    let enrolled = ledger.node(&n.name)?.filter(|r| r.status != "revoked" && n.ssh_target.as_deref() == Some(r.target.as_str()));
    if enrolled.is_none() {
        return Ok(false);
    }
    crate::enrol::revoke(ledger, &crate::enrol::Paths::installation().nodes_dir, &n.name)?;
    Ok(true)
}

fn usd(micros: i64) -> String {
    MicroUsd(micros.max(0) as u64).to_string()
}

/// What `wicket node list` says about the lease, provider and cost of the node named `name`, if it
/// has a lease: one from `wicket node create`, or a run's capacity lease. None for a machine that was
/// only enrolled.
pub fn lease_summary(l: &Ledger, name: &str, now: i64) -> Result<Option<String>> {
    if let Some(p) = l.placed_nodes(&["active"])?.into_iter().find(|p| p.name == name) {
        return Ok(Some(placed_summary(&p, now)));
    }
    let lease = l.leases(wicket_store::LIVE_LEASES)?.into_iter().find(|x| x.node_name.as_deref() == Some(name));
    Ok(lease.map(|x| lease_row_summary(&x)))
}

fn placed_summary(p: &wicket_store::PlacedNodeRow, now: i64) -> String {
    let cost = p.hourly.map(|h| format!("{}/h", usd(h))).unwrap_or_else(|| "cost not recorded".into());
    let end = if p.lease_until <= now {
        match &p.held_by {
            Some(runs) => format!("PAST ITS LEASE (ended {}): held by run {runs}, billing until released", fmt_time(p.lease_until)),
            None => format!("PAST ITS LEASE (ended {}): released at the reconciler's next pass", fmt_time(p.lease_until)),
        }
    } else {
        format!("lease until {}", fmt_time(p.lease_until))
    };
    format!("{end}; provider {} instance {}, {cost}; release with: wicket node release {}", p.backend, p.id, p.name)
}

fn lease_row_summary(x: &wicket_store::LeaseRow) -> String {
    let end = x.not_after.map(|t| format!("until {}", fmt_time(t))).unwrap_or_else(|| x.status.clone());
    let cost =
        if x.reserved == 0 { "no cost".to_string() } else { format!("at most {}/h, {} reserved", usd(x.hourly_cap), usd(x.reserved)) };
    let instance = x.node_id.as_deref().map(|i| format!(" instance {i}")).unwrap_or_default();
    format!("capacity lease {} for run {} {end}; provider {}{instance}, {cost}", x.id, x.run, x.provider)
}

/// Leased nodes that aren't enrolled under their name (made with `--no-enrol`, still being set up,
/// or whose enrolment was revoked), one line each: they bill all the same.
pub fn leased_not_enrolled(l: &Ledger, enrolled: &[String], now: i64) -> Result<Vec<String>> {
    let mut out = vec![];
    for p in l.placed_nodes(&["active"])? {
        if !enrolled.contains(&p.name) {
            out.push(format!("{}  not enrolled  {}", p.name, placed_summary(&p, now)));
        }
    }
    for x in l.leases(wicket_store::LIVE_LEASES)? {
        if !x.node_name.as_ref().is_some_and(|n| enrolled.contains(n)) {
            let name = x.node_name.clone().unwrap_or_else(|| "-".into());
            out.push(format!("{name}  {}  {}", x.status, lease_row_summary(&x)));
        }
    }
    Ok(out)
}

/// What `list` says about a node's lease at `now`: empty while it lasts.
fn lease_note(n: &NodeHandle, placed: Option<&wicket_store::PlacedNodeRow>, capacity: bool, now: i64) -> String {
    let Some(until) = placed.filter(|p| p.status == "active").map(|p| p.lease_until).or(n.lease_until) else { return String::new() };
    if until > now {
        return String::new();
    }
    let ended = format!("PAST ITS LEASE (ended {})", fmt_time(until));
    match placed.filter(|p| p.status == "active") {
        Some(p) => match &p.held_by {
            Some(runs) => format!(
                "{ended}: still held by run {runs}, so the reconciler keeps it and it bills until released (wicket node release {})",
                n.id
            ),
            None => format!("{ended}: the reconciler releases it at its next pass if nothing runs on it"),
        },
        None if capacity => format!("{ended}: its capacity lease ends at the reconciler's next pass"),
        None => format!("{ended}: not recorded by `wicket node create` here, so nothing releases it: wicket node release {}", n.id),
    }
}

fn dollars(s: &str) -> Result<MicroUsd> {
    MicroUsd::parse_dollars(s).with_context(|| format!("{s:?} is not a dollar amount"))
}

fn fmt_time(t: i64) -> String {
    wicket_core::time::format_rfc3339_seconds(std::time::UNIX_EPOCH + Duration::from_secs(t.max(0) as u64)).to_string()
}

/// Decides a node's spend as a CAPACITY request (#256): `CAPACITY wicket.internal
/// /capacity/node/<name>`, filed by the principal running `create`. A live capacity grant of that
/// principal's that covers the node approves it at once, through [`crate::grant::decide`], and the
/// decision is audited against the grant. Otherwise it waits, pending, for an operator (`wicket
/// approve`, or the console, which notifies) for up to `wait`, and is denied when nobody decides.
/// The placer calls it only for a node already inside the money envelope.
pub struct CapacityApprover {
    pub ledger: PathBuf,
    pub tenant: TenantId,
    /// Who asks: the operator's identity.
    pub principal: String,
    pub wait: Duration,
    pub poll: Duration,
    /// The request filed, once it is.
    pub request: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl CapacityApprover {
    pub fn new(ledger: PathBuf, tenant: TenantId, principal: String, wait: Duration) -> CapacityApprover {
        CapacityApprover { ledger, tenant, principal, wait, poll: Duration::from_secs(2), request: Default::default() }
    }

    fn ask(r: &SpendRequest) -> wicket_store::CapacityAsk {
        wicket_store::CapacityAsk {
            node: r.node_name.clone(),
            plan: r.plan.clone(),
            region: r.region.clone().unwrap_or_default(),
            hourly: i64::try_from(r.hourly.0).unwrap_or(i64::MAX),
            worst: i64::try_from(r.worst_case.0).unwrap_or(i64::MAX),
        }
    }

    /// Files the request (or finds the one still pending for this node).
    fn file(&self, l: &Ledger, r: &SpendRequest) -> Result<String> {
        let op = wicket_core::Op::egress(
            &self.tenant,
            &wicket_core::RunId(self.principal.clone()),
            OPERATOR_ZONE,
            crate::capacity::METHOD,
            crate::capacity::HOST,
            &crate::grant::node_request_path(&r.node_name),
        );
        let reason = format!(
            "node {} on {}: plan {} in {}, {}/h for {} (worst case {}), for {}. Already committed: {}/h, {} (envelope {}/h, {} total)",
            r.node_name,
            r.backend,
            r.plan,
            r.region.as_deref().unwrap_or("?"),
            r.hourly,
            wicket_core::time::format_duration(Duration::from_secs(r.lifetime_secs.max(0) as u64)),
            r.worst_case,
            r.purpose,
            r.committed_hourly,
            r.committed_total,
            r.max_hourly,
            r.max_total
        );
        let (id, _) = l.pending_for(&op, &reason, None)?;
        l.audit(
            &self.tenant,
            None,
            "capacity.requested",
            &serde_json::json!({ "request": id, "principal": self.principal, "ask": Self::ask(r), "backend": r.backend,
                                 "lifetime_secs": r.lifetime_secs, "purpose": r.purpose }),
        )?;
        Ok(id)
    }

    async fn decide(&self, r: &SpendRequest) -> Result<Approval> {
        let ask = Self::ask(r);
        let id = {
            let mut l = Ledger::open(&self.ledger)?;
            let id = self.file(&l, r)?;
            *self.request.lock().expect("request") = Some(id.clone());
            match crate::grant::decide_by_capacity_grants(&mut l, &self.tenant, &self.principal, &id, &ask)? {
                Ok((g, _)) => {
                    say!("approved by capacity grant {g} (request {id})");
                    return Ok(Approval::Approved);
                }
                Err(why) => {
                    say!("no capacity grant covers node {}:", r.node_name);
                    for w in why {
                        say!("  {w}");
                    }
                }
            }
            id
        };
        if self.wait.is_zero() {
            Ledger::open(&self.ledger)?.deny(&id, "wicket:no-wait")?;
            return Ok(Approval::Denied(format!("no capacity grant covers it, and --wait 0 (request {id} withdrawn)")));
        }
        say!(
            "waiting up to {} for an operator to decide request {id} (wicket approve {id}, or the console)",
            wicket_core::time::format_duration(self.wait)
        );
        let deadline = tokio::time::Instant::now() + self.wait;
        loop {
            let status = Ledger::open(&self.ledger)?.request(&id)?.status;
            match status.as_str() {
                "granted" => return Ok(Approval::Approved),
                "pending" => {}
                s => return Ok(Approval::Denied(format!("request {id} is {s}"))),
            }
            if tokio::time::Instant::now() >= deadline {
                let l = Ledger::open(&self.ledger)?;
                l.deny(&id, "wicket:timed-out")?;
                l.audit(
                    &self.tenant,
                    None,
                    "decision",
                    &serde_json::json!({ "request": id, "decision": "deny", "by": "wicket:timed-out" }),
                )?;
                return Ok(Approval::Denied(format!(
                    "nobody decided request {id} within {}",
                    wicket_core::time::format_duration(self.wait)
                )));
            }
            tokio::time::sleep(self.poll).await;
        }
    }
}

/// The zone a request an operator files is recorded in (it has no run's).
pub const OPERATOR_ZONE: &str = "operator";

impl SpendApprover for CapacityApprover {
    async fn approve(&self, r: &SpendRequest) -> Approval {
        match self.decide(r).await {
            Ok(a) => a,
            Err(e) => Approval::Denied(format!("the capacity request failed: {e:#}")),
        }
    }
}

/// `wicket node plans`: a region's plans with their hourly price.
pub async fn plans(common: Common, region: String, plan_type: String) -> Result<()> {
    let p = provider(&common, VultrConfig::default())?;
    let mut plans: Vec<_> = p.client().list_plans(&plan_type).await?.into_iter().filter(|p| p.locations.contains(&region)).collect();
    plans.sort_by_key(|p| (p.hourly_rate(), p.id.clone()));
    for p in plans {
        say!("{:<24} {:>2} vCPU {:>6} MB  {}/h  (${}/month)", p.id, p.vcpu_count, p.ram, p.hourly_rate(), p.monthly_cost);
    }
    Ok(())
}

/// The provider half of `wicket node list --provider`: this installation's instances (by owner tag)
/// as the provider sees them, with their cost, lease and next paid hour.
pub async fn list_provider(common: &Common) -> Result<()> {
    let o = owner(common);
    let p = Placer::new(
        provider(common, VultrConfig::default())?,
        envelope::DenyAll,
        o.clone(),
        MoneyEnvelope { max_hourly: MicroUsd::ZERO, max_total: MicroUsd::ZERO },
    );
    let nodes = p.list().await?;
    let ledger = Ledger::open(&crate::ledger_path())?;
    let now = wicket_store::now();
    for n in &nodes {
        let placed = ledger.placed_node(&n.id.0)?;
        let capacity = ledger.leases(wicket_store::LIVE_LEASES)?.iter().any(|l| l.node_id.as_deref() == Some(n.id.0.as_str()));
        say!(
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
        let note = lease_note(n, placed.as_ref(), capacity, now);
        if !note.is_empty() {
            say!("  ! {note}");
        }
    }
    say!("{} node(s) tagged {}", nodes.len(), o.tag());
    Ok(())
}

/// `wicket node create`.
pub async fn create(args: CreateArgs) -> Result<()> {
    let CreateArgs {
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
        wait,
    } = args;
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
    let lifetime = wicket_core::time::parse_duration(&lifetime)?;
    let ca_ttl = wicket_core::time::parse_duration(&ca_ttl)?;
    let owner_name = owner_name(&common);
    let o = Owner::new(&owner_name);
    let config = VultrConfig { os_id, sshkey_ids: ssh_key_ids, default_region: region.clone(), ..VultrConfig::default() };
    let envelope = MoneyEnvelope { max_hourly: dollars(&max_hourly)?, max_total: dollars(&max_total)? };
    let principal = crate::operators::Operator::cli(&TenantId::single().0)?.id;
    let approver = CapacityApprover::new(crate::ledger_path(), TenantId::single(), principal, wicket_core::time::parse_duration(&wait)?);
    let filed = approver.request.clone();
    let placer = Placer::new(provider(&common, config)?, approver, o.clone(), envelope);

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
        // What a retry matches on (hashed into the instance's tag): kept from before the rename, so a
        // create retried across it still finds its node.
        idempotency_key: idempotency_key.unwrap_or_else(|| format!("place-create:{name}")),
        name: name.clone(),
        purpose: format!("wicket node create {name}"),
        boot: Some(Boot { user_data, host_key: pinned.clone() }),
    };
    let acquired = placer.acquire(&req).await;
    let filed = filed.lock().ok().and_then(|r| r.clone());
    if let Some(rid) = filed {
        let l = Ledger::open(&crate::ledger_path())?;
        match &acquired {
            Ok(n) => l.capacity_use_created(&rid, &n.id.0)?,
            Err(e) => l.capacity_use_failed(&rid, &format!("{e}"))?,
        };
    }
    let n = acquired?;
    // Recorded at once, so the reconciler releases it at its lease end whatever happens next.
    let lease_until = n.lease_until.unwrap_or(n.created_at + req.lifetime_secs);
    Ledger::open(&crate::ledger_path())?.record_placed_node(&wicket_store::PlacedNodeRow {
        id: n.id.0.clone(),
        backend: n.backend.clone(),
        name: name.clone(),
        owner: owner_name.clone(),
        api_key_secret: common.api_key_secret.clone(),
        created_at: n.created_at,
        lease_until,
        status: String::new(),
        held_by: None,
        ended_at: None,
        detail: None,
        hourly: Some(n.billing.hourly_rate().0 as i64),
    })?;
    say!("created {} ({}), {}/h, lease until {}", n.id, name, n.billing.hourly_rate(), n.lease_until.map(fmt_time).unwrap_or_default());
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
    let wait = boot::ReadyWait { silent_limit: wicket_core::time::parse_duration(&give_up_silent)?, ..boot::ReadyWait::default() };
    let ready =
        bring_up_or_release::<_, boot::SshProbe>(&placer, &crate::ledger_path(), &n, &name, &pinned, ssh_key, hosts, ca_ttl, &wait, None)
            .await?;
    if let Some(next) = placer.next_paid_hour_at(&ready) {
        say!("next paid hour starts {}; release before then: wicket node release {}", fmt_time(next), n.id);
    }
    say!("the reconciler (wicket reconcile --every) releases it at {} unless a run is still placed on it", fmt_time(lease_until));
    Ok(())
}

/// The provider's instance id for `arg`: the id of the active node `create` recorded under that
/// name, else `arg` itself (an instance id).
fn instance_id(l: &Ledger, arg: &str) -> Result<String> {
    Ok(l.placed_nodes(&["active"])?.into_iter().find(|r| r.name == arg).map(|r| r.id).unwrap_or_else(|| arg.to_string()))
}

/// `wicket node release`: destroys an owned node now (by its instance id, or the name `create` gave
/// it), refusing anything without the owner tag, and revokes its enrolment.
pub async fn release(common: Common, id: String) -> Result<()> {
    let o = owner(&common);
    let p = Placer::new(
        provider(&common, VultrConfig::default())?,
        envelope::DenyAll,
        o,
        MoneyEnvelope { max_hourly: MicroUsd::ZERO, max_total: MicroUsd::ZERO },
    );
    let id = NodeId(instance_id(&Ledger::open(&crate::ledger_path())?, &id)?);
    let node = p.get(&id).await?;
    match p.release(&id, ReleaseMode::Now).await? {
        Released::AlreadyGone => say!("{id} is already gone"),
        r => say!("{id}: {r:?}"),
    }
    let mut ledger = Ledger::open(&crate::ledger_path())?;
    ledger.placed_node_ended(&id.0, "released", "released by wicket node release")?;
    if let Some(n) = node {
        // Files of runs a fetch didn't bring back went with it (#300): a human chose that.
        let lost = ledger.forget_uncollected_on_node(&n.name)?;
        if lost > 0 {
            say!("{} run(s)' uncollected files went with it", lost);
        }
        ledger.audit(
            &TenantId::single(),
            None,
            "placement.node_released",
            &serde_json::json!({ "id": id.0, "name": n.name, "uncollected_runs_lost": lost }),
        )?;
        if retire_enrolment(&mut ledger, &n)? {
            say!("revoked node {}", n.name);
        }
    }
    Ok(())
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
        Err(e) => return Err(e.context(format!("{id} is still billing: `wicket node release {id}`"))),
    };
    let target = ready.ssh_target.clone().context("no address")?;
    say!(
        "{id} is active at {target}; waiting for node setup (host key pinned: {pinned}; giving up after {} without any answer on port {})",
        wicket_core::time::format_duration(wait.silent_limit),
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
        return Err(e.context(format!("{id} is still billing: `wicket node release {id}`")));
    }
    if let Some(hosts) = hosts {
        let ledger = Ledger::open(&crate::ledger_path())?;
        let token = ledger.create_node_token(&TenantId::single(), name, 600)?;
        ledger.audit(
            &TenantId::single(),
            None,
            "node.token",
            &serde_json::json!({ "name": name, "ttl_secs": 600, "by": "node create" }),
        )?;
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
        say_err!("warning: could not replace {id}'s user data (it still holds the boot host key): {e:#}");
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
        say_err!("warning: could not audit giving up on {id}: {e:#}");
    }
    if released.is_ok() {
        if let Err(e) = ledger.placed_node_ended(&id.0, "released", &format!("released by wicket node create: {why}")) {
            say_err!("warning: could not record {id} as released: {e:#}");
        }
    }
    match released {
        Ok(_) => anyhow::anyhow!("{why}: released {id} ({}) rather than leave it billing", node.name),
        Err(e) => anyhow::anyhow!("{why}, and releasing it failed ({e}): {id} is still billing: `wicket node release {id}`"),
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
    /// #324: a placed node past its lease takes no new run; one within it does, and so does a
    /// node `node create` didn't make.
    #[test]
    fn a_placed_node_past_its_lease_takes_no_new_run() {
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        l.record_placed_node(&wicket_store::PlacedNodeRow {
            id: "i-1".into(),
            backend: "vultr".into(),
            name: "build5".into(),
            owner: "example".into(),
            api_key_secret: "vultr".into(),
            created_at: 1_000,
            lease_until: 4_000,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: None,
        })
        .unwrap();
        assert_eq!(super::refuse_past_lease(&l, "build5", 3_999).unwrap(), Some(4_000), "its lease's end, for the box's start");
        let e = super::refuse_past_lease(&l, "build5", 4_000).unwrap_err().to_string();
        assert!(e.contains("past its lease"), "{e}");
        assert_eq!(super::refuse_past_lease(&l, "elsewhere", 9_000).unwrap(), None, "an enrolled node has no lease");
        l.placed_node_ended("i-1", "released", "lease ended").unwrap();
        super::refuse_past_lease(&l, "build5", 9_000).unwrap();
    }

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
            purpose: format!("wicket node create {name}"),
            boot: Some(Boot { user_data: "#cloud-config\n{}\n".into(), host_key: PINNED.into() }),
        }
    }

    fn ledger_path(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-place-{tag}-{}", wicket_core::new_ulid()));
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

    /// #294: `place list` marks a node past its lease, and says what happens to it.
    #[test]
    fn list_marks_a_node_past_its_lease() {
        let mut n = NodeHandle {
            id: NodeId("i-1".into()),
            backend: "vultr".into(),
            name: "n1".into(),
            ssh_target: None,
            region: None,
            plan: None,
            isolation: IsolationTier::Gvisor,
            resources: Resources { vcpus: 1, memory_mib: 1024 },
            billing: BillingModel::vultr(MicroUsd(14_000)),
            created_at: 0,
            lease_until: Some(3000),
            host_key: None,
            tags: vec![],
            state: NodeState::Active,
        };
        let mut row = wicket_store::PlacedNodeRow {
            id: "i-1".into(),
            backend: "vultr".into(),
            name: "n1".into(),
            owner: "example".into(),
            api_key_secret: "vultr-api-key".into(),
            created_at: 0,
            lease_until: 3000,
            status: "active".into(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: None,
        };
        assert_eq!(lease_note(&n, Some(&row), false, 2999), "");
        let idle = lease_note(&n, Some(&row), false, 3000);
        assert!(idle.starts_with("PAST ITS LEASE") && idle.contains("releases it at its next pass"), "{idle}");
        row.held_by = Some("run_a".into());
        let held = lease_note(&n, Some(&row), false, 3000);
        assert!(held.contains("still held by run run_a") && held.contains("wicket node release i-1"), "{held}");
        assert!(lease_note(&n, None, true, 3000).contains("capacity lease"));
        assert!(lease_note(&n, None, false, 3000).contains("nothing releases it"));
        n.lease_until = None;
        assert_eq!(lease_note(&n, None, false, 3000), "");
    }

    /// #358: `node list` shows each node's lease, provider and cost, and the leased nodes not enrolled.
    #[test]
    fn node_list_shows_lease_provider_and_cost() {
        let l = Ledger::open_in_memory().unwrap();
        let placed = |id: &str, name: &str, until: i64| wicket_store::PlacedNodeRow {
            id: id.into(),
            backend: "vultr".into(),
            name: name.into(),
            owner: "example".into(),
            api_key_secret: "vultr-api-key".into(),
            created_at: 0,
            lease_until: until,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: Some(14_000),
        };
        l.record_placed_node(&placed("i-1", "n1", 3000)).unwrap();
        l.record_placed_node(&placed("i-2", "n2", 3000)).unwrap();
        let s = lease_summary(&l, "n1", 100).unwrap().unwrap();
        assert!(s.starts_with("lease until") && s.contains("provider vultr instance i-1") && s.contains("$0.0140/h"), "{s}");
        assert!(s.contains("wicket node release n1"), "{s}");
        assert!(lease_summary(&l, "n1", 3000).unwrap().unwrap().starts_with("PAST ITS LEASE"));
        // An enrolled machine with no lease has nothing to say.
        assert_eq!(lease_summary(&l, "own", 100).unwrap(), None);
        // A run's capacity lease, by its node's enrolled name.
        let mut l = l;
        let row = wicket_store::LeaseRow {
            id: "l-a".into(),
            tenant: TenantId::single().0,
            run: "run_a".into(),
            request_id: None,
            provider: "vultr".into(),
            spec: serde_json::json!({}),
            hourly_cap: 20_000,
            reserved: 20_000,
            duration_secs: 1800,
            created_at: 0,
            not_after: None,
            status: "pending".into(),
            node_id: None,
            node_name: None,
            ssh_target: None,
            host_key: None,
            billed: None,
            ended_at: None,
            detail: None,
        };
        l.create_lease(&row, wicket_store::LeaseBudget { max_hourly: 1_000_000, max_total: 1_000_000 }).unwrap().unwrap();
        // Not enrolled yet: n2 (placed) and the pending lease are listed on their own.
        let un = leased_not_enrolled(&l, &["n1".to_string()], 100).unwrap();
        assert_eq!(un.len(), 2, "{un:?}");
        assert!(un[0].starts_with("n2  not enrolled") && un[0].contains("i-2"), "{un:?}");
        assert!(un[1].contains("capacity lease l-a for run run_a") && un[1].contains("at most $0.0200/h"), "{un:?}");
    }

    // ---- #256: the spend is a CAPACITY request, decided against the caller's capacity grants ----

    const ALEX: &str = "spiffe://wicket.test/t/default/op/unix/alex";

    fn granted_placer(base: &str, path: &std::path::Path, wait: Duration) -> Placer<VultrProvider, CapacityApprover> {
        let client = Client::with_base(base, ApiKey::new(KEY)).unwrap();
        let config = VultrConfig { sshkey_ids: vec!["k1".into()], ..VultrConfig::default() };
        let mut a = CapacityApprover::new(path.to_path_buf(), TenantId::single(), ALEX.into(), wait);
        a.poll = Duration::from_millis(20);
        Placer::new(
            VultrProvider::new(client, config),
            a,
            Owner::new("example"),
            MoneyEnvelope { max_hourly: MicroUsd::parse_dollars("0.05").unwrap(), max_total: MicroUsd::parse_dollars("0.10").unwrap() },
        )
        .with_clock(std::sync::Arc::new(|| CREATED + 60))
    }

    fn issue(path: &std::path::Path, nodes: u32) -> String {
        let mut l = Ledger::open(path).unwrap();
        let op = crate::grant::Granter::Human(crate::operators::Operator {
            id: "spiffe://wicket.test/t/default/op/passkey/laptop".into(),
            label: "passkey:laptop".into(),
            authority: crate::operators::Authority::Anything,
        });
        let terms = wicket_store::CapacityTerms {
            plans: vec!["vc2-1c-2gb".into()],
            regions: vec!["lhr".into()],
            hourly: 30_000,
            daily: 50_000,
            nodes,
        };
        crate::grant::issue_capacity_grant(&mut l, &op, &TenantId::single(), ALEX, &terms, Duration::from_secs(3600), serde_json::json!({}))
            .unwrap()
    }

    fn requests(path: &std::path::Path) -> Vec<wicket_store::Request> {
        let l = Ledger::open(path).unwrap();
        let mut out = l.pending(&TenantId::single()).unwrap();
        out.extend(l.decided(&TenantId::single(), 50).unwrap());
        out
    }

    #[tokio::test]
    async fn a_node_within_the_callers_capacity_grant_is_created_without_asking() {
        let (base, st) = serve().await;
        let path = ledger_path("granted");
        let g = issue(&path, 1);
        let p = granted_placer(&base, &path, Duration::from_millis(200));
        let n = p.acquire(&request("n1")).await.unwrap();
        assert_eq!(st.lock().unwrap().instances.len(), 1);
        let rs = requests(&path);
        assert_eq!(rs.len(), 1);
        assert_eq!(
            (rs[0].method.as_str(), rs[0].path.as_str(), rs[0].run.as_str(), rs[0].status.as_str()),
            ("CAPACITY", "/capacity/node/n1", ALEX, "granted")
        );
        let l = Ledger::open(&path).unwrap();
        let rec: serde_json::Value = serde_json::from_str(&l.audit_of_kind("decision").unwrap().last().unwrap().body).unwrap();
        assert_eq!((rec["capacity_grant"].as_str(), rec["ask"]["plan"].as_str()), (Some(g.as_str()), Some("vc2-1c-2gb")));
        // The use counts while the node is being created; then while it is an active placed node.
        assert_eq!(l.capacity_used(&g).unwrap().nodes, 1);
        assert!(!n.id.0.is_empty());

        // A second node is beyond the grant (one at once): it waits for an operator, and nobody
        // deciding is a denial. Nothing is created.
        let e = p.acquire(&request("n2")).await.unwrap_err();
        assert!(matches!(&e, PlacementError::NotApproved(w) if w.contains("nobody decided")), "{e:?}");
        assert_eq!(st.lock().unwrap().instances.len(), 1);
        let r2 = requests(&path).into_iter().find(|r| r.path == "/capacity/node/n2").unwrap();
        assert_eq!(r2.status, "denied");
    }

    #[tokio::test]
    async fn beyond_every_grant_an_operator_decides_the_pending_request() {
        let (base, st) = serve().await;
        let path = ledger_path("operator");
        let p = granted_placer(&base, &path, Duration::from_secs(10));
        let decider = {
            let path = path.clone();
            tokio::spawn(async move {
                loop {
                    let pending = Ledger::open(&path).unwrap().pending(&TenantId::single()).unwrap();
                    if let Some(r) = pending.into_iter().find(|r| r.method == "CAPACITY") {
                        let mut l = Ledger::open(&path).unwrap();
                        let by = crate::grant::Granter::Human(crate::operators::Operator {
                            id: "spiffe://wicket.test/t/default/op/unix/root".into(),
                            label: "root".into(),
                            authority: crate::operators::Authority::Anything,
                        });
                        let t = crate::grant::Terms { uses: Some(1), ttl: Duration::from_secs(600), prefix: None, zone_wide: false };
                        crate::grant::decide(&mut l, &by, &r.id, &crate::grant::Verdict::Approve(t), serde_json::json!({})).unwrap();
                        return r.reason;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
        };
        p.acquire(&request("n1")).await.unwrap();
        let reason = decider.await.unwrap();
        assert!(reason.contains("plan vc2-1c-2gb in lhr") && reason.contains("worst case"), "{reason}");
        assert_eq!(st.lock().unwrap().instances.len(), 1);
    }
}

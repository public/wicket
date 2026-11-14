//! Capacity leases (#7): an agent asks for a node with `request_capacity`, a human approves, the
//! reconciler (`reconcile.rs`) acquires, enrols and installs the node, and the agent's children run
//! there (`spawn` with `placement: {lease}`) until the lease ends and the node is destroyed.
//!
//! **Configuration** is `<data dir>/placement.yaml` (or `$WICKET_PLACEMENT`). Without it, agents can't
//! ask, and the reconciler only looks after runs and boxes. See `examples/placement/placement.yaml`.
//!
//! **Money.** A lease reserves its worst case *at the agent's own price cap* (`max_hourly_usd` for
//! every started hour of its duration) the moment it is asked for, in the ledger, atomically against
//! `max_hourly_usd`/`max_total_usd` here ([`wicket_store::Ledger::create_lease`]). The node the
//! placer then picks is no dearer than that cap, so the real worst case is never above what was
//! reserved; the placer's own money envelope (the same limits, over the provider's owner-tagged nodes)
//! is checked again before anything is created. Static hosts cost nothing and reserve nothing.
//!
//! **The human.** The ask becomes an ordinary pending request (`CAPACITY wicket.internal
//! /capacity/<lease>`), whose reason states the resources, duration, price cap and worst case: it shows
//! in `wicket pending` and on the console, and `wicket approve`/`deny` decide it (the console too). An
//! approval is bound to that lease: [`LeaseApprover`] lets the placer spend only on the lease being
//! provisioned and only up to its reservation. `wicket approve` provisions at once (one reconcile pass);
//! an approval on the console is picked up by the next pass of `wicket reconcile --every`.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wicket_core::{Op, RunId, TenantId};
use wicket_placement::billing::BillingModel;
use wicket_placement::model::Boot;
use wicket_placement::static_hosts::StaticHost;
use wicket_placement::*;
use wicket_proxy::{CapacityAsk, CapacityCall, CapacityState};
use wicket_store::{LeaseBudget, LeaseRow, Ledger};

/// The method and host of a capacity request's op.
pub const METHOD: &str = "CAPACITY";
pub const HOST: &str = "wicket.internal";
/// Live leases one run may hold or ask for at once.
const MAX_LIVE_PER_RUN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Static,
    Vultr,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VultrSettings {
    #[serde(default = "default_region")]
    pub region: String,
    /// Ids of ssh keys already in the Vultr account.
    pub ssh_key_ids: Vec<String>,
    /// The private half of one of them, on this host (default: ssh's own).
    #[serde(default)]
    pub ssh_key: Option<PathBuf>,
    #[serde(default)]
    pub os_id: Option<u32>,
    #[serde(default)]
    pub plan_type: Option<String>,
    /// The vault secret holding the API key.
    #[serde(default = "default_secret")]
    pub api_key_secret: String,
    /// Give up on a new node, and destroy it, if nothing answers on its ssh port for this long (a
    /// duration, e.g. `4m`, the default). Once the port answers, setup is waited for up to 15 minutes.
    #[serde(default)]
    pub give_up_silent: Option<String>,
    /// Tests only: a local mock of the API. The API key is sent there, so never point it anywhere else.
    #[serde(default)]
    pub api_base: Option<String>,
}

impl VultrSettings {
    /// How long to wait for a new node's setup, and when to give up on one that never answers.
    pub fn ready_wait(&self) -> Result<wicket_placement::boot::ReadyWait> {
        let mut w = wicket_placement::boot::ReadyWait::default();
        if let Some(d) = &self.give_up_silent {
            w.silent_limit = humantime::parse_duration(d).with_context(|| format!("vultr.give_up_silent {d:?}"))?;
        }
        Ok(w)
    }
}

fn default_region() -> String {
    "lhr".into()
}

fn default_secret() -> String {
    "vultr-api-key".into()
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementConfig {
    /// The owner tag's installation name (default: the issuer's trust domain, else "wicket"). Keep it
    /// stable: the reconciler only ever touches instances carrying it.
    #[serde(default)]
    pub owner: Option<String>,
    pub backend: Backend,
    /// For `backend: static`: the operator's own machines, each an enrolled node of the same name.
    #[serde(default)]
    pub static_hosts: Vec<StaticHost>,
    #[serde(default)]
    pub vultr: Option<VultrSettings>,
    /// The most all leases together may cost per hour, and in total (worst case), in dollars.
    pub max_hourly_usd: String,
    pub max_total_usd: String,
    /// Hosts the CA of a node enrolled for a lease may issue for (`wicket node enrol --hosts`).
    #[serde(default)]
    pub node_hosts: Vec<String>,
    /// Keep a node whose lease ended warm until shortly before its next paid hour (a later ask may
    /// claim it in-process); default: destroy at once.
    #[serde(default)]
    pub warm_pool: bool,
    /// Run `wicket node install` on a static host when a lease binds it (default: only Vultr nodes,
    /// which are fresh).
    #[serde(default)]
    pub install_static: bool,
}

impl PlacementConfig {
    pub fn path() -> PathBuf {
        std::env::var_os("WICKET_PLACEMENT").map(PathBuf::from).unwrap_or_else(|| crate::data_dir().join("placement.yaml"))
    }

    /// The configuration, if there is one.
    pub fn load() -> Result<Option<PlacementConfig>> {
        let p = Self::path();
        match std::fs::read_to_string(&p) {
            Ok(s) => Ok(Some(Self::parse(&s).with_context(|| p.display().to_string())?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context(p.display().to_string()),
        }
    }

    pub fn parse(s: &str) -> Result<PlacementConfig> {
        let c: PlacementConfig = serde_yaml::from_str(s)?;
        c.budget()?;
        match c.backend {
            Backend::Static if c.static_hosts.is_empty() => bail!("backend static needs static_hosts"),
            Backend::Vultr if c.vultr.is_none() => bail!("backend vultr needs a vultr section"),
            Backend::Vultr => {
                c.vultr.as_ref().map(VultrSettings::ready_wait).transpose()?;
            }
            _ => {}
        }
        for h in &c.static_hosts {
            crate::enrol::validate_name(&h.name)?;
        }
        Ok(c)
    }

    pub fn budget(&self) -> Result<LeaseBudget> {
        Ok(LeaseBudget { max_hourly: dollars(&self.max_hourly_usd)?.0 as i64, max_total: dollars(&self.max_total_usd)?.0 as i64 })
    }

    pub fn envelope(&self) -> Result<MoneyEnvelope> {
        Ok(MoneyEnvelope { max_hourly: dollars(&self.max_hourly_usd)?, max_total: dollars(&self.max_total_usd)? })
    }

    pub fn owner(&self) -> Owner {
        let name = self.owner.clone().or_else(|| crate::issuer().ok().map(|i| i.trust_domain)).unwrap_or_else(|| "wicket".into());
        Owner::new(&name)
    }

    pub fn provider_id(&self) -> &'static str {
        match self.backend {
            Backend::Static => "static",
            Backend::Vultr => "vultr",
        }
    }
}

fn dollars(s: &str) -> Result<MicroUsd> {
    MicroUsd::parse_dollars(s).with_context(|| format!("{s:?} is not a dollar amount"))
}

fn usd(m: i64) -> String {
    MicroUsd(m.max(0) as u64).to_string()
}

/// The idempotency key of a lease's node: what ties the provider's instance (by its hashed tag) to the
/// ledger's lease after a crash.
pub fn lease_key(lease: &str) -> String {
    format!("capacity:{lease}")
}

/// The name a lease's node is created and enrolled under.
pub fn node_name(lease: &LeaseRow) -> String {
    format!("cap-{}", lease.id.trim_start_matches("l-"))
}

/// The placement request for a lease, rebuilt from its row.
pub fn request_for(lease: &LeaseRow, boot: Option<Boot>) -> Result<CapacityRequest> {
    let s = &lease.spec;
    let iso = s.get("isolation").and_then(|v| v.as_str()).unwrap_or("gvisor");
    Ok(CapacityRequest {
        resources: Resources {
            vcpus: s.get("vcpus").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            memory_mib: s.get("memory_mib").and_then(|v| v.as_u64()).unwrap_or(1024),
        },
        min_isolation: IsolationTier::parse(iso).with_context(|| format!("unknown isolation {iso:?}"))?,
        region_hint: s.get("region").and_then(|v| v.as_str()).map(String::from),
        plan_hint: None,
        max_hourly: s.get("max_hourly_micros").and_then(|v| v.as_u64()).map(MicroUsd),
        lifetime_secs: lease.duration_secs,
        idempotency_key: lease_key(&lease.id),
        name: node_name(lease),
        purpose: format!("lease {} for run {}: {}", lease.id, lease.run, s.get("reason").and_then(|v| v.as_str()).unwrap_or("")),
        boot,
    })
}

/// Lets the placer spend only on the lease being provisioned, and no more than it reserved: the
/// human's approval, bound to that lease. Shared between the placer and the reconciler, which sets it
/// right before each acquire.
#[derive(Clone, Default)]
pub struct LeaseApprover(Arc<Mutex<Option<(String, MicroUsd)>>>);

impl LeaseApprover {
    pub fn allow(&self, node_name: &str, max: MicroUsd) {
        *self.0.lock().expect("approver") = Some((node_name.to_string(), max));
    }
    pub fn clear(&self) {
        *self.0.lock().expect("approver") = None;
    }
}

impl SpendApprover for LeaseApprover {
    async fn approve(&self, r: &SpendRequest) -> Approval {
        match self.0.lock().expect("approver").clone() {
            Some((name, max)) if name == r.node_name && r.worst_case <= max => Approval::Approved,
            Some((name, max)) if name == r.node_name => {
                Approval::Denied(format!("its worst case {} is over the {} a human approved", r.worst_case, max))
            }
            _ => Approval::Denied("no approved lease for this node".into()),
        }
    }
}

/// The `request_capacity` hook for one run.
pub fn hook(tenant: TenantId, run: RunId, zone: String, ledger: Arc<Mutex<Ledger>>, cfg: PlacementConfig) -> wicket_proxy::CapacityHook {
    Arc::new(move |call| match call {
        CapacityCall::Ask(a) => {
            let mut l = ledger.lock().map_err(|_| "ledger lock")?;
            ask(&mut l, &cfg, &tenant, &run, &zone, &a).map_err(|e| format!("{e:#}"))
        }
        CapacityCall::Status(id) => {
            let l = ledger.lock().map_err(|_| "ledger lock")?;
            status(&l, &run, &id).map_err(|e| format!("{e:#}"))
        }
    })
}

/// Files a capacity ask: a pending lease with its money reserved, and the request a human decides.
pub fn ask(l: &mut Ledger, cfg: &PlacementConfig, tenant: &TenantId, run: &RunId, zone: &str, a: &CapacityAsk) -> Result<CapacityState> {
    let iso =
        IsolationTier::parse(&a.isolation).with_context(|| format!("isolation must be process, gvisor or vm, not {:?}", a.isolation))?;
    let max = MicroUsd::parse_dollars(&a.max_hourly_usd).with_context(|| format!("{:?} is not a dollar amount", a.max_hourly_usd))?;
    let live = l.leases(wicket_store::LIVE_LEASES)?.into_iter().filter(|x| x.run == run.0).count();
    if live >= MAX_LIVE_PER_RUN {
        bail!("this run already holds or asked for {live} leases; release one first");
    }
    // What it can cost: nothing on the operator's own machines; otherwise every started hour at the
    // agent's own cap.
    let (hourly, worst) = match cfg.backend {
        Backend::Static => (MicroUsd::ZERO, MicroUsd::ZERO),
        Backend::Vultr => {
            if max == MicroUsd::ZERO {
                bail!("max_hourly_usd must be more than 0 for {} nodes", cfg.provider_id());
            }
            (max, BillingModel::vultr(max).worst_case(a.duration_secs))
        }
    };
    let id = wicket_store::new_lease_id();
    let spec = serde_json::json!({
        "vcpus": a.vcpus, "memory_mib": a.memory_mib, "isolation": iso, "region": a.region,
        "max_hourly_micros": max.0, "reason": a.reason,
    });
    let row = LeaseRow {
        id: id.clone(),
        tenant: tenant.0.clone(),
        run: run.0.clone(),
        request_id: None,
        provider: cfg.provider_id().into(),
        spec,
        hourly_cap: hourly.0 as i64,
        reserved: worst.0 as i64,
        duration_secs: a.duration_secs,
        created_at: 0,
        not_after: None,
        status: String::new(),
        node_id: None,
        node_name: None,
        ssh_target: None,
        host_key: None,
        billed: None,
        ended_at: None,
        detail: None,
    };
    if let Err(r) = l.create_lease(&row, cfg.budget()?)? {
        bail!("over this installation's budget for capacity: {r}");
    }
    let what = format!(
        "{} vCPU, {} MiB, isolation {:?} or stronger{}, for {}, on {}",
        a.vcpus,
        a.memory_mib,
        iso,
        a.region.as_deref().map(|r| format!(", region {r} preferred")).unwrap_or_default(),
        humantime::format_duration(Duration::from_secs(a.duration_secs.max(0) as u64)),
        cfg.provider_id()
    );
    let money = if worst == MicroUsd::ZERO {
        "no cost (the operator's own machines)".to_string()
    } else {
        format!("at most {max}/h, worst case {worst} (reserved now)")
    };
    let op = Op::egress(tenant, run, zone, METHOD, HOST, &format!("/capacity/{id}"));
    let reason = format!("capacity lease {id}: {what}, {money}. Asked by the agent: {}", a.reason);
    let (rid, _) = l.pending_for(&op, &reason, None)?;
    l.set_lease_request(&id, &rid)?;
    l.audit(
        tenant,
        Some(run),
        "lease.requested",
        &serde_json::json!({ "lease": id, "request": rid, "provider": cfg.provider_id(), "spec": row.spec,
                             "hourly_cap_usd_micros": hourly.0, "reserved_usd_micros": worst.0, "duration_secs": a.duration_secs }),
    )?;
    Ok(CapacityState::Waiting(format!(
        "requested: lease {id} ({what}; {money}), waiting for a human (request {rid}). Call request_capacity with lease {id} to wait until its node is ready."
    )))
}

/// Where a lease this run holds is.
pub fn status(l: &Ledger, run: &RunId, id: &str) -> Result<CapacityState> {
    let lease = l.lease(id)?.filter(|x| x.run == run.0).with_context(|| format!("no lease {id} held by this run"))?;
    let rid = lease.request_id.clone().unwrap_or_default();
    Ok(match lease.status.as_str() {
        "pending" => CapacityState::Waiting(format!("lease {id} is waiting for a human (request {rid})")),
        "approved" => CapacityState::Waiting(format!("lease {id} is approved; its node is being set up")),
        "active" => CapacityState::Settled(format!(
            "ready: lease {id} is node {} until {}. Start boxes there with spawn and placement {{\"lease\": \"{id}\"}}. They stop when the lease ends.",
            lease.node_name.as_deref().unwrap_or("?"),
            lease.not_after.map(fmt_time).unwrap_or_else(|| "?".into())
        )),
        s => CapacityState::Settled(format!("lease {id} is {s}: {}", lease.detail.unwrap_or_default())),
    })
}

pub fn fmt_time(t: i64) -> String {
    humantime::format_rfc3339_seconds(std::time::UNIX_EPOCH + Duration::from_secs(t.max(0) as u64)).to_string()
}

/// Whether a request is a capacity ask, and for which lease.
///
/// Found by the request's id, as the lease recorded it, and only a lease of the run that asked: the
/// path is only the op's text, and anyone who could file a request at it would end someone else's
/// lease on a deny (#117).
pub fn lease_of_request(l: &Ledger, r: &wicket_store::Request) -> Result<Option<String>> {
    if r.method != METHOD || r.host != HOST {
        return Ok(None);
    }
    Ok(l.lease_for_request(&r.id)?.filter(|x| x.run == r.run && x.tenant == r.tenant).map(|x| x.id))
}

/// `wicket lease list`.
pub fn list() -> Result<()> {
    let l = Ledger::open(&crate::ledger_path())?;
    let leases = l.leases(&[])?;
    if leases.is_empty() {
        println!("no capacity leases");
    }
    for x in leases {
        println!(
            "{}  {:<9} run {}  {}  {}  reserved {}  until {}  {}{}",
            x.id,
            x.status,
            x.run,
            x.provider,
            x.node_name.as_deref().or(x.node_id.as_deref()).unwrap_or("-"),
            usd(x.reserved),
            x.not_after.map(fmt_time).unwrap_or_else(|| "-".into()),
            x.billed.map(|b| format!("billed {}  ", usd(b))).unwrap_or_default(),
            x.detail.unwrap_or_default()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #117: a deny ends the lease that recorded the request, not whatever lease its path names.
    #[test]
    fn a_capacity_request_is_found_by_its_id() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let row = LeaseRow {
            id: "l-a".into(),
            tenant: t.0.clone(),
            run: "run_a".into(),
            request_id: None,
            provider: "static".into(),
            spec: serde_json::json!({}),
            hourly_cap: 0,
            reserved: 0,
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
        l.create_lease(&row, LeaseBudget { max_hourly: 0, max_total: 0 }).unwrap().unwrap();
        let l = l;
        let ask = |run: &str, zone: &str| {
            let op = Op::egress(&t, &RunId(run.into()), zone, METHOD, HOST, "/capacity/l-a");
            l.pending_for(&op, "capacity", None).unwrap().0
        };
        let mine = ask("run_a", "a");
        l.set_lease_request("l-a", &mine).unwrap();
        assert_eq!(lease_of_request(&l, &l.request(&mine).unwrap()).unwrap().as_deref(), Some("l-a"));
        // The same path, filed by another run: not that lease's request.
        let theirs = ask("run_b", "b");
        assert_ne!(theirs, mine);
        assert_eq!(lease_of_request(&l, &l.request(&theirs).unwrap()).unwrap(), None);
    }
}

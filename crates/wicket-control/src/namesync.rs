//! The names reconciler (#575 step 4b; design in `docs/explanation/box-dns.md`, "Records and
//! reconciliation"): one pass makes the boxes zone's records that wicket owns agree with the
//! ledger's live public names, through the installation's DNS provider. `wicket reconcile` runs it.
//!
//! **What is wanted.** For each live, unlapsed public name a running run holds, on a node that may
//! publish (it has the node labels `names.public.nodes` asks for, and public addresses its operator
//! set): an A record for the node's IPv4 address, an AAAA record for its IPv6 one, and, once the
//! name has a host port on that node (step 4c), an SRV record naming it. The plan adds each name's
//! owner record (`_wicket.<name>` TXT). A name that can't be published yet is *waiting*, with why;
//! it has no records, as any name without a live holder. So is a name whose label the settings as
//! they are now don't allow, or that was approved under another boxes domain than the zone's now.
//!
//! **One pass.**
//! 1. Names whose lifetime is over end (`Ledger::lapse_names`), each audited `name.lapsed`.
//! 2. The wanted records, the zone's records as the provider lists them, and the records the ledger
//!    says this installation created give the plan (`wicket_names::plan`), which never changes a
//!    record wicket doesn't own.
//! 3. A provider that writes: the plan's new records are recorded as this installation's before it
//!    is applied, and the replaced ones forgotten after, so a crash in between leaves only records
//!    the ledger knows of. Each change is audited `name.record`. The `noop` provider writes nothing,
//!    so nothing is recorded as created: the ledger never claims a record that isn't there.
//! 4. The plan, with the conflicts it left alone and the names waiting, is audited `name.plan`
//!    (`applied` says whether the provider made it, `error` why not), when it differs from the
//!    last one recorded, its outcome included:
//!    the `noop` provider plans the same each pass, and a pass every 30 s mustn't fill the record.
//!    Each conflict (a wanted name the zone holds records at that wicket doesn't own) is audited
//!    `name.conflict` with it. A conflict is never adopted.
//!
//! 5. A host port its name let go of (quarantined) is freed once none of that name's records is
//!    left in the ledger's list, in any zone: from twice the longest TTL its records had, counted
//!    from after the apply. A cached record for the old name can't reach the next box given the
//!    port. A pass whose apply failed frees none.
//!
//! A dry run computes the plan and changes nothing: no lapse, no apply, no record, no port freed.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use wicket_core::TenantId;
use wicket_names::{Change, Desired, DnsProvider, OwnerId, Plan, PublicConfig, Record, Zone};
use wicket_store::{Ledger, NameRow};

/// The host port protocol public names are published on (TCP only for now).
const PROTO: &str = "tcp";

/// A live public name that has no records yet, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Waiting {
    pub id: String,
    pub name: String,
    pub why: String,
}

/// What one pass did (or, in a dry run, would do).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The provider's name (`names.public.provider`).
    pub provider: String,
    /// Names whose lifetime ended this pass.
    pub lapsed: Vec<NameRow>,
    pub waiting: Vec<Waiting>,
    pub plan: Plan,
    /// Whether the provider made the plan's changes (false for `noop`, and in a dry run).
    pub applied: bool,
    /// Whether this pass recorded the plan (`name.plan`): it differed from the last one recorded.
    pub recorded: bool,
    /// Released host ports given a time to be free again: `(node, port)`.
    pub freed: Vec<(String, u16)>,
}

/// The records wanted for the live public names, and the names that can't be published yet.
pub fn desired(l: &Ledger, public: &PublicConfig, now: i64) -> Result<(Vec<Desired>, Vec<Waiting>)> {
    let rules = public.rules();
    let mut want = vec![];
    let mut waiting = vec![];
    for n in l.held_public_names()? {
        if !n.live(now) {
            continue;
        }
        let name = public.fqdn(&n.label);
        let mut wait = |why: String| waiting.push(Waiting { id: n.id.clone(), name: name.clone(), why });
        // Checked when asked and when approved; checked again under the settings as they are now
        // (an operator may have reserved it since), and so a bad row can't fail the whole plan.
        if let Err(e) = wicket_names::check_label(&n.label, &rules) {
            wait(format!("its label is not allowed here now: {e}"));
            continue;
        }
        // Published only in the domain it was approved under (#716 review, F3): a change of
        // names.public.zone doesn't move it into one nobody approved.
        if n.domain.as_deref() != Some(public.domain().as_str()) {
            let was = n.domain.as_deref().unwrap_or("no recorded domain");
            wait(format!("it was approved under {was}, not {}: a human approves it again there", public.domain()));
            continue;
        }
        let Some(holder) = n.holder.as_deref() else { continue };
        if l.run_status(holder)?.as_deref() != Some("running") {
            wait(format!("its run {holder} isn't running"));
            continue;
        }
        let Some(node) = l.run_node(holder)? else {
            wait(format!("its run {holder} isn't on a node yet"));
            continue;
        };
        let labels = l.node_labels(&node)?;
        if let Some((k, v)) = public.nodes.iter().find(|(k, v)| labels.get(*k) != Some(*v)) {
            wait(format!("node {node} may not publish: it lacks the label {k}={v} (names.public.nodes)"));
            continue;
        }
        let addrs = l.node_addresses(&node)?;
        if addrs.is_empty() {
            wait(format!("node {node} has no public address (wicket node set {node} --public-ipv4 …)"));
            continue;
        }
        let mut records = vec![];
        records.extend(addrs.ipv4.map(|a| Record::a(&name, a, public.ttl)));
        records.extend(addrs.ipv6.map(|a| Record::aaaa(&name, a, public.ttl)));
        if let (Some(service), Some(port)) = (n.service.as_deref(), l.port_of(&n.id, &node, PROTO)?) {
            records.push(Record::srv(&name, service, port, public.ttl));
        }
        want.push(Desired { name, grant: n.id.clone(), records, ttl: public.ttl });
    }
    Ok((want, waiting))
}

/// The tenant a record of box name `base` is audited under: its name's, found by the wanted names
/// or by the grant its owner record in `owned` names; the installation's if neither says.
fn tenant_of(l: &Ledger, base: &str, wanted: &BTreeMap<String, String>, owned: &[Record]) -> TenantId {
    let grant = wanted
        .get(base)
        .cloned()
        .or_else(|| owned.iter().find(|r| r.is_owner_record() && r.base() == base).and_then(|r| owner_grant(&r.value).map(str::to_string)));
    grant.and_then(|g| l.name(&g).ok()).map(|n| TenantId(n.tenant)).unwrap_or_else(TenantId::single)
}

/// One pass (see the module's documentation) for the zone of `public`, through `provider`.
pub async fn pass<P: DnsProvider>(l: &Ledger, public: &PublicConfig, provider: &P, now: i64, dry_run: bool) -> Result<Report> {
    let owner = OwnerId::parse(&public.owner).ok_or_else(|| anyhow!("names.public.owner {:?} is not an owner id", public.owner))?;
    let zone = Zone::new(&public.domain());
    // Each audited `name.lapsed` by the ledger.
    let lapsed = if dry_run { vec![] } else { l.lapse_names(now)? };
    let (want, waiting) = desired(l, public, now)?;
    let listed = provider.list(&zone).await.with_context(|| format!("listing zone {} with provider {}", zone.apex(), provider.id()))?;
    let owned_records = l.owned_records(&zone)?;
    let owned = wicket_names::Owned::new(&owned_records);
    let plan = wicket_names::plan(&zone, &owner, &want, &listed, &owned).map_err(|e| anyhow!("planning zone {}: {e}", zone.apex()))?;
    let mut report = Report { provider: provider.id().to_string(), lapsed, waiting, plan, applied: false, recorded: false, freed: vec![] };
    if dry_run {
        return Ok(report);
    }

    let writes = provider.writes();
    if !report.plan.is_empty() {
        if writes {
            l.owned_before_apply(&zone, provider.id(), &report.plan)?;
        }
        let applied = match provider.apply(&zone, &report.plan).await {
            Ok(a) => a,
            Err(e) => {
                // Recorded once while it keeps failing the same way (#742 review, F6). No port is
                // freed: the records may still be there.
                record_plan(l, &plan_body(&zone, &report, Some(&e.to_string())))?;
                return Err(anyhow!("applying the plan for zone {} with provider {}: {e}", zone.apex(), provider.id()));
            }
        };
        report.applied = applied.applied && writes;
        if report.applied {
            l.owned_after_apply(&zone, &report.plan)?;
            let wanted: BTreeMap<String, String> = want.iter().map(|d| (d.name.clone(), d.grant.clone())).collect();
            for c in &report.plan.changes {
                let (op, r) = match c {
                    Change::Create(r) => ("create", r),
                    Change::Update { to, .. } => ("update", to),
                    Change::Delete(r) => ("delete", r),
                };
                let tenant = tenant_of(l, r.base(), &wanted, &owned_records);
                let body = serde_json::json!({ "zone": zone.apex(), "provider": provider.id(), "op": op, "change": c });
                l.audit(&tenant, None, "name.record", &body)?;
            }
        }
    } else {
        report.applied = writes;
    }

    if record_plan(l, &plan_body(&zone, &report, None))? {
        let wanted: BTreeMap<String, String> = want.iter().map(|d| (d.name.clone(), d.grant.clone())).collect();
        for c in &report.plan.conflicts {
            let body = serde_json::json!({ "zone": zone.apex(), "name": c.name, "records": c.records, "grant": wanted.get(&c.name) });
            l.audit(&tenant_of(l, &c.name, &wanted, &owned_records), None, "name.conflict", &body)?;
        }
        report.recorded = true;
    }

    // A host port its name let go of is free again twice the TTL after none of the name's records
    // is left in the ledger's list (which a failed apply keeps), in any zone (#742 review, F2: the
    // zone it was approved in may not be the zone now), so a cached record for the old name can't
    // reach the next box given it. Twice the longest TTL its records had, from now, after the
    // apply (F1: a pass can take minutes).
    let left = l.owned_records_everywhere()?;
    let after = std::cmp::max(now, wicket_store::now());
    for (node, proto, port, last) in l.quarantined_ports()? {
        let n = l.name(&last)?;
        let bases: Vec<String> = [n.domain.clone(), Some(public.domain())]
            .into_iter()
            .flatten()
            .map(|d| format!("{}.{d}", n.label))
            .chain(
                left.iter()
                    .filter(|(_, r)| r.is_owner_record() && owner_grant(&r.value) == Some(n.id.as_str()))
                    .map(|(_, r)| r.base().to_string()),
            )
            .collect();
        if left.iter().any(|(_, r)| bases.iter().any(|b| b == r.base())) {
            continue;
        }
        let ttl = report
            .plan
            .changes
            .iter()
            .filter_map(|c| match c {
                Change::Delete(r) | Change::Update { from: r, .. } if bases.iter().any(|b| b == r.base()) => Some(r.ttl),
                _ => None,
            })
            .fold(public.ttl, u32::max);
        l.free_port_after(&node, &proto, port, after + 2 * i64::from(ttl))?;
        report.freed.push((node, port));
    }
    Ok(report)
}

/// The grant an owner record's text names (`…;name=<grant>`).
fn owner_grant(text: &str) -> Option<&str> {
    text.split(';').find_map(|f| f.strip_prefix("name="))
}

/// Audits `name.plan` with `body` unless the last one recorded has its digest. Whether it did.
fn record_plan(l: &Ledger, body: &serde_json::Value) -> Result<bool> {
    let last = l.audit_latest_unscoped("name.plan")?.and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok());
    if last.as_ref().and_then(|b| b.get("digest")) == body.get("digest") {
        return Ok(false);
    }
    l.audit(&TenantId::single(), None, "name.plan", body)?;
    Ok(true)
}

/// `name.plan`'s body. Its digest covers what the plan is and how it ended (the zone, the
/// provider, the changes, the conflicts, the names waiting, whether it was applied and its error),
/// not when it was made, so the same outcome again is told from a new one, and a success after a
/// failure is recorded (#742 review, F6).
fn plan_body(zone: &Zone, r: &Report, error: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "zone": zone.apex(), "provider": r.provider, "changes": r.plan.changes, "conflicts": r.plan.conflicts, "waiting": r.waiting,
        "applied": r.applied, "error": error,
    });
    let digest = hex::encode(Sha256::digest(body.to_string().as_bytes()));
    body["digest"] = serde_json::json!(digest);
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use wicket_core::RunId;
    use wicket_names::{MemoryProvider, NoopProvider, RecordType};
    use wicket_store::{AddressChange, NameAsk, NameScope, NameTerms, StandingBound};

    const P: &str = "spiffe://t.wicket.test/t/t0/z/web/a/demo";
    const V4: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);

    fn public() -> PublicConfig {
        let c: wicket_names::NamesConfig = serde_json::from_value(serde_json::json!({
            "public": { "provider": "noop", "zone": "boxes.example.com", "owner": "a1b2c3d4", "nodes": { "publish": "true" } }
        }))
        .unwrap();
        c.public.unwrap()
    }

    fn enrol(l: &Ledger, node: &str) {
        l.enrol_builtin_node(&wicket_store::NodeRow {
            name: node.into(),
            tenant: "t0".into(),
            target: "unix:/x/ctl.sock".into(),
            host_key: String::new(),
            host_key_fp: String::new(),
            node_key: "00".into(),
            ssh_key: None,
            hosts: vec![],
            enrolled_at: 1,
            status: "active".into(),
            revoked_at: None,
        })
        .unwrap();
        l.set_node_label(node, "publish", Some("true")).unwrap();
        l.set_node_addresses(node, AddressChange::Set(V4), AddressChange::Keep, "op").unwrap();
    }

    fn running_run(l: &Ledger, node: &str) -> RunId {
        let run = RunId("run_demo".into());
        l.run_started(&TenantId::single(), &run, "web", "demo").unwrap();
        l.set_run_node(&run.0, node).unwrap();
        run
    }

    fn approve(l: &Ledger, id: &str, terms: &NameTerms) {
        let effect = wicket_store::name_effect(&l.name(id).unwrap(), terms, "boxes.example.com");
        l.approve_name(id, terms, "op", Some(&effect), &public()).unwrap();
    }

    /// A ledger with node n1 enrolled (labelled to publish, with a public IPv4 address), a running
    /// run on it, and a live public name `demo` that run holds.
    fn ledger() -> (Ledger, RunId, String) {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        enrol(&l, "n1");
        let run = running_run(&l, "n1");
        let ask = NameAsk {
            tenant: &t,
            run: &run,
            zone: "web",
            zone_digest: "zd",
            principal: P,
            label: "demo",
            port: 3000,
            service: Some("http"),
            reason: "the demo",
            scope: NameScope::Run,
        };
        let (id, _) = l.ask_public(&ask).unwrap();
        approve(&l, &id, &NameTerms { bound: StandingBound::Agent, ttl_secs: None });
        (l, run, id)
    }

    fn kinds(l: &Ledger, kind: &str) -> usize {
        l.audit_of_kind(kind).unwrap().len()
    }

    #[test]
    fn a_held_name_on_a_publishing_node_wants_its_addresses() {
        let (l, _run, id) = ledger();
        let (want, waiting) = desired(&l, &public(), wicket_store::now()).unwrap();
        assert!(waiting.is_empty(), "{waiting:?}");
        assert_eq!(want.len(), 1);
        assert_eq!(want[0].name, "demo.boxes.example.com");
        assert_eq!(want[0].grant, id);
        assert_eq!(want[0].records, vec![Record::a("demo.boxes.example.com", V4, 60)]);
        // With an IPv6 address and a host port (step 4c), AAAA and SRV too.
        let v6: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        l.set_node_addresses("n1", AddressChange::Keep, AddressChange::Set(v6), "op").unwrap();
        let port = l.allocate_port("n1", PROTO, &id, 20000..=20999, None).unwrap();
        let (want, _) = desired(&l, &public(), wicket_store::now()).unwrap();
        let types: Vec<RecordType> = want[0].records.iter().map(|r| r.rtype).collect();
        assert_eq!(types, vec![RecordType::A, RecordType::Aaaa, RecordType::Srv]);
        assert_eq!(want[0].records[2], Record::srv("demo.boxes.example.com", "http", port, 60));
    }

    #[test]
    fn a_name_that_cant_be_published_waits_and_says_why() {
        let (l, run, _) = ledger();
        let now = wicket_store::now();
        l.set_node_label("n1", "publish", None).unwrap();
        let (want, waiting) = desired(&l, &public(), now).unwrap();
        assert!(want.is_empty());
        assert!(waiting[0].why.contains("lacks the label publish=true"), "{waiting:?}");
        l.set_node_label("n1", "publish", Some("true")).unwrap();
        l.set_node_addresses("n1", AddressChange::Clear, AddressChange::Keep, "op").unwrap();
        let (_, waiting) = desired(&l, &public(), now).unwrap();
        assert!(waiting[0].why.contains("no public address"), "{waiting:?}");
        l.set_node_addresses("n1", AddressChange::Set(V4), AddressChange::Keep, "op").unwrap();
        let mut p = public();
        p.reserved.push("demo".into());
        let (_, waiting) = desired(&l, &p, now).unwrap();
        assert!(waiting[0].why.contains("not allowed"), "{waiting:?}");
        let mut p = public();
        p.zone = "other.example.com".into();
        let (want, waiting) = desired(&l, &p, now).unwrap();
        assert!(want.is_empty() && waiting[0].why.contains("approved under boxes.example.com"), "{waiting:?}");
        l.run_ended(&run, "succeeded", "").unwrap();
        l.release_run_names(&run).unwrap();
        let (want, waiting) = desired(&l, &public(), now).unwrap();
        assert!(want.is_empty() && waiting.is_empty(), "a name its run let go of has no records: {want:?} {waiting:?}");
    }

    #[tokio::test]
    async fn noop_records_the_plan_once_and_claims_no_record() {
        let (l, _run, _) = ledger();
        let p = NoopProvider::new();
        let r = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(!r.applied && r.recorded);
        // The owner record and the A record.
        assert_eq!(r.plan.changes.len(), 2, "{:?}", r.plan);
        assert_eq!(p.plans(), vec![r.plan.clone()]);
        assert!(l.owned_records(&Zone::new("boxes.example.com")).unwrap().is_empty(), "noop created nothing");
        assert_eq!(kinds(&l, "name.plan"), 1);
        assert_eq!(kinds(&l, "name.record"), 0);
        let plan = l.audit_of_kind("name.plan").unwrap().pop().unwrap();
        let body: serde_json::Value = serde_json::from_str(&plan.body).unwrap();
        assert_eq!(body["applied"], false);
        // The same plan next pass: not recorded again.
        let again = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(!again.recorded);
        assert_eq!(kinds(&l, "name.plan"), 1);
    }

    #[tokio::test]
    async fn a_dry_run_changes_nothing() {
        let (l, _run, _) = ledger();
        let p = NoopProvider::new();
        let r = pass(&l, &public(), &p, wicket_store::now(), true).await.unwrap();
        assert_eq!(r.plan.changes.len(), 2);
        assert!(p.plans().is_empty());
        assert_eq!(kinds(&l, "name.plan"), 0);
    }

    #[tokio::test]
    async fn a_writing_provider_converges_and_removes_on_revoke() {
        let (l, _run, id) = ledger();
        let zone = Zone::new("boxes.example.com");
        let theirs = Record::a("www.boxes.example.com", Ipv4Addr::new(203, 0, 113, 1), 300);
        let p = MemoryProvider::new(zone.clone(), vec![theirs.clone()]);
        let r = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(r.applied && r.recorded);
        assert_eq!(kinds(&l, "name.record"), 2);
        let zr = p.records();
        assert!(zr.contains(&theirs));
        assert!(zr.contains(&Record::a("demo.boxes.example.com", V4, 60)));
        assert!(zr.iter().any(|r| r.is_owner_record() && r.base() == "demo.boxes.example.com"));
        assert_eq!(l.owned_records(&zone).unwrap().len(), 2);
        // In sync: nothing to change.
        let again = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(again.plan.is_empty(), "{:?}", again.plan);
        // Revoked: its records go, the owner record last, and someone else's stays.
        crate::names::revoke(&l, "op", &id).unwrap();
        let gone = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert_eq!(gone.plan.changes.len(), 2);
        assert!(matches!(gone.plan.changes.last(), Some(Change::Delete(r)) if r.is_owner_record()));
        assert_eq!(p.records(), vec![theirs]);
        assert!(l.owned_records(&zone).unwrap().is_empty());
    }

    /// A provider that lists what it is given and fails every apply.
    struct Failing(Vec<Record>);

    impl DnsProvider for Failing {
        fn id(&self) -> &str {
            "failing"
        }
        fn caps(&self) -> wicket_names::Caps {
            wicket_names::Caps { types: vec![RecordType::A, RecordType::Aaaa, RecordType::Srv, RecordType::Txt], min_ttl: 1, atomic: true }
        }
        async fn list(&self, _zone: &Zone) -> Result<Vec<Record>, wicket_names::ProviderError> {
            Ok(self.0.clone())
        }
        async fn apply(&self, _zone: &Zone, _plan: &Plan) -> Result<wicket_names::Applied, wicket_names::ProviderError> {
            Err(wicket_names::ProviderError::Failed("the provider is down".into()))
        }
    }

    /// #742 review: a failed apply frees no port and is recorded once; the success after it is
    /// recorded too, and only then is the port freed.
    #[tokio::test]
    async fn a_failing_provider_keeps_the_port_and_is_recorded_once() {
        let (l, _run, id) = ledger();
        let port = l.allocate_port("n1", PROTO, &id, 20000..=20999, None).unwrap();
        let p = MemoryProvider::new(Zone::new("boxes.example.com"), vec![]);
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        crate::names::revoke(&l, "op", &id).unwrap();
        let plans = kinds(&l, "name.plan");
        let down = Failing(p.records());
        for _ in 0..3 {
            assert!(pass(&l, &public(), &down, wicket_store::now(), false).await.is_err());
        }
        assert_eq!(kinds(&l, "name.plan"), plans + 1, "the same failure recorded once");
        assert_eq!(l.quarantined_ports().unwrap().len(), 1, "no port freed while its records may be there");
        let r = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(r.applied && r.recorded, "the success after a failure is recorded");
        let last: serde_json::Value = serde_json::from_str(&l.audit_of_kind("name.plan").unwrap().pop().unwrap().body).unwrap();
        assert_eq!((last["applied"].as_bool(), last["error"].is_null()), (Some(true), true));
        assert_eq!(r.freed, vec![("n1".to_string(), port)]);
    }

    /// #742 review: what ends a name's publication withdraws its records, whatever its status.
    #[tokio::test]
    async fn records_are_withdrawn_whatever_ends_publication() {
        let other: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
        type Change = Box<dyn Fn(&mut Ledger, &RunId, &mut PublicConfig)>;
        let cases: Vec<(&str, Change)> = vec![
            (
                "run ended",
                Box::new(|l, run, _| {
                    l.run_ended(run, "succeeded", "").unwrap();
                    l.release_run_names(run).unwrap();
                }),
            ),
            (
                "node revoked",
                Box::new(|l, _, _| {
                    l.revoke_node("n1").unwrap();
                }),
            ),
            (
                "address cleared",
                Box::new(|l, _, _| {
                    l.set_node_addresses("n1", AddressChange::Clear, AddressChange::Keep, "op").unwrap();
                }),
            ),
            ("label reserved", Box::new(|_, _, p| p.reserved.push("demo".into()))),
            (
                "address changed",
                Box::new(move |l, _, _| {
                    l.set_node_addresses("n1", AddressChange::Set(other), AddressChange::Keep, "op").unwrap();
                }),
            ),
        ];
        for (case, change) in cases {
            let (mut l, run, _) = ledger();
            let mut cfg = public();
            let p = MemoryProvider::new(Zone::new("boxes.example.com"), vec![]);
            pass(&l, &cfg, &p, wicket_store::now(), false).await.unwrap();
            assert!(p.records().contains(&Record::a("demo.boxes.example.com", V4, 60)), "{case}");
            change(&mut l, &run, &mut cfg);
            pass(&l, &cfg, &p, wicket_store::now(), false).await.unwrap();
            let a: Vec<Record> = p.records().into_iter().filter(|r| r.rtype == RecordType::A).collect();
            match case {
                "address changed" => assert_eq!(a, vec![Record::a("demo.boxes.example.com", other, 60)], "{case}"),
                _ => assert!(p.records().is_empty(), "{case}: {:?}", p.records()),
            }
        }
    }

    /// #742 review, F2: after a zone change, a revoked name's port stays quarantined while its
    /// records in the old zone are still the ledger's.
    #[tokio::test]
    async fn a_port_waits_for_its_records_in_the_zone_it_was_published_in() {
        let (l, _run, id) = ledger();
        l.allocate_port("n1", PROTO, &id, 20000..=20999, None).unwrap();
        let p = MemoryProvider::new(Zone::new("boxes.example.com"), vec![]);
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        crate::names::revoke(&l, "op", &id).unwrap();
        let mut moved = public();
        moved.zone = "other.example.com".into();
        let q = MemoryProvider::new(Zone::new("other.example.com"), vec![]);
        let r = pass(&l, &moved, &q, wicket_store::now(), false).await.unwrap();
        assert!(r.freed.is_empty(), "{:?}", r.freed);
        assert_eq!(l.quarantined_ports().unwrap().len(), 1);
    }

    /// A crash after the plan's records were recorded and before it was applied: the next pass
    /// makes them, and the one after has nothing to do.
    #[tokio::test]
    async fn a_crash_between_recording_and_applying_converges() {
        let (l, _run, _) = ledger();
        let zone = Zone::new("boxes.example.com");
        let p = MemoryProvider::new(zone.clone(), vec![]);
        let dry = pass(&l, &public(), &p, wicket_store::now(), true).await.unwrap();
        l.owned_before_apply(&zone, "memory", &dry.plan).unwrap();
        let r = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(r.applied);
        assert_eq!(p.records().len(), 2);
        assert_eq!(l.owned_records(&zone).unwrap().len(), 2);
        assert!(pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap().plan.is_empty());
    }

    /// Each record's audit is filed under its name's tenant, not the installation's.
    #[tokio::test]
    async fn records_are_audited_under_their_names_tenant() {
        let (l, _run, _) = ledger();
        let t1 = TenantId("t1".into());
        let run = RunId("run_t1".into());
        l.run_started(&t1, &run, "web", "shop").unwrap();
        l.set_run_node(&run.0, "n1").unwrap();
        let principal = "spiffe://t.wicket.test/t/t1/z/web/a/shop";
        let ask = NameAsk {
            tenant: &t1,
            run: &run,
            zone: "web",
            zone_digest: "zd",
            principal,
            label: "shop",
            port: 3000,
            service: None,
            reason: "the shop",
            scope: NameScope::Run,
        };
        let (id, _) = l.ask_public(&ask).unwrap();
        approve(&l, &id, &NameTerms { bound: StandingBound::Agent, ttl_secs: None });
        let p = MemoryProvider::new(Zone::new("boxes.example.com"), vec![]);
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        let recs = l.audit_of_kind("name.record").unwrap();
        let of = |name: &str| recs.iter().filter(|a| a.body.contains(name)).map(|a| a.tenant.clone()).collect::<Vec<_>>();
        assert_eq!(of("shop.boxes.example.com"), vec!["t1".to_string(); 2]);
        assert_eq!(of("demo.boxes.example.com"), vec![TenantId::single().0; 2]);
    }

    #[tokio::test]
    async fn a_name_someone_else_holds_in_the_zone_is_a_conflict_left_alone() {
        let (l, _run, _) = ledger();
        let zone = Zone::new("boxes.example.com");
        let theirs = Record::a("demo.boxes.example.com", Ipv4Addr::new(203, 0, 113, 9), 300);
        let p = MemoryProvider::new(zone, vec![theirs.clone()]);
        let r = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(r.plan.changes.is_empty());
        assert_eq!(r.plan.conflicts.len(), 1);
        assert_eq!(p.records(), vec![theirs]);
        assert_eq!(kinds(&l, "name.conflict"), 1);
        // The same conflict next pass isn't recorded again.
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert_eq!(kinds(&l, "name.conflict"), 1);
    }

    #[tokio::test]
    async fn a_released_port_is_freed_once_its_names_records_are_gone() {
        let (l, _run, id) = ledger();
        let port = l.allocate_port("n1", PROTO, &id, 20000..=20999, None).unwrap();
        let p = MemoryProvider::new(Zone::new("boxes.example.com"), vec![]);
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert_eq!(p.records().len(), 3, "owner, A and SRV");
        // Revoked: its port is released, and quarantined while its records are there.
        crate::names::revoke(&l, "op", &id).unwrap();
        assert_eq!(l.quarantined_ports().unwrap().len(), 1);
        let noop = NoopProvider::new();
        let r = pass(&l, &public(), &noop, wicket_store::now(), false).await.unwrap();
        assert!(r.freed.is_empty(), "the ledger still lists its records: {:?}", r.freed);
        // The records go: the port is freed for twice the TTL from now, not before.
        let now = wicket_store::now();
        let r = pass(&l, &public(), &p, now, false).await.unwrap();
        assert!(p.records().is_empty());
        assert_eq!(r.freed, vec![("n1".to_string(), port)]);
        assert!(l.quarantined_ports().unwrap().is_empty());
        assert_ne!(l.allocate_port("n1", PROTO, "n-other", port..=port + 1, Some(port)).unwrap(), port, "still quarantined");
    }

    #[tokio::test]
    async fn a_lapsed_name_ends_is_audited_and_loses_its_records() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        enrol(&l, "n1");
        let run = running_run(&l, "n1");
        let ask = NameAsk {
            tenant: &t,
            run: &run,
            zone: "web",
            zone_digest: "zd",
            principal: P,
            label: "demo",
            port: 3000,
            service: None,
            reason: "the demo",
            scope: NameScope::Standing,
        };
        let (id, _) = l.ask_public(&ask).unwrap();
        approve(&l, &id, &NameTerms { bound: StandingBound::Agent, ttl_secs: Some(60) });
        let zone = Zone::new("boxes.example.com");
        let p = MemoryProvider::new(zone.clone(), vec![]);
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert_eq!(p.records().len(), 2);
        let r = pass(&l, &public(), &p, wicket_store::now() + 120, false).await.unwrap();
        assert_eq!(r.lapsed.len(), 1);
        assert_eq!(kinds(&l, "name.lapsed"), 1);
        assert!(p.records().is_empty());
    }
}

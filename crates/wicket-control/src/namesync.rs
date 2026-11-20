//! The names reconciler (#575 step 4b; design in `docs/explanation/box-dns.md`, "Records and
//! reconciliation"): one pass makes the records wicket owns agree with the ledger's live public
//! names, through the installation's DNS provider. `wicket reconcile` runs it.
//!
//! **What is wanted.** For each live, unlapsed public name a running run holds, on a node that may
//! publish (it has the node labels `names.public.nodes` asks for, and public addresses its operator
//! set that no other node's name would resolve to): an A record for the node's IPv4 address, an
//! AAAA record for its IPv6 one, and, once the name has a host port on that node (step 4c), an SRV
//! record naming it. The plan adds each name's owner record (`_wicket.<name>` TXT). A name that
//! can't be published yet is *waiting*, with why; it has no records, as any name without a live
//! holder. So is a name whose label the settings as they are now don't allow, or that was approved
//! under another boxes domain than the zone's now.
//!
//! **One pass.**
//! 1. Names whose lifetime is over end (`Ledger::lapse_names`), each audited `name.lapsed`.
//! 2. For the configured zone, and for every other zone the ledger has records of (#748, F3):
//!    - the zone is listed. A provider that writes: records it made that the listing lacks, and
//!      that were written over [`FORGET_AFTER_SECS`] ago, are forgotten (F4), audited
//!      `name.record` (`state: forgotten`), so they hold no port;
//!    - the wanted records (none in a zone that isn't the configured one), the zone's records and
//!      the records the ledger says this installation created give the plan
//!      (`wicket_names::plan`), which never changes a record wicket doesn't own;
//!    - the provider's capabilities are checked (F8): a plan it can't take is refused whole;
//!    - a provider that writes: the plan's new records are recorded as this installation's, and
//!      each change is audited `name.record` (`state: intended`), in one write before it is
//!      applied (F5), so a crash leaves only records the ledger knows of and changes on the record.
//!      The intents are written once per plan, not again while the same plan keeps failing. After
//!      the apply, the replaced records are forgotten and `name.applied` says how it ended; a
//!      provider that stopped part way says how far (`ProviderError::Partial`), and only those
//!      changes count as made. The `noop` provider writes nothing, so nothing is recorded as
//!      created: the ledger never claims a record that isn't there.
//! 3. Records in a zone whose provider isn't the configured one are *stranded*: the configured
//!    provider can't withdraw them, so the pass says so each time (and the plan records it) until
//!    the setting is put back and they are withdrawn. So are records left after a withdrawal
//!    (another owner id, say).
//! 4. One `name.plan` records every zone's plan, the conflicts it left alone, the names waiting,
//!    whether each was applied and its error, when that differs from the last one recorded: the
//!    `noop` provider plans the same each pass, and a pass every 30 s mustn't fill the record. Each
//!    conflict (a wanted name the zone holds records at that wicket doesn't own) is audited
//!    `name.conflict` with it. A conflict is never adopted.
//! 5. A host port its name let go of (quarantined) is freed once none of that name's records is
//!    left in the ledger's list, in any zone: from twice the longest TTL its records had, counted
//!    from after the apply. A cached record for the old name can't reach the next box given the
//!    port.
//!
//! A dry run computes the plans and changes nothing: no lapse, no forgetting, no apply, no record,
//! no port freed.

use anyhow::{anyhow, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use wicket_core::TenantId;
use wicket_names::{Change, Desired, DnsProvider, OwnerId, Plan, ProviderError, PublicConfig, Record, Zone};
use wicket_store::{Ledger, NameRow};

/// The host port protocol public names are published on (TCP only for now).
const PROTO: &str = "tcp";

/// How long after it was written a record the zone's listing lacks is forgotten: a provider's
/// listing may lag its writes.
pub const FORGET_AFTER_SECS: i64 = 10 * 60;

/// A live public name that has no records yet, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Waiting {
    pub id: String,
    pub name: String,
    pub why: String,
}

/// What a pass did in one zone.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ZonePass {
    pub zone: String,
    pub plan: Plan,
    /// Whether the provider made the plan's changes (false for `noop`, and in a dry run).
    pub applied: bool,
    /// Why the plan wasn't (all) made, if it wasn't.
    pub error: Option<String>,
    /// What kind of failure (`list`, `listing`, `caps`, `apply:failed`, `apply:partial`,
    /// `apply:none`): what the recorded plan's digest counts, not the provider's words, which may
    /// change from one try to the next.
    pub error_kind: Option<String>,
    /// Names the provider can't take a record of.
    pub waiting: Vec<Waiting>,
    /// Records forgotten: gone from the zone's listing.
    pub forgotten: Vec<Record>,
}

/// Records of this installation's that this pass can't withdraw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stranded {
    pub zone: String,
    pub provider: String,
    pub records: usize,
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
    /// The configured zone's plan.
    pub plan: Plan,
    /// Whether the provider made the configured zone's plan.
    pub applied: bool,
    /// Every zone's pass, the configured one first.
    pub zones: Vec<ZonePass>,
    pub stranded: Vec<Stranded>,
    /// Whether this pass recorded its plans (`name.plan`): they differed from the last recorded.
    pub recorded: bool,
    /// Released host ports given a time to be free again: `(node, port)`.
    pub freed: Vec<(String, u16)>,
}

impl Report {
    /// The zones whose plan wasn't (all) made, and why.
    pub fn errors(&self) -> impl Iterator<Item = (&str, &str)> {
        self.zones.iter().filter_map(|z| z.error.as_deref().map(|e| (z.zone.as_str(), e)))
    }
}

/// The records wanted for the live public names, and the names that can't be published yet.
pub fn desired(l: &Ledger, public: &PublicConfig, now: i64) -> Result<(Vec<Desired>, Vec<Waiting>)> {
    let rules = public.rules();
    let mut found = vec![];
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
        found.push((n, name, node, addrs));
    }
    // One address, one node (#748, F9): host ports are allocated per node, so two nodes behind
    // one address would both hand out a port. The ledger refuses setting such addresses; if two
    // nodes have one anyway, the names on both wait.
    let mut nodes_at: BTreeMap<IpAddr, BTreeSet<&str>> = BTreeMap::new();
    for (_, _, node, a) in &found {
        for ip in a.ipv4.map(IpAddr::V4).into_iter().chain(a.ipv6.map(IpAddr::V6)) {
            nodes_at.entry(ip).or_default().insert(node.as_str());
        }
    }
    let shared: BTreeMap<&str, (IpAddr, Vec<&str>)> = nodes_at
        .iter()
        .filter(|(_, ns)| ns.len() > 1)
        .flat_map(|(ip, ns)| ns.iter().map(move |n| (*n, (*ip, ns.iter().filter(|o| *o != n).copied().collect()))))
        .collect();
    let mut want = vec![];
    for (n, name, node, addrs) in &found {
        if let Some((ip, others)) = shared.get(node.as_str()) {
            waiting.push(Waiting {
                id: n.id.clone(),
                name: name.clone(),
                why: format!("node {node} shares its public address {ip} with {}: give each node its own", others.join(", ")),
            });
            continue;
        }
        let mut records = vec![];
        records.extend(addrs.ipv4.map(|a| Record::a(name, a, public.ttl)));
        records.extend(addrs.ipv6.map(|a| Record::aaaa(name, a, public.ttl)));
        if let (Some(service), Some(port)) = (n.service.as_deref(), l.port_of(&n.id, node, PROTO)?) {
            records.push(Record::srv(name, service, port, public.ttl));
        }
        want.push(Desired { name: name.clone(), grant: n.id.clone(), records, ttl: public.ttl });
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

/// The digest of what a zone's plan is (not how it ended): its intents are written once per plan.
fn content_digest(zone: &Zone, provider: &str, plan: &Plan) -> String {
    let v = serde_json::json!({ "zone": zone.apex(), "provider": provider, "changes": plan.changes, "conflicts": plan.conflicts });
    hex::encode(Sha256::digest(v.to_string().as_bytes()))
}

/// The last `name.plan` recorded, if any.
fn last_plan(l: &Ledger) -> Result<Option<serde_json::Value>> {
    Ok(l.audit_latest_unscoped("name.plan")?.and_then(|b| serde_json::from_str(&b).ok()))
}

/// One zone's pass (step 2 of the module's documentation).
#[allow(clippy::too_many_arguments)]
async fn zone_pass<P: DnsProvider>(
    l: &Ledger,
    zone: &Zone,
    owner: &OwnerId,
    want: &[Desired],
    provider: &P,
    last: Option<&serde_json::Value>,
    now: i64,
    dry_run: bool,
) -> Result<ZonePass> {
    let mut out = ZonePass { zone: zone.apex().to_string(), ..ZonePass::default() };
    let fail = |out: &mut ZonePass, kind: &str, e: String| {
        out.error_kind = Some(kind.to_string());
        out.error = Some(e);
    };
    let listed = match provider.list(zone).await {
        Ok(r) => r,
        Err(e) => {
            fail(&mut out, "list", format!("listing the zone with provider {}: {e}", provider.id()));
            return Ok(out);
        }
    };
    let wanted: BTreeMap<String, String> = want.iter().map(|d| (d.name.clone(), d.grant.clone())).collect();
    let writes = provider.writes();
    if writes && !dry_run {
        // The forgetting and its audit records are one write (#778 review, S3).
        let before = l.owned_records_by(zone, provider.id())?;
        let forgot = l.immediate(|l| -> Result<wicket_store::ForgotRecords> {
            let f = l.forget_unlisted(zone, provider.id(), &listed, now, FORGET_AFTER_SECS)?;
            for r in &f.forgotten {
                let body = serde_json::json!({ "zone": zone.apex(), "provider": provider.id(), "state": "forgotten", "record": r });
                l.audit(&tenant_of(l, r.base(), &wanted, &before), None, "name.record", &body)?;
            }
            Ok(f)
        })?;
        out.forgotten = forgot.forgotten;
        // A listing without any of the provider's records (R1): a bad listing, a zone emptied by
        // hand, or a crash before they were first made. Nothing is forgotten, and it is said; the
        // plan makes what the listing lacks, as for a record the zone never had.
        if forgot.all_missing > 0 {
            let e = format!(
                "provider {}'s listing has none of the {} record(s) it made here: none is forgotten while that holds",
                provider.id(),
                forgot.all_missing
            );
            fail(&mut out, "listing", e);
        }
    }
    // A name the provider can't take a record of waits on its own (S4), rather than failing the
    // whole plan, so the others' changes (a revoked name's deletes) still go.
    let caps = provider.caps();
    let mut fit = vec![];
    for d in want {
        let records = d.records.iter().cloned().chain([owner.owner_record(&d.name, &d.grant, d.ttl)]);
        let one = Plan { changes: records.map(Change::Create).collect(), conflicts: vec![] };
        match caps.check(&one) {
            Ok(()) => fit.push(d.clone()),
            Err(e) => out.waiting.push(Waiting {
                id: d.grant.clone(),
                name: d.name.clone(),
                why: format!("provider {} can't take its records: {e}", provider.id()),
            }),
        }
    }
    let owned_records = l.owned_records_by(zone, provider.id())?;
    let owned = wicket_names::Owned::new(&owned_records);
    out.plan = wicket_names::plan(zone, owner, &fit, &listed, &owned).map_err(|e| anyhow!("planning zone {}: {e}", zone.apex()))?;
    if dry_run {
        return Ok(out);
    }
    if out.plan.is_empty() {
        out.applied = writes;
        return Ok(out);
    }
    if let Err(e) = caps.check(&out.plan) {
        fail(&mut out, "caps", format!("provider {} can't take the plan: {e}", provider.id()));
        return Ok(out);
    }
    let content = content_digest(zone, provider.id(), &out.plan);
    if writes {
        // The intents, with the records they create, in one write before the apply (F5); once per
        // plan: not again while the same plan keeps failing, and again once one was applied (S1).
        let seen = last.and_then(|b| b.get("zones")).and_then(|z| z.as_array()).is_some_and(|zs| {
            zs.iter().any(|z| {
                z.get("content").and_then(|c| c.as_str()) == Some(content.as_str())
                    && z.get("applied").and_then(|a| a.as_bool()) == Some(false)
            })
        });
        let recorded = l.immediate(|l| -> Result<()> {
            l.owned_before_apply(zone, provider.id(), &out.plan)?;
            if !seen {
                for c in &out.plan.changes {
                    let r = match c {
                        Change::Create(r) | Change::Update { to: r, .. } | Change::Delete(r) => r,
                    };
                    let body = serde_json::json!({ "zone": zone.apex(), "provider": provider.id(), "state": "intended", "plan": content, "change": c });
                    l.audit(&tenant_of(l, r.base(), &wanted, &owned_records), None, "name.record", &body)?;
                }
            }
            Ok(())
        });
        // Refused (another provider's record, R2): nothing is applied in this zone.
        if let Err(e) = recorded {
            fail(&mut out, "ledger", format!("recording the plan before applying it: {e:#}"));
            return Ok(out);
        }
    }
    let (made, error) = match provider.apply(zone, &out.plan).await {
        Ok(a) if a.applied => (out.plan.changes.len(), None),
        Ok(_) => (0, writes.then(|| ("apply:none", "the provider says it applied nothing".to_string()))),
        Err(ProviderError::Partial { done, why }) => {
            (done.min(out.plan.changes.len()), Some(("apply:partial", format!("stopped after {done} change(s): {why}"))))
        }
        Err(e) => (0, Some(("apply:failed", e.to_string()))),
    };
    if writes {
        // What was made, forgotten as replaced, with how the apply ended, in one write (S2, S3):
        // on a failure too.
        let body = serde_json::json!({
            "zone": zone.apex(), "provider": provider.id(), "plan": content,
            "changes": out.plan.changes.len(), "made": made, "error": error.as_ref().map(|(_, e)| e),
        });
        l.immediate(|l| -> Result<()> {
            l.owned_after_apply(zone, provider.id(), &out.plan.prefix(made))?;
            l.audit(&TenantId::single(), None, "name.applied", &body)?;
            Ok(())
        })?;
    }
    out.applied = writes && made == out.plan.changes.len() && error.is_none();
    if let Some((kind, e)) = error {
        fail(&mut out, kind, format!("applying the plan with provider {}: {e}", provider.id()));
    }
    Ok(out)
}

/// One pass (see the module's documentation) for the zone of `public`, through `provider`, and for
/// the other zones the ledger has records of.
pub async fn pass<P: DnsProvider>(l: &Ledger, public: &PublicConfig, provider: &P, now: i64, dry_run: bool) -> Result<Report> {
    let owner = OwnerId::parse(&public.owner).ok_or_else(|| anyhow!("names.public.owner {:?} is not an owner id", public.owner))?;
    let zone = Zone::new(&public.domain());
    // Each audited `name.lapsed` by the ledger.
    let lapsed = if dry_run { vec![] } else { l.lapse_names(now)? };
    let (want, waiting) = desired(l, public, now)?;
    let last = last_plan(l)?;
    let mut zones = vec![zone_pass(l, &zone, &owner, &want, provider, last.as_ref(), now, dry_run).await?];
    // The other zones with records of this installation's (F3): withdrawn if the configured
    // provider made them, otherwise stranded.
    let mut stranded = vec![];
    for (z, made_by, _) in l.owned_zones()?.into_iter().filter(|(z, _, _)| *z != zone.apex()) {
        if made_by != provider.id() {
            continue;
        }
        zones.push(zone_pass(l, &Zone::new(&z), &owner, &[], provider, last.as_ref(), now, dry_run).await?);
    }
    for (z, made_by, n) in l.owned_zones()?.into_iter().filter(|(z, p, _)| *z != zone.apex() || *p != provider.id()) {
        let why = match (made_by == provider.id(), dry_run) {
            (false, _) => format!("made by provider {made_by}, not the configured {}: put it back to withdraw them", provider.id()),
            (true, true) => continue,
            (true, false) => match zones.iter().find(|p| p.zone == z).and_then(|p| p.error.clone()) {
                Some(e) => format!("withdrawing them failed: {e}"),
                None => {
                    "left after withdrawing them: none of them is this installation's by its owner record (was names.public.owner changed?)"
                        .into()
                }
            },
        };
        stranded.push(Stranded { zone: z, provider: made_by, records: n, why });
    }
    let mut waiting = waiting;
    for z in &zones {
        waiting.extend(z.waiting.iter().cloned());
    }
    let main = &zones[0];
    let mut report = Report {
        provider: provider.id().to_string(),
        lapsed,
        waiting,
        plan: main.plan.clone(),
        applied: main.applied,
        zones: zones.clone(),
        stranded,
        recorded: false,
        freed: vec![],
    };
    if dry_run {
        return Ok(report);
    }

    let body = plan_body(&report);
    if last.as_ref().and_then(|b| b.get("digest")) != body.get("digest") {
        l.audit(&TenantId::single(), None, "name.plan", &body)?;
        let wanted: BTreeMap<String, String> = want.iter().map(|d| (d.name.clone(), d.grant.clone())).collect();
        for zp in &report.zones {
            let owned = l.owned_records_by(&Zone::new(&zp.zone), provider.id())?;
            for c in &zp.plan.conflicts {
                let body = serde_json::json!({ "zone": zp.zone, "name": c.name, "records": c.records, "grant": wanted.get(&c.name) });
                l.audit(&tenant_of(l, &c.name, &wanted, &owned), None, "name.conflict", &body)?;
            }
        }
        report.recorded = true;
    }

    // A host port its name let go of is free again twice the TTL after none of the name's records
    // is left in the ledger's list (which a failed apply keeps), in any zone (#742 review, F2: the
    // zone it was approved in may not be the zone now), so a cached record for the old name can't
    // reach the next box given it. Twice the longest TTL its records had in any zone's plan, from
    // now, after the apply (F1: a pass can take minutes).
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
            .zones
            .iter()
            .flat_map(|z| {
                let gone = z.plan.changes.iter().filter_map(|c| match c {
                    Change::Delete(r) | Change::Update { from: r, .. } => Some(r),
                    Change::Create(_) => None,
                });
                gone.chain(z.forgotten.iter())
            })
            .filter(|r| bases.iter().any(|b| b == r.base()))
            .map(|r| r.ttl)
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

/// `name.plan`'s body: every zone's plan with how it ended, the stranded records and the names
/// waiting. Its digest covers all of it but not when it was made, so the same outcome again is
/// told from a new one, and a success after a failure is recorded (#742 review, F6). Each zone
/// carries its plan's content digest, by which its intents are written once.
fn plan_body(r: &Report) -> serde_json::Value {
    let zone = |z: &ZonePass, texts: bool| {
        serde_json::json!({
            "zone": z.zone, "changes": z.plan.changes, "conflicts": z.plan.conflicts, "applied": z.applied,
            "error": if texts { serde_json::json!(z.error) } else { serde_json::json!(z.error_kind) },
            "forgotten": z.forgotten, "content": content_digest(&Zone::new(&z.zone), &r.provider, &z.plan),
        })
    };
    let body = |texts: bool| {
        serde_json::json!({
            "zone": r.zones.first().map(|z| z.zone.clone()), "provider": r.provider,
            "zones": r.zones.iter().map(|z| zone(z, texts)).collect::<Vec<_>>(), "stranded": r.stranded, "waiting": r.waiting,
            "applied": r.applied,
            "error": r.zones.first().and_then(|z| if texts { z.error.clone() } else { z.error_kind.clone() }),
        })
    };
    // The digest counts each failure's kind, not the provider's words (S4).
    let digest = hex::encode(Sha256::digest(body(false).to_string().as_bytes()));
    let mut out = body(true);
    out["digest"] = serde_json::json!(digest);
    out
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
        enrol_bare(l, node);
        l.set_node_addresses(node, AddressChange::Set(V4), AddressChange::Keep, "op").unwrap();
    }

    /// Enrolled and labelled to publish, with no address.
    fn enrol_bare(l: &Ledger, node: &str) {
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

    /// A second live public name, `label`, held by another running run on n1.
    fn second_name(l: &Ledger, label: &str) -> String {
        let t = TenantId::single();
        let run = RunId(format!("run_{label}"));
        l.run_started(&t, &run, "web", label).unwrap();
        l.set_run_node(&run.0, "n1").unwrap();
        let principal = format!("spiffe://t.wicket.test/t/t0/z/web/a/{label}");
        let ask = NameAsk {
            tenant: &t,
            run: &run,
            zone: "web",
            zone_digest: "zd",
            principal: &principal,
            label,
            port: 3000,
            service: None,
            reason: "another",
            scope: NameScope::Run,
        };
        let (id, _) = l.ask_public(&ask).unwrap();
        approve(l, &id, &NameTerms { bound: StandingBound::Agent, ttl_secs: None });
        id
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
        /// The memory provider's account, down: its records are this one's.
        fn id(&self) -> &str {
            "memory"
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
        let (plans, records) = (kinds(&l, "name.plan"), kinds(&l, "name.record"));
        let down = Failing(p.records());
        for _ in 0..3 {
            let r = pass(&l, &public(), &down, wicket_store::now(), false).await.unwrap();
            assert!(r.errors().next().is_some_and(|(_, e)| e.contains("down")), "{:?}", r.zones);
        }
        assert_eq!(kinds(&l, "name.plan"), plans + 1, "the same failure recorded once");
        assert_eq!(kinds(&l, "name.record"), records + 3, "its three intents (owner, A, SRV) written once, not on every pass (#748, F5)");
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

    /// A provider serving several zones, whose apply isn't atomic: it can be made to stop after a
    /// number of changes, and to take only some record types.
    struct Multi {
        id: &'static str,
        zones: std::sync::Mutex<BTreeMap<String, Vec<Record>>>,
        stop_after: std::sync::Mutex<Option<usize>>,
        types: Vec<RecordType>,
    }

    impl Default for Multi {
        fn default() -> Self {
            Multi { id: "multi", zones: Default::default(), stop_after: Default::default(), types: vec![] }
        }
    }

    impl Multi {
        fn records(&self, zone: &str) -> Vec<Record> {
            self.zones.lock().unwrap().get(zone).cloned().unwrap_or_default()
        }
    }

    impl DnsProvider for Multi {
        fn id(&self) -> &str {
            self.id
        }
        fn caps(&self) -> wicket_names::Caps {
            let types = match self.types.is_empty() {
                true => vec![RecordType::A, RecordType::Aaaa, RecordType::Srv, RecordType::Txt],
                false => self.types.clone(),
            };
            wicket_names::Caps { types, min_ttl: 1, atomic: false }
        }
        async fn list(&self, zone: &Zone) -> Result<Vec<Record>, ProviderError> {
            Ok(self.records(zone.apex()))
        }
        async fn apply(&self, zone: &Zone, plan: &Plan) -> Result<wicket_names::Applied, ProviderError> {
            let mut zs = self.zones.lock().unwrap();
            let recs = zs.entry(zone.apex().to_string()).or_default();
            match self.stop_after.lock().unwrap().take() {
                Some(k) => {
                    plan.prefix(k).apply_to(recs).map_err(ProviderError::Failed)?;
                    Err(ProviderError::Partial { done: k, why: "rate limited".into() })
                }
                None => {
                    plan.apply_to(recs).map_err(ProviderError::Failed)?;
                    Ok(wicket_names::Applied { applied: true, changes: plan.changes.len() })
                }
            }
        }
    }

    const BOXES: &str = "boxes.example.com";

    /// #748, F3: a zone change withdraws the records in the old zone, with the provider that made
    /// them; the name waits in the new one (approved under the old).
    #[tokio::test]
    async fn a_zone_change_withdraws_the_old_zones_records() {
        let (l, _run, _) = ledger();
        let p = Multi::default();
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert_eq!(p.records(BOXES).len(), 2);
        let mut moved = public();
        moved.zone = "other.example.com".into();
        let r = pass(&l, &moved, &p, wicket_store::now(), false).await.unwrap();
        assert!(p.records(BOXES).is_empty(), "{:?}", p.records(BOXES));
        assert!(r.stranded.is_empty() && r.errors().next().is_none(), "{:?} {:?}", r.stranded, r.zones);
        assert!(l.owned_zones().unwrap().is_empty());
        assert!(r.waiting[0].why.contains("approved under boxes.example.com"), "{:?}", r.waiting);
    }

    /// #748, F3: records another provider made are stranded, said each pass and recorded once,
    /// and kept; a provider that only reports forgets none of them (F4).
    #[tokio::test]
    async fn another_providers_records_are_stranded_not_forgotten() {
        let (l, _run, _) = ledger();
        let p = Multi::default();
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        let noop = NoopProvider::new();
        let later = wicket_store::now() + FORGET_AFTER_SECS + 60;
        let r = pass(&l, &public(), &noop, later, false).await.unwrap();
        assert_eq!(r.stranded.len(), 1, "{:?}", r.stranded);
        assert!(r.stranded[0].provider == "multi" && r.stranded[0].records == 2 && r.stranded[0].why.contains("put it back"));
        assert!(r.recorded);
        assert_eq!(l.owned_records(&Zone::new(BOXES)).unwrap().len(), 2, "nothing forgotten");
        let again = pass(&l, &public(), &noop, later, false).await.unwrap();
        assert_eq!(again.stranded.len(), 1);
        assert!(!again.recorded, "the same stranding recorded once");
    }

    /// #748, F4: a record gone from the zone's listing is forgotten once it is older than the
    /// guard, audited, and made again; a forgotten one of a revoked name frees its port.
    #[tokio::test]
    async fn records_missing_from_the_zone_are_forgotten_after_the_guard() {
        let (l, _run, id) = ledger();
        let port = l.allocate_port("n1", PROTO, &id, 20000..=20999, None).unwrap();
        second_name(&l, "shop");
        let p = Multi::default();
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert_eq!(p.records(BOXES).len(), 5);
        // demo's records deleted by hand; shop's still there. The first listing without them notes
        // it, and forgets nothing (#778 review, R1: one listing is not enough).
        p.zones.lock().unwrap().get_mut(BOXES).unwrap().retain(|r| r.base() != "demo.boxes.example.com");
        crate::names::revoke(&l, "op", &id).unwrap();
        let t0 = wicket_store::now();
        let r = pass(&l, &public(), &p, t0, false).await.unwrap();
        assert!(r.zones[0].forgotten.is_empty());
        assert!(r.freed.is_empty(), "the ledger still lists its records");
        // Still within the guard: nothing yet.
        let r = pass(&l, &public(), &p, t0 + FORGET_AFTER_SECS - 60, false).await.unwrap();
        assert!(r.zones[0].forgotten.is_empty());
        // Missing across listings spanning the guard: forgotten, audited, its port freed.
        let r = pass(&l, &public(), &p, t0 + FORGET_AFTER_SECS + 60, false).await.unwrap();
        assert_eq!(r.zones[0].forgotten.len(), 3, "owner, A and SRV");
        assert_eq!(l.audit_of_kind("name.record").unwrap().iter().filter(|a| a.body.contains("\"forgotten\"")).count(), 3);
        assert_eq!(l.owned_records(&Zone::new(BOXES)).unwrap().len(), 2, "shop's stay");
        assert_eq!(r.freed, vec![("n1".to_string(), port)]);
    }

    /// #778 review, R1: a record seen again before the guard ran out isn't forgotten later.
    #[tokio::test]
    async fn a_record_seen_again_is_not_forgotten() {
        let (l, _run, _) = ledger();
        second_name(&l, "shop");
        let p = Multi::default();
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        let demo: Vec<Record> = p.records(BOXES).into_iter().filter(|r| r.base() == "demo.boxes.example.com").collect();
        p.zones.lock().unwrap().get_mut(BOXES).unwrap().retain(|r| r.base() != "demo.boxes.example.com");
        let t0 = wicket_store::now();
        // Missing once (an eventually consistent read, or deleted by hand and put back).
        let r = pass(&l, &public(), &p, t0, false).await.unwrap();
        assert!(r.zones[0].forgotten.is_empty());
        // The pass made them again (the zone lacked them); a later pass past the guard forgets none.
        assert!(demo.iter().all(|d| p.records(BOXES).contains(d)), "{:?}", p.records(BOXES));
        let r = pass(&l, &public(), &p, t0 + FORGET_AFTER_SECS + 60, false).await.unwrap();
        assert!(r.zones[0].forgotten.is_empty(), "{:?}", r.zones[0].forgotten);
    }

    /// #778 review, R1: a listing with none of the provider's records forgets none, and says so.
    #[tokio::test]
    async fn a_listing_without_any_of_ours_forgets_nothing() {
        let (l, _run, _) = ledger();
        let p = Multi::default();
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        p.zones.lock().unwrap().clear();
        let r = pass(&l, &public(), &p, wicket_store::now() + FORGET_AFTER_SECS + 60, false).await.unwrap();
        assert!(r.zones[0].forgotten.is_empty());
        assert!(r.errors().any(|(_, e)| e.contains("has none of the 2 record(s)")), "{:?}", r.zones);
        assert_eq!(l.owned_records(&Zone::new(BOXES)).unwrap().len(), 2, "none forgotten");
    }

    /// #778 review, R2: a writing provider never takes over another's rows, and its plan, its
    /// forgetting and what it replaces count only its own.
    #[tokio::test]
    async fn two_writing_providers_keep_their_own_records() {
        let (l, _run, _) = ledger();
        let a = Multi::default();
        pass(&l, &public(), &a, wicket_store::now(), false).await.unwrap();
        let b = Multi { id: "multi-b", ..Multi::default() };
        let r = pass(&l, &public(), &b, wicket_store::now() + FORGET_AFTER_SECS + 60, false).await.unwrap();
        assert!(r.errors().any(|(_, e)| e.contains("another provider's record")), "{:?}", r.zones);
        let zone = Zone::new(BOXES);
        assert_eq!(l.owned_records_by(&zone, "multi").unwrap().len(), 2, "a's rows are a's");
        assert!(l.owned_records_by(&zone, "multi-b").unwrap().is_empty());
        assert!(r.stranded.iter().any(|s| s.provider == "multi" && s.records == 2), "{:?}", r.stranded);
    }

    /// #748, F8 and #778 review, S4: a name the provider can't take a record of waits on its own,
    /// recording nothing as created.
    #[tokio::test]
    async fn a_name_the_provider_cant_take_waits() {
        let (l, _run, _) = ledger();
        let p = Multi { types: vec![RecordType::A], ..Multi::default() };
        let r = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(r.waiting.iter().any(|w| w.why.contains("can't take its records")), "{:?}", r.waiting);
        assert!(r.plan.is_empty());
        assert!(p.records(BOXES).is_empty());
        assert!(l.owned_records(&Zone::new(BOXES)).unwrap().is_empty());
        assert_eq!(kinds(&l, "name.record"), 0);
    }

    /// #748, F8: a provider that stopped part way: only the changes it made count; the next pass
    /// finishes.
    #[tokio::test]
    async fn a_partial_apply_counts_only_what_was_made() {
        let (l, _run, id) = ledger();
        let p = Multi::default();
        pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        crate::names::revoke(&l, "op", &id).unwrap();
        *p.stop_after.lock().unwrap() = Some(1);
        let r = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(r.errors().next().is_some_and(|(_, e)| e.contains("stopped after 1")), "{:?}", r.zones);
        // The A record went first; the owner record is still there, and still the ledger's.
        let left = l.owned_records(&Zone::new(BOXES)).unwrap();
        assert!(left.len() == 1 && left[0].is_owner_record(), "{left:?}");
        assert_eq!(p.records(BOXES), left);
        let applied: serde_json::Value = serde_json::from_str(&l.audit_of_kind("name.applied").unwrap().pop().unwrap().body).unwrap();
        assert_eq!((applied["made"].as_u64(), applied["changes"].as_u64()), (Some(1), Some(2)));
        let r = pass(&l, &public(), &p, wicket_store::now(), false).await.unwrap();
        assert!(r.applied && r.errors().next().is_none());
        assert!(p.records(BOXES).is_empty() && l.owned_records(&Zone::new(BOXES)).unwrap().is_empty());
    }

    /// #748, F9: two nodes the ledger gives one address (by hand, or an older build): the names on
    /// both wait.
    #[test]
    fn names_on_nodes_sharing_an_address_wait() {
        let (l, _run, _) = ledger();
        enrol_bare(&l, "n2");
        l.force_node_addresses_for_tests("n2", Some(V4), None).unwrap();
        let t = TenantId::single();
        let run = RunId("run_shop".into());
        l.run_started(&t, &run, "web", "shop").unwrap();
        l.set_run_node(&run.0, "n2").unwrap();
        let ask = NameAsk {
            tenant: &t,
            run: &run,
            zone: "web",
            zone_digest: "zd",
            principal: "spiffe://t.wicket.test/t/t0/z/web/a/shop",
            label: "shop",
            port: 3000,
            service: None,
            reason: "the shop",
            scope: NameScope::Run,
        };
        let (id, _) = l.ask_public(&ask).unwrap();
        approve(&l, &id, &NameTerms { bound: StandingBound::Agent, ttl_secs: None });
        let (want, waiting) = desired(&l, &public(), wicket_store::now()).unwrap();
        assert!(want.is_empty(), "{want:?}");
        assert_eq!(waiting.len(), 2);
        assert!(waiting.iter().all(|w| w.why.contains("shares its public address")), "{waiting:?}");
    }
}

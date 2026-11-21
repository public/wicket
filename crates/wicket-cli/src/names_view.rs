//! The Names card's JSON (#575 step 4d; design in `docs/explanation/box-dns.md`, "Audit and
//! console"): what `/api/names`, `/api/names/<id>`, the dashboard's `names`, `wicket names list
//! --json` and `wicket names show --json` print, one shape for all of them.
//!
//! - Each name: its kind, the ledger's `status`, and wicket's `state` with `why` (pending, live,
//!   waiting, taken in the zone, records out of sync, lapsed, or how it ended); its full name; its
//!   owner (principal, zone, the run that asked and the run that holds it); its target (node, the
//!   node's public addresses, the host port, the box's own port); its scope, binding and lifetime;
//!   and who decided it.
//! - What the agent wrote (its label, service and reason) is under `agent`, apart from wicket's own
//!   words, and as the agent wrote it: a page or terminal showing it cleans it, as the text output
//!   does. wicket's sentences (`why`) never quote it.
//! - The state is what the reconciler would do now ([`namesync::desired_with`]) and what its last
//!   recorded plan (`name.plan`) left: a name it can't publish yet is `waiting` with why; one whose
//!   name the zone holds records at that wicket doesn't own is `taken`; one whose records the
//!   ledger doesn't list as made (or lists more of) is `out_of_sync`. The `noop` provider never
//!   publishes, so its names are `live` once wanted, with why.
//! - One name's view adds its records as the ledger lists them (zone and provider), the last plan's
//!   entries for it, and its last connections (the node's `name.conn` and `name.conn.refused`
//!   records, newest first, from a bounded read of the log's tail: there is no index by name).

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wicket_control::names as nm;
use wicket_control::namesync::{self, Listens};
use wicket_names::{Desired, NamesConfig, PublicConfig, Record};
use wicket_store::{Ledger, NameKind, NameRow};

/// How long ended, denied and withdrawn names stay on the card.
pub const RECENT_SECS: i64 = 7 * 24 * 3600;
/// At most this many of them.
pub const MAX_RECENT: usize = 200;
/// How many of the newest node audit records a name's last connections are looked for in.
pub const CONN_SCAN: usize = 2000;
/// At most this many connections are shown.
pub const MAX_CONNS: usize = 50;

/// The installation's `names:` settings, or why they can't be read.
pub type Settings = std::result::Result<NamesConfig, String>;

/// What the views read: the ledger, the settings, whether a node listens on a host port, and now.
pub struct Ctx<'a> {
    pub l: &'a Ledger,
    pub settings: &'a Settings,
    pub listens: &'a Listens,
    pub now: i64,
}

impl Ctx<'_> {
    fn public(&self) -> Option<&PublicConfig> {
        self.settings.as_ref().ok().and_then(|s| s.public.as_ref())
    }
}

/// A name's full name: `<label>.<zone>.wicket.internal` for an internal one; for a public one,
/// under the boxes domain it was approved under, or (undecided) the installation's now. None: a
/// public ask on an installation without public names.
pub fn full_name(n: &NameRow, public: Option<&PublicConfig>) -> Option<String> {
    match n.kind {
        NameKind::Internal => Some(format!("{}.{}.{}", n.label, n.zone, wicket_core::link::DOMAIN)),
        NameKind::Public => n.domain.as_ref().map(|d| format!("{}.{d}", n.label)).or_else(|| public.map(|p| p.fqdn(&n.label))),
    }
}

/// What the reconciler would do now, for every live public name: wanted (its records) or waiting
/// (why), by name id; or why that can't be told.
struct Now {
    wanted: BTreeMap<String, Desired>,
    waiting: BTreeMap<String, String>,
    error: Option<String>,
}

fn reconciler_now(c: &Ctx<'_>, rows: &[NameRow]) -> Now {
    let mut out = Now { wanted: BTreeMap::new(), waiting: BTreeMap::new(), error: None };
    let Some(public) = c.public() else { return out };
    if !rows.iter().any(|n| n.kind == NameKind::Public && n.live(c.now)) {
        return out;
    }
    match namesync::desired_with(c.l, public, c.now, c.listens) {
        Ok((want, waiting)) => {
            out.wanted = want.into_iter().map(|d| (d.grant.clone(), d)).collect();
            out.waiting = waiting.into_iter().map(|w| (w.id, w.why)).collect();
        }
        Err(e) => out.error = Some(format!("what the reconciler would publish can't be told now: {e:#}")),
    }
    out
}

/// The last recorded plan (`name.plan`), if any.
fn last_plan(l: &Ledger) -> Option<Value> {
    l.audit_latest_unscoped("name.plan").ok().flatten().and_then(|b| serde_json::from_str(&b).ok())
}

/// A record's identity, TTL aside.
fn same_record(a: &Record, b: &Record) -> bool {
    a.name == b.name && a.rtype == b.rtype && a.value == b.value
}

/// The state and why of `n`, as the card shows it.
fn state_of(c: &Ctx<'_>, n: &NameRow, rn: &Now, plan: Option<&Value>, owned: &[(String, String, Record)]) -> (String, Option<String>) {
    let s = |state: &str, why: Option<String>| (state.to_string(), why);
    match n.status.as_str() {
        "live" => {}
        // A name whose lifetime ended (the sweep ends it within seconds of its end) is lapsed.
        "ended" if n.end_reason.as_deref() == Some("lapsed") => return s("lapsed", Some("its lifetime ended".into())),
        "ended" => return s("ended", n.end_reason.clone()),
        other => return s(other, None),
    }
    if !n.live(c.now) {
        return s("lapsed", Some("its lifetime is over: the next reconcile ends it".into()));
    }
    if n.kind == NameKind::Internal {
        return s("live", None);
    }
    if let Err(e) = c.settings {
        return s("waiting", Some(format!("the installation's settings can't be read: {e}")));
    }
    let Some(public) = c.public() else {
        return s("waiting", Some("this installation publishes no public names now (names.public in wicket.yaml)".into()));
    };
    if let Some(e) = &rn.error {
        return s("waiting", Some(e.clone()));
    }
    if let Some(why) = rn.waiting.get(&n.id) {
        return s("waiting", Some(why.clone()));
    }
    let Some(want) = rn.wanted.get(&n.id) else {
        let why = match n.holder {
            None => "no run holds it: the next run it is for takes it up when it starts",
            Some(_) => "its run doesn't hold it on a node yet",
        };
        return s("waiting", Some(why.into()));
    };
    let plan_zones = plan.and_then(|p| p["zones"].as_array()).cloned().unwrap_or_default();
    if plan_zones.iter().any(|z| z["conflicts"].as_array().is_some_and(|cs| cs.iter().any(|c| c["name"] == want.name.as_str()))) {
        return s(
            "taken",
            Some("the zone holds records at this name that wicket didn't make: they are left alone, and none is published".into()),
        );
    }
    if matches!(public.provider, wicket_names::ProviderKind::Noop) {
        return s("live", Some("the noop provider only records the plan: nothing is published".into()));
    }
    let mine: Vec<&Record> = owned.iter().filter(|(z, _, r)| *z == public.domain() && !r.is_owner_record()).map(|(_, _, r)| r).collect();
    let missing = want.records.iter().any(|w| !mine.iter().any(|r| same_record(r, w)));
    let extra = mine.iter().any(|r| !want.records.iter().any(|w| same_record(r, w)));
    if missing || extra {
        let zone_error = plan_zones.iter().find(|z| z["zone"] == public.domain().as_str()).and_then(|z| z["error"].as_str());
        let why = match zone_error {
            Some(e) => format!("its records aren't as wanted, and the last reconcile of the zone failed: {e}"),
            None => "its records aren't as wanted yet: the next reconcile makes them so".into(),
        };
        return s("out_of_sync", Some(why));
    }
    s("live", None)
}

fn row_with(c: &Ctx<'_>, n: &NameRow, rn: &Now, plan: Option<&Value>) -> Result<Value> {
    let name = full_name(n, c.public());
    let owned = match (&name, n.kind) {
        (Some(f), NameKind::Public) => c.l.owned_records_of(f)?,
        _ => vec![],
    };
    let (state, why) = state_of(c, n, rn, plan, &owned);
    let node = match (&n.holder, n.status.as_str()) {
        (Some(h), "live") => c.l.run_node(h)?,
        _ => None,
    };
    let addrs = match &node {
        Some(node) => c.l.node_addresses(node)?,
        None => Default::default(),
    };
    let host_port = match (&node, n.kind) {
        (Some(node), NameKind::Public) => c.l.port_of(&n.id, node, namesync::PROTO)?,
        _ => None,
    };
    Ok(json!({
        "id": n.id, "kind": n.kind.as_str(), "status": n.status, "state": state, "why": why, "name": name,
        "scope": n.scope.as_str(), "for": n.bound.map(|b| b.as_str()), "expires_at": n.expires_at,
        "created_at": n.created_at, "decided_by": n.decided_by, "decided_at": n.decided_at, "ended_at": n.ended_at,
        "end_reason": n.end_reason,
        "owner": { "principal": n.principal, "zone": n.zone, "run": n.asked_run, "holder": n.holder },
        "target": {
            "node": node, "public_ipv4": addrs.ipv4.map(|a| a.to_string()), "public_ipv6": addrs.ipv6.map(|a| a.to_string()),
            "host_port": host_port, "box_port": n.port,
        },
        // The agent's own words: shown quoted, and cleaned for where they are shown.
        "agent": { "label": n.label, "service": n.service, "reason": n.reason },
    }))
}

/// The rows of `names`, in order.
pub fn rows(c: &Ctx<'_>, names: &[NameRow]) -> Result<Vec<Value>> {
    let rn = reconciler_now(c, names);
    let plan = last_plan(c.l);
    names.iter().map(|n| row_with(c, n, &rn, plan.as_ref())).collect()
}

/// The names of `tenant` the card lists: pending asks, live names, and those that ended, were
/// denied or withdrawn in the last [`RECENT_SECS`] (at most [`MAX_RECENT`]).
pub fn card_names(l: &Ledger, tenant: &wicket_core::TenantId, now: i64) -> Result<Vec<NameRow>> {
    let mut names = l.names_with_status(tenant, "pending")?;
    names.extend(l.names_with_status(tenant, "live")?);
    names.extend(l.recent_names(tenant, now - RECENT_SECS, MAX_RECENT)?);
    Ok(names)
}

/// The card: [`card_names`]' rows, the installation's public settings (or why they can't be read),
/// and what a public name means.
pub fn card(c: &Ctx<'_>, tenant: &wicket_core::TenantId) -> Result<Value> {
    let names = card_names(c.l, tenant, c.now)?;
    Ok(json!({
        "names": rows(c, &names)?,
        "public": c.public().map(|p| json!({ "domain": p.domain(), "provider": p.provider.as_str() })),
        "settings_error": c.settings.as_ref().err(),
        "warning": nm::WARNING,
    }))
}

/// One name: its row, its records as the ledger lists them, the last plan's entries for it, and its
/// last connections.
pub fn detail(c: &Ctx<'_>, n: &NameRow) -> Result<Value> {
    let rn = reconciler_now(c, std::slice::from_ref(n));
    let plan = last_plan(c.l);
    let mut v = row_with(c, n, &rn, plan.as_ref())?;
    let name = full_name(n, c.public());
    let records: Vec<Value> = match (&name, n.kind) {
        (Some(f), NameKind::Public) => c
            .l
            .owned_records_of(f)?
            .into_iter()
            .map(|(zone, provider, r)| json!({ "zone": zone, "provider": provider, "name": r.name, "type": r.rtype, "value": r.value, "ttl": r.ttl }))
            .collect(),
        _ => vec![],
    };
    v["records"] = records.into();
    v["plan"] = match (&plan, &name) {
        (Some(p), Some(f)) if n.kind == NameKind::Public => plan_for(p, &n.id, f),
        _ => Value::Null,
    };
    v["connections"] = connections(c.l, n)?.into();
    Ok(v)
}

/// The base name a plan's change is about.
fn change_base(ch: &Value) -> Option<&str> {
    ch["name"].as_str().or_else(|| ch["to"]["name"].as_str()).map(wicket_names::record::base_of)
}

/// The last plan's entries for name `id` (full name `fqdn`): each zone's conflicts at it and
/// changes to it (with the zone's error, if its plan wasn't made), and why it was waiting.
fn plan_for(p: &Value, id: &str, fqdn: &str) -> Value {
    let zones: Vec<Value> = p["zones"]
        .as_array()
        .map(|zs| {
            zs.iter()
                .filter_map(|z| {
                    let conflicts: Vec<Value> =
                        z["conflicts"].as_array().map(|cs| cs.iter().filter(|c| c["name"] == fqdn).cloned().collect()).unwrap_or_default();
                    let changes: Vec<Value> = z["changes"]
                        .as_array()
                        .map(|cs| cs.iter().filter(|c| change_base(c) == Some(fqdn)).cloned().collect())
                        .unwrap_or_default();
                    (!conflicts.is_empty() || !changes.is_empty()).then(|| {
                        json!({ "zone": z["zone"], "conflicts": conflicts, "changes": changes, "applied": z["applied"], "error": z["error"] })
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let waiting = p["waiting"].as_array().and_then(|ws| ws.iter().find(|w| w["id"] == id)).map(|w| w["why"].clone());
    json!({ "provider": p["provider"], "zones": zones, "waiting": waiting })
}

/// Name `n`'s last connections, newest first: the node's `name.conn` and `name.conn.refused`
/// records for it among the newest [`CONN_SCAN`] node audit records, at most [`MAX_CONNS`].
fn connections(l: &Ledger, n: &NameRow) -> Result<Vec<Value>> {
    if n.kind != NameKind::Public {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for (seq, ts, _, run, body) in l.audit_newest_of_kind("node.audit", CONN_SCAN)? {
        let Ok(outer) = serde_json::from_str::<Value>(&body) else { continue };
        let kind = outer["kind"].as_str().unwrap_or("");
        if kind != "name.conn" && kind != "name.conn.refused" {
            continue;
        }
        let Some(mut inner) = outer["body"].as_str().and_then(|b| serde_json::from_str::<Value>(b).ok()) else { continue };
        if inner["name"] != n.id.as_str() || outer["tenant"].as_str().is_some_and(|t| t != n.tenant) {
            continue;
        }
        // The label the node copied in is the agent's: the row has it, under `agent`.
        if let Some(o) = inner.as_object_mut() {
            o.remove("label");
        }
        out.push(json!({ "seq": seq, "ts": ts, "node": outer["node"], "run": run, "kind": kind, "record": inner }));
        if out.len() >= MAX_CONNS {
            break;
        }
    }
    Ok(out)
}

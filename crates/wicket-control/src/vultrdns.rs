//! The Vultr DNS provider (#575 step 5a; design in `docs/explanation/box-dns.md`, "Providers"): a
//! [`DnsProvider`] over Vultr API v2's DNS records, through the placement crate's Vultr client
//! (its bearer key, paging, backoff and error mapping), so wicket-names stays free of HTTP.
//!
//! **Requests used** (all JSON, `Authorization: Bearer <key>`):
//! - `GET /domains/{zone}`: whether the account serves the zone (`404`: it doesn't,
//!   [`ProviderError::Zone`]).
//! - `GET /domains/{zone}/records?per_page=500[&cursor=C]` → `{"records": [{id, type, name, data,
//!   priority, ttl}], "meta": {"total", "links": {"next", "prev"}}}`, paged to the end. A page
//!   failing, a page without `records` or `meta`, or a count other than `meta.total` fails the
//!   listing ([`ProviderError::List`]): never a partial `Ok`.
//! - `POST /domains/{zone}/records` with `{name, type, data, ttl, priority?}` → `{"record": {…}}`.
//! - `PATCH /domains/{zone}/records/{id}` with `{data, ttl, priority?}`.
//! - `DELETE /domains/{zone}/records/{id}`; `404` counts as already gone.
//!
//! **Records as wicket has them.** Vultr names a record relative to its zone (`demo`,
//! `_wicket.demo`; the apex as `""`, or `"@"`, both read as the apex; a name ending in a dot as
//! absolute); wicket's are absolute, lower case, without the trailing dot. An SRV's `data` is
//! `weight port target`, its priority a field of its own; wicket's value is
//! `priority weight port target`. The target is sent fully qualified (`demo.boxes.example.com.`:
//! octodns-vultr sends it so, and its fixtures of Vultr's listings hold SRV targets with the dot),
//! and read with or without the dot. TXT data is written quoted (an owner record's `;` would start a
//! comment in a zone file) and read with or without quotes. Any other type is listed as
//! [`RecordType::Other`]. A listed field that doesn't parse (a priority absent, or `-1`, on an A
//! record) is read leniently, so one odd record can't fail the whole listing.
//!
//! **Assumed, not yet checked against the real API** (the tests run against a local mock; an
//! operator's manual check is in `docs/explanation/box-dns.md`): the apex's name is `""`; TXT data
//! may be sent quoted and is listed as sent or unquoted; an SRV's `data` is `weight port target`
//! with `priority` apart, its target with a trailing dot taken as absolute; a 30 s TTL is
//! accepted (octodns-vultr says Vultr clamps TTLs below 60 rather than refusing them: a clamped
//! TTL would list as 60 and be planned as an update at every pass); create answers
//! `{"record": {…}}` (as the govultr client reads it); `meta.total` counts the zone's records, as
//! it counts plans (checked live) and as octodns-vultr's fixtures show it. The field names and the
//! request bodies are govultr's.
//!
//! **Apply** lists the zone afresh, maps each record to its Vultr id, and makes the plan's changes
//! in order, keeping the map current (a create's new id, an update's new value). A zone may hold
//! one name, type and value twice: a delete removes every such record, and an update deletes the
//! others and patches the first, so either leaves exactly what the plan wants. It stops at the
//! first failure with [`ProviderError::Partial`] (how many changes were made), or
//! [`ProviderError::Failed`] for an authorization failure on the first. A record to update or
//! delete that the listing lacks stops it there too. `429` is retried with backoff, and `5xx` except after a POST: a create retried
//! after a `5xx` could make a second record. The reconciler recorded the create before applying,
//! so the next pass's listing shows whether it happened and plans from there.
//!
//! **The key** is an [`ApiKey`]: read from wicket's vault by the secret `names.public.credential`
//! names, at each pass on the control host, never written to a URL, an error, a log or an audit
//! body (errors pass through [`ApiKey::redact`] too). The provider's id is
//! `vultr:<first 12 hex digits of the key's SHA-256>`: it names the account without the key, so
//! a rotated key is another provider to the ledger (its records are stranded until the old key is
//! back, or are withdrawn by it).

use anyhow::Result;
use serde::Deserialize;
use std::collections::BTreeMap;
use wicket_names::{Applied, Caps, Change, DnsProvider, Plan, ProviderError, Record, RecordType, Zone};
use wicket_placement::vultr::{ApiError, ApiKey, Client};

/// The host the key goes to: what its vault secret's `.hosts` should name. [`VultrDns::new`] (the
/// provider the reconciler builds from the vault) refuses a client whose base URL is anything but
/// `https://` at this host, before any request carries the key.
pub const API_HOST: &str = "api.vultr.com";

/// The lowest TTL wicket sends Vultr (s). Vultr documents none that we could find; 30 is wicket's
/// own floor (`names.public.ttl`).
/// Vultr raises a lower TTL to 60 silently, by octodns-vultr's account (its `MIN_TTL = 60`), so a
/// record written at 30 would list at 60 and be planned again every pass: 60 is refused below.
pub const MIN_TTL: u32 = 60;

/// Vultr's DNS, for whichever zone the reconciler asks about (a zone change withdraws the old
/// zone's records with the same provider).
pub struct VultrDns {
    client: Client,
    id: String,
}

/// A record as the API lists it, every field optional.
#[derive(Deserialize)]
struct Listed {
    #[serde(default)]
    id: String,
    #[serde(default, rename = "type")]
    rtype: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    priority: Option<serde_json::Value>,
    #[serde(default)]
    ttl: Option<serde_json::Value>,
}

/// Why a change stopped.
enum Stop {
    Api(anyhow::Error),
    Missing(String),
}

type Key = (String, RecordType, String);

impl VultrDns {
    /// A provider writing with `key`, at Vultr's API: its client's base URL is checked to be
    /// `https://` [`API_HOST`], so the key goes nowhere else.
    pub fn new(key: ApiKey) -> Result<VultrDns> {
        let client = Client::new(key)?.with_per_page(500);
        at_api_host(client.base())?;
        Ok(VultrDns::over(client))
    }

    /// A provider over `client` (a mock's base URL, retry or page size), its host not checked:
    /// tests only, so every provider outside them is built by [`VultrDns::new`].
    #[cfg(test)]
    pub(crate) fn with_client(client: Client) -> VultrDns {
        VultrDns::over(client)
    }

    fn over(client: Client) -> VultrDns {
        let id = format!("vultr:{}", client.key().fingerprint());
        VultrDns { client, id }
    }

    /// The provider with the key in vault secret `secret` (`names.public.credential`), read now.
    /// The error names the secret, never its value.
    pub fn from_vault(vault: &wicket_proxy::vault::Vault, secret: &str) -> Result<VultrDns> {
        let key = vault.get(secret).map_err(|e| anyhow::anyhow!("reading names.public.credential {secret:?} from the vault: {e:#}"))?;
        VultrDns::new(ApiKey::new(key))
    }

    fn redact(&self, e: &anyhow::Error) -> String {
        self.client.key().redact(&format!("{e:#}"))
    }

    fn base(zone: &Zone) -> Result<String, ProviderError> {
        let apex = zone.apex();
        if apex.is_empty() || !apex.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')) {
            return Err(ProviderError::Zone(apex.to_string()));
        }
        Ok(format!("/domains/{apex}"))
    }

    /// The zone's records with their Vultr ids.
    async fn listing(&self, zone: &Zone) -> Result<Vec<(String, Record)>, ProviderError> {
        let base = Self::base(zone)?;
        match self.client.call(reqwest::Method::GET, &base, &[], None).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(ProviderError::Zone(zone.apex().to_string())),
            Err(e) => return Err(ProviderError::List(self.redact(&e))),
        }
        let listed: Vec<Listed> =
            self.client.paged(&format!("{base}/records"), "records", &[]).await.map_err(|e| ProviderError::List(self.redact(&e)))?;
        Ok(listed.into_iter().map(|l| (l.id.clone(), from_vultr(zone, &l))).collect())
    }

    /// Whether `e` is the API refusing the key.
    fn is_auth(e: &anyhow::Error) -> bool {
        e.downcast_ref::<ApiError>().is_some_and(|a| a.status == 401 || a.status == 403)
    }

    /// Deletes record `id`; a `404` counts as already gone.
    async fn delete(&self, base: &str, id: &str) -> Result<(), Stop> {
        let path = format!("{base}/records/{}", segment(id).map_err(Stop::Missing)?);
        self.client.call(reqwest::Method::DELETE, &path, &[], None).await.map_err(Stop::Api)?;
        Ok(())
    }

    async fn change(&self, zone: &Zone, base: &str, c: &Change, ids: &mut BTreeMap<Key, Vec<String>>) -> Result<(), Stop> {
        let rid = |ids: &BTreeMap<Key, Vec<String>>, r: &Record| -> Result<String, Stop> {
            ids.get(&r.key())
                .and_then(|v| v.first())
                .cloned()
                .ok_or_else(|| Stop::Missing(format!("{} {} {:?} isn't in the zone's listing", r.name, r.rtype, r.value)))
        };
        match c {
            Change::Create(r) => {
                let mut body = to_vultr(zone, r).map_err(Stop::Missing)?;
                body["name"] = relative(zone, &r.name).map_err(Stop::Missing)?.into();
                body["type"] = r.rtype.to_string().into();
                let out = self.client.call(reqwest::Method::POST, &format!("{base}/records"), &[], Some(&body)).await.map_err(Stop::Api)?;
                let out = out.ok_or_else(|| Stop::Missing(format!("creating {} {}: the zone is gone", r.name, r.rtype)))?;
                if let Some(id) = out.pointer("/record/id").and_then(|v| v.as_str()) {
                    ids.entry(r.key()).or_default().push(id.to_string());
                }
            }
            Change::Update { from, to } => {
                // Duplicates of `from` (Vultr lets a zone hold the same name, type and value
                // twice): the first is patched, the others deleted first, so the zone ends with
                // exactly the wanted record, as a delete leaves none. Deleting first means a
                // failure part way still lists `from`, so the next pass plans this update again.
                let id = rid(ids, from)?;
                let extras: Vec<String> =
                    ids.get(&from.key()).map(|v| v.iter().filter(|x| **x != id).cloned().collect()).unwrap_or_default();
                for x in extras {
                    self.delete(base, &x).await?;
                    if let Some(v) = ids.get_mut(&from.key()) {
                        v.retain(|y| *y != x);
                    }
                }
                let body = to_vultr(zone, to).map_err(Stop::Missing)?;
                let path = format!("{base}/records/{}", segment(&id).map_err(Stop::Missing)?);
                let out = self.client.call(reqwest::Method::PATCH, &path, &[], Some(&body)).await.map_err(Stop::Api)?;
                if out.is_none() {
                    return Err(Stop::Missing(format!("updating {} {}: the record is gone", from.name, from.rtype)));
                }
                if let Some(v) = ids.get_mut(&from.key()) {
                    v.retain(|x| *x != id);
                }
                ids.entry(to.key()).or_default().push(id);
            }
            Change::Delete(r) => {
                // Every record with this name, type and value: a duplicate left behind would be an
                // address no ledger row vouches for.
                let all = ids.get(&r.key()).cloned().unwrap_or_default();
                if all.is_empty() {
                    rid(ids, r)?;
                }
                for id in all {
                    self.delete(base, &id).await?;
                    if let Some(v) = ids.get_mut(&r.key()) {
                        v.retain(|x| *x != id);
                    }
                }
            }
        }
        Ok(())
    }
}

impl DnsProvider for VultrDns {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { types: vec![RecordType::A, RecordType::Aaaa, RecordType::Srv, RecordType::Txt], min_ttl: MIN_TTL, atomic: false }
    }

    async fn list(&self, zone: &Zone) -> Result<Vec<Record>, ProviderError> {
        Ok(self.listing(zone).await?.into_iter().map(|(_, r)| r).collect())
    }

    async fn apply(&self, zone: &Zone, plan: &Plan) -> Result<Applied, ProviderError> {
        self.caps().check(plan)?;
        let base = Self::base(zone)?;
        let mut ids: BTreeMap<Key, Vec<String>> = BTreeMap::new();
        for (id, r) in self.listing(zone).await? {
            ids.entry(r.key()).or_default().push(id);
        }
        for (i, c) in plan.changes.iter().enumerate() {
            if let Err(stop) = self.change(zone, &base, c, &mut ids).await {
                return Err(match stop {
                    Stop::Api(e) if i == 0 && Self::is_auth(&e) => ProviderError::Failed(self.redact(&e)),
                    Stop::Api(e) => ProviderError::Partial { done: i, why: self.redact(&e) },
                    Stop::Missing(why) => ProviderError::Partial { done: i, why },
                });
            }
        }
        Ok(Applied { applied: true, changes: plan.changes.len() })
    }
}

/// Whether `base` is `https://` [`API_HOST`] (no other host, port or userinfo).
fn at_api_host(base: &str) -> Result<()> {
    let u = reqwest::Url::parse(base).map_err(|e| anyhow::anyhow!("the Vultr API base URL doesn't parse: {e}"))?;
    let ok =
        u.scheme() == "https" && u.host_str() == Some(API_HOST) && u.port().is_none() && u.username().is_empty() && u.password().is_none();
    anyhow::ensure!(ok, "the Vultr API key goes only to https://{API_HOST}, not {}", u.host_str().unwrap_or("?"));
    Ok(())
}

/// A Vultr record id as a path segment: anything that could change the path is refused.
fn segment(id: &str) -> Result<&str, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!("{id:?} is not a Vultr record id"));
    }
    Ok(id)
}

/// `name` relative to the zone, as Vultr writes it (`""` for the apex).
fn relative(zone: &Zone, name: &str) -> Result<String, String> {
    let apex = zone.apex();
    if name == apex {
        return Ok(String::new());
    }
    name.strip_suffix(apex)
        .and_then(|l| l.strip_suffix('.'))
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{name} is not in zone {apex}"))
}

/// The fields of a create or update: `data`, `ttl`, and an SRV's `priority`.
fn to_vultr(zone: &Zone, r: &Record) -> Result<serde_json::Value, String> {
    let mut body = serde_json::json!({ "ttl": r.ttl });
    match r.rtype {
        RecordType::A | RecordType::Aaaa => body["data"] = r.value.clone().into(),
        RecordType::Txt => body["data"] = format!("\"{}\"", r.value.replace('\\', "\\\\").replace('"', "\\\"")).into(),
        RecordType::Srv => match r.value.split_whitespace().collect::<Vec<_>>().as_slice() {
            [p, w, port, target] => {
                let p: u16 = p.parse().map_err(|_| format!("SRV {} has priority {p:?}", r.name))?;
                body["priority"] = p.into();
                // Fully qualified: a target without the dot may be read relative to the zone.
                let target = if target.ends_with('.') { target.to_string() } else { format!("{target}.") };
                body["data"] = format!("{w} {port} {target}").into();
            }
            _ => return Err(format!("SRV {} has value {:?}, not `priority weight port target`", r.name, r.value)),
        },
        RecordType::Other => return Err(format!("{} in zone {}: wicket writes no record of another type", r.name, zone.apex())),
    }
    Ok(body)
}

/// A listed record as wicket has it.
fn from_vultr(zone: &Zone, l: &Listed) -> Record {
    let rtype = match l.rtype.to_ascii_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::Aaaa,
        "SRV" => RecordType::Srv,
        "TXT" => RecordType::Txt,
        _ => RecordType::Other,
    };
    let n = l.name.trim();
    let name = match n {
        "" | "@" => zone.apex().to_string(),
        n if n.ends_with('.') => n.to_string(),
        n => format!("{n}.{}", zone.apex()),
    };
    let num = |v: &Option<serde_json::Value>| -> Option<i64> {
        v.as_ref().and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
    };
    let value = match rtype {
        // `weight port target`, the priority apart; a `data` that has all four is taken as it is.
        RecordType::Srv if l.data.split_whitespace().count() == 3 => format!("{} {}", num(&l.priority).unwrap_or(0).max(0), l.data.trim()),
        RecordType::Txt => unquote(l.data.trim()),
        _ => l.data.clone(),
    };
    let ttl = num(&l.ttl).and_then(|t| u32::try_from(t).ok()).unwrap_or(0);
    Record { name, rtype, value, ttl }.normalized()
}

/// TXT data without the quotes Vultr may list it in, its escapes undone: `"a\"b"` is `a"b`.
fn unquote(d: &str) -> String {
    let Some(inner) = d.strip_prefix('"').and_then(|d| d.strip_suffix('"')) else { return d.to_string() };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use wicket_names::{Desired, Owned, OwnerId};
    use wicket_placement::mock::{self, record, KEY};
    use wicket_placement::vultr::Retry;

    const ZONE: &str = "boxes.example.com";

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, last)
    }

    fn client(base: &str, key: &str, per_page: u32) -> Client {
        Client::with_base(base, ApiKey::new(key))
            .unwrap()
            .with_per_page(per_page)
            .with_retry(Retry { attempts: 3, base: Duration::from_millis(1) })
    }

    async fn served(records: Vec<Value>) -> (VultrDns, mock::Shared) {
        let (base, st) = mock::serve().await;
        st.lock().unwrap().domains.insert(ZONE.into(), records);
        (VultrDns::with_client(client(&base, KEY, 2)), st)
    }

    fn zone() -> Zone {
        Zone::new(ZONE)
    }

    fn writes(st: &mock::Shared) -> Vec<(String, String)> {
        st.lock().unwrap().seen.iter().filter(|s| s.method != "GET").map(|s| (s.method.clone(), s.path.clone())).collect()
    }

    #[tokio::test]
    async fn lists_every_page_and_normalises_names_srv_and_txt() {
        let recs = vec![
            record("r1", "A", "Demo", &ip(1).to_string(), 0, 60),
            record("r2", "TXT", "_wicket.demo", "\"wicket-owner=a1b2c3d4;name=g1\"", 0, 60),
            record("r3", "SRV", "_http._tcp.demo", "0 20001 demo.boxes.example.com.", 5, 60),
            record("r4", "TXT", "", "plain text", -1, 300),
            record("r5", "MX", "@", "mail.example.net", 10, 300),
            json!({ "id": "r6", "type": "AAAA", "name": "v6", "data": "2001:DB8:0::1", "ttl": 60 }),
            record("r7", "CNAME", "www.boxes.example.com.", "elsewhere.example.net", 0, 300),
        ];
        let (p, st) = served(recs).await;
        let got = p.list(&zone()).await.unwrap();
        assert_eq!(got.len(), 7);
        assert_eq!(got[0], Record::a("demo.boxes.example.com", ip(1), 60));
        assert_eq!(got[1], OwnerId::parse("a1b2c3d4").unwrap().owner_record("demo.boxes.example.com", "g1", 60));
        assert_eq!(got[2].value, "5 0 20001 demo.boxes.example.com");
        assert_eq!((got[3].name.as_str(), got[3].value.as_str()), (ZONE, "plain text"));
        assert_eq!((got[4].name.as_str(), got[4].rtype), (ZONE, RecordType::Other));
        assert_eq!(got[5].value, "2001:db8::1");
        assert_eq!(got[6].name, "www.boxes.example.com");
        // Four pages of two, after the domain check.
        let pages: Vec<_> = st.lock().unwrap().seen.iter().filter(|s| s.path.ends_with("/records")).map(|s| s.query.clone()).collect();
        assert_eq!(pages.len(), 4);
        assert!(pages[1].iter().any(|(k, v)| k == "cursor" && v == "c2"), "{pages:?}");
        // Every request carried the key as a bearer token, and only there.
        for s in &st.lock().unwrap().seen {
            assert_eq!(s.auth.as_deref(), Some(format!("Bearer {KEY}").as_str()));
            assert!(!s.path.contains(KEY) && !s.query.iter().any(|(_, v)| v.contains(KEY)));
        }
    }

    #[tokio::test]
    async fn a_page_failing_fails_the_listing() {
        let (p, st) = served((0..5).map(|i| record(&format!("r{i}"), "A", &format!("n{i}"), &ip(i).to_string(), 0, 60)).collect()).await;
        st.lock().unwrap().fail_when =
            Some(Box::new(|s| s.query.iter().any(|(k, v)| k == "cursor" && v == "c2").then(|| (500, json!({"error": "boom"})))));
        assert!(matches!(p.list(&zone()).await, Err(ProviderError::List(e)) if e.contains("HTTP 500")));
    }

    /// A short listing would read as records gone: a page without its list or `meta`, or a count
    /// other than `meta.total`, fails the listing, on the first page or a later one.
    #[tokio::test]
    async fn a_page_short_of_records_or_meta_fails_the_listing() {
        let five: Vec<Value> = (0..5).map(|i| record(&format!("r{i}"), "A", &format!("n{i}"), &ip(i).to_string(), 0, 60)).collect();
        let meta = |total: u64, next: &str| json!({ "total": total, "links": { "next": next, "prev": "" } });
        let page1 = || json!([five_slice(0), five_slice(1)]);
        fn five_slice(i: u8) -> Value {
            record(&format!("r{i}"), "A", &format!("n{i}"), &ip(i).to_string(), 0, 60)
        }
        let cases: Vec<(&str, Option<&str>, Value)> = vec![
            ("the first page without records", None, json!({ "meta": meta(5, "c2") })),
            ("a later page without records", Some("c2"), json!({ "meta": meta(5, "c4") })),
            ("an empty body", Some("c2"), Value::Null),
            ("records not a list", None, json!({ "records": {}, "meta": meta(5, "c2") })),
            ("no meta", Some("c2"), json!({ "records": [] })),
            ("meta without a total", None, json!({ "records": page1(), "meta": { "links": { "next": "c2" } } })),
            ("meta without links", Some("c4"), json!({ "records": [five_slice(4)], "meta": { "total": 5 } })),
            ("meta not an object", None, json!({ "records": page1(), "meta": "x" })),
            ("the last page short", Some("c4"), json!({ "records": [], "meta": meta(5, "") })),
            ("the total changed while paging", Some("c2"), json!({ "records": [five_slice(2), five_slice(3)], "meta": meta(6, "c4") })),
            ("a total above the count, all on one page", None, json!({ "records": page1(), "meta": meta(3, "") })),
        ];
        for (what, cursor, body) in cases {
            let (p, st) = served(five.clone()).await;
            let cursor = cursor.map(str::to_string);
            st.lock().unwrap().fail_when = Some(Box::new(move |s| {
                let at = s.query.iter().find(|(k, _)| k == "cursor").map(|(_, v)| v.clone());
                (s.path.ends_with("/records") && at == cursor).then(|| (200, body.clone()))
            }));
            assert!(matches!(p.list(&zone()).await, Err(ProviderError::List(_))), "{what}");
            let pl = Plan { changes: vec![Change::Delete(Record::a("n9.boxes.example.com", ip(9), 60))], conflicts: vec![] };
            assert!(matches!(p.apply(&zone(), &pl).await, Err(ProviderError::List(_))), "{what}: apply lists first");
            assert!(writes(&st).is_empty(), "{what}: nothing written");
        }
        // The same zone listed whole passes.
        let (p, _st) = served(five).await;
        assert_eq!(p.list(&zone()).await.unwrap().len(), 5);
    }

    /// Vultr lets a zone hold one name, type and value twice; an update leaves exactly the wanted
    /// record, as a delete leaves none.
    #[tokio::test]
    async fn an_update_of_a_duplicated_record_leaves_exactly_one() {
        let n = "demo.boxes.example.com";
        let dup = |ttl| vec![record("r1", "A", "demo", &ip(1).to_string(), 0, ttl), record("r2", "A", "demo", &ip(1).to_string(), 0, ttl)];
        // A new value: the first patched, the other deleted (before the patch).
        let (p, st) = served(dup(60)).await;
        let pl = Plan { changes: vec![Change::Update { from: Record::a(n, ip(1), 60), to: Record::a(n, ip(2), 60) }], conflicts: vec![] };
        assert_eq!(p.apply(&zone(), &pl).await.unwrap(), Applied { applied: true, changes: 1 });
        assert_eq!(p.list(&zone()).await.unwrap(), vec![Record::a(n, ip(2), 60)]);
        let w = writes(&st);
        assert_eq!(w.len(), 2, "{w:?}");
        assert_eq!(w[0].0, "DELETE");
        assert!(w[0].1.ends_with("/records/r2") && w[1].0 == "PATCH" && w[1].1.ends_with("/records/r1"), "{w:?}");
        // A TTL only (the same key): one left, with the new TTL.
        let (p, _st) = served(dup(60)).await;
        let pl = Plan { changes: vec![Change::Update { from: Record::a(n, ip(1), 60), to: Record::a(n, ip(1), 120) }], conflicts: vec![] };
        p.apply(&zone(), &pl).await.unwrap();
        assert_eq!(p.list(&zone()).await.unwrap(), vec![Record::a(n, ip(1), 120)]);
        // The extra's delete failing: Partial at 0, `from` still listed for the next pass to update.
        let (p, st) = served(dup(60)).await;
        st.lock().unwrap().fail_when = Some(Box::new(|s| (s.method == "DELETE").then(|| (500, json!({"error": "boom"})))));
        let pl = Plan { changes: vec![Change::Update { from: Record::a(n, ip(1), 60), to: Record::a(n, ip(2), 60) }], conflicts: vec![] };
        assert!(matches!(p.apply(&zone(), &pl).await, Err(ProviderError::Partial { done: 0, .. })));
        st.lock().unwrap().fail_when = None;
        assert!(p.list(&zone()).await.unwrap().contains(&Record::a(n, ip(1), 60)));
    }

    #[test]
    fn the_key_goes_only_to_the_api_host() {
        assert!(at_api_host(wicket_placement::vultr::API_BASE).is_ok());
        assert!(VultrDns::new(ApiKey::new(KEY)).is_ok());
        for bad in [
            "http://api.vultr.com/v2",
            "https://api.vultr.com.example.net/v2",
            "https://example.net/api.vultr.com/v2",
            "https://api.vultr.com:8443/v2",
            "https://user@api.vultr.com/v2",
            "https://example.net/v2?h=api.vultr.com",
            "not a url",
        ] {
            assert!(at_api_host(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_zone_the_account_doesnt_serve_is_a_zone_error() {
        let (p, _st) = served(vec![]).await;
        assert_eq!(p.list(&Zone::new("other.example.com")).await, Err(ProviderError::Zone("other.example.com".into())));
        let pl = Plan { changes: vec![Change::Create(Record::a("x.other.example.com", ip(1), 60))], conflicts: vec![] };
        assert_eq!(p.apply(&Zone::new("other.example.com"), &pl).await, Err(ProviderError::Zone("other.example.com".into())));
    }

    #[tokio::test]
    async fn creates_updates_and_deletes_in_order() {
        let (p, st) = served(vec![]).await;
        let z = zone();
        let o = OwnerId::parse("a1b2c3d4").unwrap();
        let n = z.name("demo");
        let d = Desired {
            name: n.clone(),
            grant: "g1".into(),
            records: vec![Record::a(&n, ip(1), 60), Record::srv(&n, "http", 20001, 60)],
            ttl: 60,
        };
        let pl = wicket_names::plan(&z, &o, std::slice::from_ref(&d), &p.list(&z).await.unwrap(), &Owned::default()).unwrap();
        assert_eq!(p.apply(&z, &pl).await.unwrap(), Applied { applied: true, changes: 3 });
        {
            let m = st.lock().unwrap();
            let recs = &m.domains[ZONE];
            let txt = recs.iter().find(|r| r["type"] == "TXT").unwrap();
            assert_eq!((txt["name"].as_str(), txt["data"].as_str()), (Some("_wicket.demo"), Some("\"wicket-owner=a1b2c3d4;name=g1\"")));
            let srv = recs.iter().find(|r| r["type"] == "SRV").unwrap();
            assert_eq!(
                (srv["name"].as_str(), srv["data"].as_str(), srv["priority"].as_u64()),
                (Some("_http._tcp.demo"), Some("0 20001 demo.boxes.example.com."), Some(0))
            );
        }
        // What it made lists as what was planned: the next plan is empty.
        let owned = Owned::default().before_apply(&pl);
        assert!(wicket_names::plan(&z, &o, std::slice::from_ref(&d), &p.list(&z).await.unwrap(), &owned).unwrap().is_empty());
        // The box moves: the A record is updated in place.
        let moved = Desired { records: vec![Record::a(&n, ip(2), 60), Record::srv(&n, "http", 20001, 60)], ..d.clone() };
        let pl2 = wicket_names::plan(&z, &o, std::slice::from_ref(&moved), &p.list(&z).await.unwrap(), &owned).unwrap();
        assert!(matches!(pl2.changes.as_slice(), [Change::Update { .. }]), "{pl2:?}");
        p.apply(&z, &pl2).await.unwrap();
        assert!(writes(&st).iter().any(|(m, _)| m == "PATCH"));
        assert!(p.list(&z).await.unwrap().contains(&Record::a(&n, ip(2), 60)));
        // Revoked: every record goes, the owner record last.
        let owned = owned.after_apply(&pl2);
        let pl3 = wicket_names::plan(&z, &o, &[], &p.list(&z).await.unwrap(), &owned).unwrap();
        assert_eq!(pl3.changes.len(), 3);
        p.apply(&z, &pl3).await.unwrap();
        assert!(st.lock().unwrap().domains[ZONE].is_empty());
        let deletes: Vec<_> = writes(&st).into_iter().filter(|(m, _)| m == "DELETE").collect();
        assert_eq!(deletes.len(), 3);
    }

    #[tokio::test]
    async fn a_delete_of_a_record_already_gone_counts_done() {
        let r = Record::a("demo.boxes.example.com", ip(1), 60);
        let (p, st) = served(vec![record("r1", "A", "demo", &ip(1).to_string(), 0, 60)]).await;
        // Deleted by someone else between the listing and the delete.
        st.lock().unwrap().fail_when = Some(Box::new(|s| (s.method == "DELETE").then(|| (404, json!({"error": "Invalid record."})))));
        let pl = Plan { changes: vec![Change::Delete(r)], conflicts: vec![] };
        assert_eq!(p.apply(&zone(), &pl).await.unwrap(), Applied { applied: true, changes: 1 });
    }

    #[tokio::test]
    async fn a_mid_plan_failure_says_how_far_it_got() {
        let (p, st) = served(vec![]).await;
        let mut n = 0;
        st.lock().unwrap().fail_when = Some(Box::new(move |s| {
            if s.method != "POST" {
                return None;
            }
            n += 1;
            (n == 2).then(|| (400, json!({"error": "Unable to create record", "status": 400})))
        }));
        let pl = Plan {
            changes: vec![
                Change::Create(Record::a("a.boxes.example.com", ip(1), 60)),
                Change::Create(Record::a("b.boxes.example.com", ip(2), 60)),
                Change::Create(Record::a("c.boxes.example.com", ip(3), 60)),
            ],
            conflicts: vec![],
        };
        match p.apply(&zone(), &pl).await {
            Err(ProviderError::Partial { done: 1, why }) => assert!(why.contains("Unable to create record"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(st.lock().unwrap().domains[ZONE].len(), 1);
        // A POST failing with a 5xx isn't retried (the create may have happened).
        st.lock().unwrap().fail_when = Some(Box::new(|s| (s.method == "POST").then(|| (503, json!({"error": "busy"})))));
        let before = writes(&st).len();
        assert!(matches!(p.apply(&zone(), &pl).await, Err(ProviderError::Partial { done: 0, .. })));
        assert_eq!(writes(&st).len(), before + 1, "one POST, no retry");
        // A record to update that the listing lacks stops the plan there.
        st.lock().unwrap().fail_when = None;
        let gone = Record::a("gone.boxes.example.com", ip(9), 60);
        let pl = Plan {
            changes: vec![
                Change::Create(Record::a("d.boxes.example.com", ip(4), 60)),
                Change::Update { from: gone.clone(), to: Record { ttl: 120, ..gone } },
            ],
            conflicts: vec![],
        };
        assert!(
            matches!(p.apply(&zone(), &pl).await, Err(ProviderError::Partial { done: 1, why }) if why.contains("isn't in the zone's listing"))
        );
    }

    #[tokio::test]
    async fn an_auth_failure_fails_and_never_shows_the_key() {
        let (base, st) = mock::serve().await;
        st.lock().unwrap().domains.insert(ZONE.into(), vec![]);
        let wrong = "wrong-key-also-not-real";
        let p = VultrDns::with_client(client(&base, wrong, 500));
        let e = p.list(&zone()).await.unwrap_err();
        assert!(matches!(&e, ProviderError::List(m) if m.contains("HTTP 401")), "{e:?}");
        assert!(!e.to_string().contains(wrong));
        // The listing passes, the first write is refused: Failed, not Partial.
        let (p, st) = served(vec![]).await;
        st.lock().unwrap().fail_when =
            Some(Box::new(|s| (s.method == "POST").then(|| (403, json!({"error": "Unauthorized IP address", "status": 403})))));
        let pl = Plan { changes: vec![Change::Create(Record::a("a.boxes.example.com", ip(1), 60))], conflicts: vec![] };
        assert!(matches!(p.apply(&zone(), &pl).await, Err(ProviderError::Failed(m)) if m.contains("HTTP 403")));
        // An API that echoed the key back: redacted from the error.
        st.lock().unwrap().fail_when =
            Some(Box::new(|s| (s.method == "POST").then(|| (400, json!({"error": format!("bad token {KEY}")})))));
        let e = p.apply(&zone(), &pl).await.unwrap_err().to_string();
        assert!(!e.contains(KEY) && e.contains("[redacted]"), "{e}");
    }

    #[test]
    fn its_id_names_the_account_not_the_key() {
        let p = VultrDns::with_client(Client::with_base("http://127.0.0.1:9", ApiKey::new(KEY)).unwrap());
        let id = p.id().to_string();
        assert!(id.starts_with("vultr:") && id.len() == "vultr:".len() + 12, "{id}");
        assert!(!id.contains(KEY));
        let other = VultrDns::with_client(Client::with_base("http://127.0.0.1:9", ApiKey::new("another-key")).unwrap());
        assert_ne!(other.id(), id);
        assert_eq!(p.caps().min_ttl, MIN_TTL);
        assert!(p.writes() && !p.caps().atomic);
    }

    #[test]
    fn names_and_values_go_back_as_vultr_has_them() {
        let z = zone();
        assert_eq!(relative(&z, ZONE).unwrap(), "");
        assert_eq!(relative(&z, "_wicket.demo.boxes.example.com").unwrap(), "_wicket.demo");
        assert!(relative(&z, "demo.other.example.com").is_err());
        assert!(relative(&z, "xboxes.example.com").is_err());
        let t = to_vultr(&z, &Record::txt("x.boxes.example.com", "say \"hi\"", 60)).unwrap();
        assert_eq!(t["data"], "\"say \\\"hi\\\"\"");
        assert_eq!(unquote(t["data"].as_str().unwrap()), "say \"hi\"");
        assert!(segment("../x").is_err() && segment("6e3b1c2a-0000").is_ok());
    }
}

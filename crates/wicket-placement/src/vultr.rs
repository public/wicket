//! The Vultr backend: a small client for Vultr API v2 and a [`Provider`] over it.
//!
//! **Requests used** (all JSON, `Authorization: Bearer <key>`):
//! - `GET /plans?type=all&per_page=N[&cursor=C]` (every family, so any instance can be priced) → `{"plans": [{id, vcpu_count, ram (MB), disk,
//!   monthly_cost, hourly_cost?, type, locations}], "meta": {"total", "links": {"next", "prev"}}}`
//! - `POST /instances` with `{region, plan, os_id, label, hostname, tags, sshkey_id, user_data (base64),
//!   backups: "disabled", enable_ipv6, activation_email: false}` → `202 {"instance": {…}}`
//! - `GET /instances/{id}` → `{"instance": {id, main_ip, date_created, status, power_status,
//!   server_status, plan, region, label, tags, vcpu_count, ram, …}}`; `404` when gone
//! - `GET /instances?tag=T&per_page=N[&cursor=C]` → `{"instances": [...], "meta": {…}}`: paged with
//!   `meta.links.next` until it is empty
//! - `PATCH /instances/{id}` with `{"user_data": …}` (to drop the boot host key after enrolment)
//! - `DELETE /instances/{id}` → `204`; `404` counts as already gone
//!
//! Errors are `{"error": "…", "status": N}`. `429` is retried with backoff a few times, and `5xx` too
//! except after a POST (the create may have happened).
//!
//! **The API key** is an [`ApiKey`]: it prints as `[redacted]`, goes only into the `Authorization`
//! header, never into a URL, an error or a log. The CLI reads it from wicket's vault by name.
//!
//! **Isolation.** Vultr cloud compute exposes no KVM (docs/explanation/research/10-infrastructure.md), so its
//! nodes offer gVisor at most; a request for `vm` gets no Vultr offer and becomes a request for a
//! KVM host elsewhere (#7).

use crate::billing::{BillingModel, VULTR_MONTHLY_CAP_HOURS};
use crate::model::*;
use crate::money::MicroUsd;
use anyhow::{bail, Context};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const API_BASE: &str = "https://api.vultr.com/v2";
/// Vultr's os_id for Ubuntu 24.04 LTS x64, what `deploy/vultr/node-setup.sh` targets. Check with
/// `GET /os` before relying on it; it is configurable.
pub const UBUNTU_2404_OS_ID: u32 = 2284;

/// A Vultr API key. Never printed.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(s: impl Into<String>) -> ApiKey {
        ApiKey(s.into().trim().to_string())
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey([redacted])")
    }
}

/// An API error: the status and Vultr's message (never the request).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Vultr API {method} {path}: HTTP {status}: {message}")]
pub struct ApiError {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Plan {
    pub id: String,
    #[serde(default)]
    pub vcpu_count: u32,
    /// MB.
    #[serde(default)]
    pub ram: u64,
    #[serde(default)]
    pub disk: u64,
    #[serde(default)]
    pub monthly_cost: f64,
    #[serde(default)]
    pub hourly_cost: Option<f64>,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub locations: Vec<String>,
}

impl Plan {
    /// `hourly_cost` if the API gives one, else `monthly_cost / 672` (the monthly cap; a $40 plan bills
    /// $0.0595/h on our own invoices), rounded up.
    pub fn hourly_rate(&self) -> MicroUsd {
        match self.hourly_cost {
            Some(h) if h > 0.0 => MicroUsd::from_dollars_f64(h),
            _ => MicroUsd::from_dollars_f64(self.monthly_cost).mul_div_ceil(1, VULTR_MONTHLY_CAP_HOURS),
        }
    }

    pub fn billing(&self) -> BillingModel {
        BillingModel::vultr(self.hourly_rate())
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Instance {
    pub id: String,
    #[serde(default)]
    pub main_ip: String,
    #[serde(default)]
    pub date_created: String,
    /// `pending`, `active`, `suspended`, `resizing`.
    #[serde(default)]
    pub status: String,
    /// `running`, `stopped`.
    #[serde(default)]
    pub power_status: String,
    /// `none`, `locked`, `installingbooting`, `ok`.
    #[serde(default)]
    pub server_status: String,
    #[serde(default)]
    pub plan: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub vcpu_count: u32,
    #[serde(default)]
    pub ram: u64,
}

impl Instance {
    /// Active, running and addressed. `server_status` is left out on purpose: the ssh probe after this
    /// (node setup finished, pinned host key) is the real readiness gate.
    pub fn is_ready(&self) -> bool {
        self.status == "active" && self.power_status == "running" && self.has_ip()
    }

    fn has_ip(&self) -> bool {
        !self.main_ip.is_empty() && self.main_ip != "0.0.0.0"
    }

    pub fn created_at(&self) -> Option<Timestamp> {
        time::OffsetDateTime::parse(&self.date_created, &time::format_description::well_known::Rfc3339).ok().map(|t| t.unix_timestamp())
    }
}

/// The body of `POST /instances`.
#[derive(Clone, Debug, Serialize)]
pub struct CreateInstance {
    pub region: String,
    pub plan: String,
    pub os_id: u32,
    pub label: String,
    pub hostname: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sshkey_id: Vec<String>,
    /// Base64, as the API wants it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
    pub backups: &'static str,
    pub enable_ipv6: bool,
    pub activation_email: bool,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(default)]
    links: Links,
}

#[derive(Default, Deserialize)]
struct Links {
    #[serde(default)]
    next: String,
}

#[derive(Clone, Debug)]
pub struct Retry {
    pub attempts: u32,
    pub base: Duration,
}

impl Default for Retry {
    fn default() -> Retry {
        Retry { attempts: 4, base: Duration::from_millis(500) }
    }
}

/// Vultr API v2 client.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    key: ApiKey,
    retry: Retry,
    per_page: u32,
}

impl Client {
    pub fn new(key: ApiKey) -> anyhow::Result<Client> {
        Client::with_base(API_BASE, key)
    }

    /// A client for another base URL (a mock server in tests).
    pub fn with_base(base: &str, key: ApiKey) -> anyhow::Result<Client> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(60)).user_agent("wicket-placement").build()?;
        Ok(Client { http, base: base.trim_end_matches('/').to_string(), key, retry: Retry::default(), per_page: 100 })
    }

    pub fn with_retry(mut self, retry: Retry) -> Self {
        self.retry = retry;
        self
    }

    pub fn with_per_page(mut self, n: u32) -> Self {
        self.per_page = n.clamp(1, 500);
        self
    }

    /// One request, retried on 429 and 5xx. Returns None for 404 (the caller decides what that means).
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&serde_json::Value>,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let url = format!("{}{}", self.base, path);
        let mut attempt = 0;
        loop {
            let mut rq = self.http.request(method.clone(), &url).bearer_auth(&self.key.0).query(query);
            if let Some(b) = body {
                rq = rq.json(b);
            }
            // reqwest's errors carry the URL, which never holds the key; strip it anyway to keep logs short.
            let resp = rq.send().await.map_err(|e| anyhow::anyhow!("Vultr API {method} {path}: {}", e.without_url()))?;
            let status = resp.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            // A 5xx after a POST may follow a create that happened: retrying could make a second
            // instance. The next acquire finds the first by its idempotency tag instead.
            let retryable =
                status == reqwest::StatusCode::TOO_MANY_REQUESTS || (status.is_server_error() && method != reqwest::Method::POST);
            if retryable && attempt + 1 < self.retry.attempts {
                tokio::time::sleep(self.retry.base * 2u32.pow(attempt)).await;
                attempt += 1;
                continue;
            }
            let text = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                let message = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
                    .unwrap_or_else(|| text.chars().take(200).collect());
                return Err(ApiError { method: method.to_string(), path: path.to_string(), status: status.as_u16(), message }.into());
            }
            if text.trim().is_empty() {
                return Ok(Some(serde_json::Value::Null));
            }
            return Ok(Some(serde_json::from_str(&text).with_context(|| format!("Vultr API {method} {path}: response is not JSON"))?));
        }
    }

    /// Every page of a listing: `field` from each, following `meta.links.next`.
    async fn paged<T: for<'de> Deserialize<'de>>(&self, path: &str, field: &str, query: &[(&str, String)]) -> anyhow::Result<Vec<T>> {
        let mut out = vec![];
        let mut cursor = String::new();
        for _ in 0..1000 {
            let mut q = query.to_vec();
            q.push(("per_page", self.per_page.to_string()));
            if !cursor.is_empty() {
                q.push(("cursor", cursor.clone()));
            }
            let v = self.call(reqwest::Method::GET, path, &q, None).await?.with_context(|| format!("Vultr API GET {path}: not found"))?;
            let items: Vec<T> = serde_json::from_value(v.get(field).cloned().unwrap_or(serde_json::Value::Array(vec![])))
                .with_context(|| format!("Vultr API GET {path}: unexpected {field}"))?;
            out.extend(items);
            let meta: Option<Meta> = v.get("meta").cloned().and_then(|m| serde_json::from_value(m).ok());
            cursor = meta.map(|m| m.links.next).unwrap_or_default();
            if cursor.is_empty() {
                return Ok(out);
            }
        }
        bail!("Vultr API GET {path}: too many pages")
    }

    pub async fn list_plans(&self, kind: &str) -> anyhow::Result<Vec<Plan>> {
        self.paged("/plans", "plans", &[("type", kind.to_string())]).await
    }

    pub async fn create_instance(&self, body: &CreateInstance) -> anyhow::Result<Instance> {
        let v = self
            .call(reqwest::Method::POST, "/instances", &[], Some(&serde_json::to_value(body)?))
            .await?
            .context("Vultr API POST /instances: 404")?;
        serde_json::from_value(v.get("instance").cloned().context("Vultr API POST /instances: no instance in the response")?)
            .context("Vultr API POST /instances: unexpected instance")
    }

    pub async fn get_instance(&self, id: &str) -> anyhow::Result<Option<Instance>> {
        let path = format!("/instances/{}", path_segment(id)?);
        match self.call(reqwest::Method::GET, &path, &[], None).await? {
            None => Ok(None),
            Some(v) => Ok(Some(serde_json::from_value(v.get("instance").cloned().context("no instance in the response")?)?)),
        }
    }

    pub async fn list_instances(&self, tag: Option<&str>) -> anyhow::Result<Vec<Instance>> {
        let q: Vec<(&str, String)> = tag.map(|t| vec![("tag", t.to_string())]).unwrap_or_default();
        self.paged("/instances", "instances", &q).await
    }

    /// Replaces the instance's user data (base64-encoded here).
    pub async fn set_user_data(&self, id: &str, user_data: &str) -> anyhow::Result<()> {
        let path = format!("/instances/{}", path_segment(id)?);
        let b = serde_json::json!({ "user_data": base64::engine::general_purpose::STANDARD.encode(user_data) });
        self.call(reqwest::Method::PATCH, &path, &[], Some(&b)).await?.with_context(|| format!("no instance {id}"))?;
        Ok(())
    }

    /// Deletes an instance. Returns false if it was already gone.
    pub async fn delete_instance(&self, id: &str) -> anyhow::Result<bool> {
        let path = format!("/instances/{}", path_segment(id)?);
        Ok(self.call(reqwest::Method::DELETE, &path, &[], None).await?.is_some())
    }
}

/// Instance ids are UUIDs; anything that could change the path is refused.
fn path_segment(id: &str) -> anyhow::Result<&str> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("{id:?} is not a Vultr instance id");
    }
    Ok(id)
}

/// Settings for nodes this installation creates on Vultr.
#[derive(Clone, Debug)]
pub struct VultrConfig {
    pub os_id: u32,
    /// Ids of ssh keys already in the Vultr account, installed for root (node-setup.sh copies them to
    /// the `wicket` user).
    pub sshkey_ids: Vec<String>,
    /// Plan family to offer (`vc2` regular, `vhp` high performance, …).
    pub plan_type: String,
    /// Region when a request gives none.
    pub default_region: String,
    /// The login wicket uses on its nodes.
    pub ssh_user: String,
}

impl Default for VultrConfig {
    fn default() -> VultrConfig {
        VultrConfig {
            os_id: UBUNTU_2404_OS_ID,
            sshkey_ids: vec![],
            plan_type: "vc2".into(),
            default_region: "lhr".into(),
            ssh_user: "wicket".into(),
        }
    }
}

pub struct VultrProvider {
    client: Client,
    config: VultrConfig,
    plans: tokio::sync::Mutex<Option<Vec<Plan>>>,
}

impl VultrProvider {
    pub fn new(client: Client, config: VultrConfig) -> VultrProvider {
        VultrProvider { client, config, plans: tokio::sync::Mutex::new(None) }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Every plan (all families, so any owned instance can be priced), fetched once.
    pub async fn plans(&self) -> anyhow::Result<Vec<Plan>> {
        let mut p = self.plans.lock().await;
        if p.is_none() {
            *p = Some(self.client.list_plans("all").await?);
        }
        Ok(p.clone().unwrap_or_default())
    }

    fn handle(&self, i: &Instance, plans: &[Plan]) -> NodeHandle {
        let plan = plans.iter().find(|p| p.id == i.plan);
        // Every plan family is fetched, so this misses only a plan Vultr no longer lists; that node is
        // still listed (the reconciler must see it), priced at zero.
        let billing = plan.map(Plan::billing).unwrap_or(BillingModel::vultr(MicroUsd::ZERO));
        let state = match i.status.as_str() {
            _ if i.is_ready() => NodeState::Active,
            "active" | "pending" | "resizing" | "suspended" => NodeState::Pending,
            _ => NodeState::Gone,
        };
        NodeHandle {
            id: NodeId(i.id.clone()),
            backend: "vultr".into(),
            name: i.label.clone(),
            ssh_target: i.has_ip().then(|| format!("{}@{}", self.config.ssh_user, i.main_ip)),
            region: Some(i.region.clone()),
            plan: Some(i.plan.clone()),
            isolation: IsolationTier::Gvisor,
            resources: Resources { vcpus: i.vcpu_count, memory_mib: i.ram },
            billing,
            created_at: i.created_at().unwrap_or_else(now),
            lease_until: Owner::lease_from_tags(&i.tags),
            host_key: None,
            tags: i.tags.clone(),
            state,
        }
    }

    /// Polls until the instance is active, running, installed and has an address, or `timeout`.
    pub async fn wait_active(&self, id: &NodeId, poll: Duration, timeout: Duration) -> anyhow::Result<NodeHandle> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let i = self.client.get_instance(&id.0).await?.with_context(|| format!("instance {id} disappeared while booting"))?;
            if i.is_ready() {
                let plans = self.plans().await?;
                return Ok(self.handle(&i, &plans));
            }
            if tokio::time::Instant::now() + poll > deadline {
                bail!(
                    "instance {id} is not active after {:?} (status {}, power {}, server {})",
                    timeout,
                    i.status,
                    i.power_status,
                    i.server_status
                );
            }
            tokio::time::sleep(poll).await;
        }
    }
}

impl Provider for VultrProvider {
    fn id(&self) -> &str {
        "vultr"
    }

    async fn offers(&self, req: &CapacityRequest) -> anyhow::Result<Vec<Offer>> {
        if req.min_isolation > IsolationTier::Gvisor {
            return Ok(vec![]); // no KVM on Vultr cloud compute
        }
        let region = req.region_hint.clone().unwrap_or_else(|| self.config.default_region.clone());
        Ok(self
            .plans()
            .await?
            .into_iter()
            .filter(|p| p.kind == self.config.plan_type && p.locations.contains(&region))
            .map(|p| Offer {
                plan: p.id.clone(),
                region: Some(region.clone()),
                resources: Resources { vcpus: p.vcpu_count, memory_mib: p.ram },
                isolation: IsolationTier::Gvisor,
                billing: p.billing(),
            })
            .collect())
    }

    async fn create(&self, spec: &CreateSpec) -> anyhow::Result<NodeHandle> {
        let body = CreateInstance {
            region: spec.offer.region.clone().unwrap_or_else(|| self.config.default_region.clone()),
            plan: spec.offer.plan.clone(),
            os_id: self.config.os_id,
            label: spec.name.clone(),
            hostname: spec.name.clone(),
            tags: spec.tags.clone(),
            sshkey_id: self.config.sshkey_ids.clone(),
            user_data: spec.boot.as_ref().map(|b| base64::engine::general_purpose::STANDARD.encode(&b.user_data)),
            backups: "disabled",
            enable_ipv6: false,
            activation_email: false,
        };
        let i = self.client.create_instance(&body).await?;
        let plans = self.plans().await?;
        let mut n = self.handle(&i, &plans);
        // The create response may omit what we sent; what we sent is what it has.
        if n.tags.is_empty() {
            n.tags = spec.tags.clone();
            n.lease_until = Owner::lease_from_tags(&n.tags);
        }
        n.billing = spec.offer.billing;
        n.host_key = spec.boot.as_ref().map(|b| b.host_key.clone());
        Ok(n)
    }

    async fn get(&self, id: &NodeId) -> anyhow::Result<Option<NodeHandle>> {
        let Some(i) = self.client.get_instance(&id.0).await? else { return Ok(None) };
        let plans = self.plans().await?;
        Ok(Some(self.handle(&i, &plans)))
    }

    async fn list_tagged(&self, tag: &str) -> anyhow::Result<Vec<NodeHandle>> {
        let instances = self.client.list_instances(Some(tag)).await?;
        let plans = self.plans().await?;
        // The API filters by tag; check again so a filter that is ignored can't widen what we touch.
        Ok(instances.iter().filter(|i| i.tags.iter().any(|t| t == tag)).map(|i| self.handle(i, &plans)).collect())
    }

    async fn destroy(&self, id: &NodeId) -> anyhow::Result<()> {
        self.client.delete_instance(&id.0).await?;
        Ok(())
    }
}

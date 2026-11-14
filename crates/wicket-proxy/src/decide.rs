//! Where the egress proxy's decisions come from (#57). The proxy itself (CONNECT, TLS, canonical
//! paths, forwarding, the problem texts) is the same everywhere; only the decision differs:
//!
//! - [`Central`]: the control host's ledger, today's path and behaviour, unchanged: the zone decides
//!   by reach, else a live ledger grant is consumed, else a pending request is raised (or a recent
//!   denial repeated).
//! - [`NodeDecider`]: a remote node's verified feed replica (`wicket_feed::Replica::decide`), so a box
//!   keeps working while the control host is unreachable (#153): connected or not, everything the
//!   box's token and its live grants allow, each until its own expiry; nothing while the replica is
//!   lagging or closed. The feed carries each box's authority as a Biscuit token chain
//!   (`wicket_feed::token`), loaded once. A request that needs a grant is put to the control host
//!   (which raises the pending request, so `wicket pending` and `wicket approve` work as usual) when
//!   the node is connected; when it isn't, the ask is queued on the node and raised when the
//!   control host is back (no approvals on the node alone). Grant uses are counted on the node, for
//!   its boxes only. Hosts the box's token allows wholesale are spliced through unless the replica
//!   is lagging or closed, and inspected otherwise (#141).

use crate::RunCtx;
use futures_util::future::BoxFuture;
use std::sync::{Arc, Mutex};
use wicket_core::{HostVerdict, Op, Verdict, ZoneSpec};
use wicket_feed::{Allowed, BoxAuthority, Decision, Mode, Replica};

/// What the egress proxy does with one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Forward it; the detail goes to the event log.
    Allow(String),
    /// Never allowed.
    Forbidden(String),
    /// Out of reach, and this run doesn't escalate (a program with `on_pending: fail`).
    NoEscalation(String),
    /// A human denied exactly this request recently.
    Denied { request: String },
    /// Waiting for a human: `request` is the pending request's id; `fresh` if this ask created it.
    Pending { request: String, fresh: bool, why: String },
    /// Queued on the node while the control host is unreachable (#153): `id` is node-local, and the
    /// ask is raised when the control host is back.
    Queued { id: String, why: String },
    /// The node can't decide this now (lagging or closed policy, or the control host is unreachable).
    Unavailable(String),
    /// The decision itself failed (a ledger error).
    Error(String),
}

/// A source of egress decisions. `who` is the untrusted attribution of the request (JSON and a
/// one-line summary), for humans only.
pub trait Decider: Send + Sync {
    /// The verdict on a host before any request to it (and before TLS).
    fn host_verdict(&self, ctx: &RunCtx, host: &str) -> HostVerdict;
    /// The outcome for one request.
    fn decide<'a>(&'a self, ctx: &'a RunCtx, op: &'a Op, who: Option<&'a (serde_json::Value, String)>) -> BoxFuture<'a, Outcome>;
    /// Why `op` is never allowed, if it is: what [`Decider::decide`] would answer `Forbidden`, found
    /// without asking anyone, raising a request or spending a grant. A push's ref paths are put
    /// through this before the push is decided (#26): a protected ref is refused before it is asked
    /// about. None for anything else, including what can't be decided right now.
    fn refuses(&self, ctx: &RunCtx, op: &Op) -> Option<String>;
    /// The reach rule that allows `host` wholesale, if connections to it may be spliced through
    /// without inspection (#62): every request to it would be allowed, with no credential. None
    /// (the default) means every request is decided on its own.
    fn splice(&self, _ctx: &RunCtx, _host: &str) -> Option<usize> {
        None
    }
    /// Why a spliced connection to `host` is cut, once [`Decider::splice`] no longer allows it.
    fn splice_lost(&self, _ctx: &RunCtx, _host: &str) -> String {
        "the host is no longer allowed wholesale".into()
    }
    /// What the audit row of a spliced connection adds about where it was decided.
    fn splice_note(&self) -> &'static str {
        ""
    }
}

/// The control host's ledger: the decision every local run gets.
pub struct Central;

impl Decider for Central {
    fn host_verdict(&self, ctx: &RunCtx, host: &str) -> HostVerdict {
        ctx.zone.host_verdict(host)
    }

    fn decide<'a>(&'a self, ctx: &'a RunCtx, op: &'a Op, who: Option<&'a (serde_json::Value, String)>) -> BoxFuture<'a, Outcome> {
        Box::pin(async move { central(ctx, op, who) })
    }

    fn refuses(&self, ctx: &RunCtx, op: &Op) -> Option<String> {
        if let Some(why) = ctx.org.as_ref().and_then(|o| o.refuses_http(&op.host, &op.method, &op.path, op.risk.rank())) {
            return Some(why);
        }
        match ctx.zone.evaluate(op) {
            Verdict::Forbidden(why) => Some(why),
            _ => None,
        }
    }

    /// The zone alone decides (a reach allow comes before grants, denials and pending requests).
    /// Under an org policy (#51), only a host it allows wholesale (its rules can depend on any path).
    fn splice(&self, ctx: &RunCtx, host: &str) -> Option<usize> {
        if ctx.org.as_ref().is_some_and(|o| !o.allows_host_wholesale(host)) {
            return None;
        }
        match wicket_core::splice::inspection(ctx.zone.spec(), host) {
            wicket_core::splice::Inspection::Spliced { rule } => Some(rule),
            wicket_core::splice::Inspection::Inspected(_) => None,
        }
    }
}

fn central(ctx: &RunCtx, op: &Op, who: Option<&(serde_json::Value, String)>) -> Outcome {
    // The org layer first: hard, no grant lifts it (#51; on a node the token's org checks do this).
    if let Some(why) = ctx.org.as_ref().and_then(|o| o.refuses_http(&op.host, &op.method, &op.path, op.risk.rank())) {
        return Outcome::Forbidden(why);
    }
    let why = match ctx.zone.evaluate(op) {
        Verdict::AllowByReach(i) => return Outcome::Allow(format!("reach rule {i}")),
        Verdict::Forbidden(why) => return Outcome::Forbidden(why),
        Verdict::NeedsGrant(why) if !ctx.escalate => return Outcome::NoEscalation(why),
        Verdict::NeedsGrant(why) => wicket_core::git::ask_reason(op, &why),
    };
    let mut ledger = ctx.ledger.lock().expect("ledger lock");
    match ledger.consume_grant(op) {
        Ok(Some(gid)) => {
            let approved_for: Vec<String> = ledger
                .request_for_grant(&gid)
                .ok()
                .flatten()
                .map(|r| r.attribution.iter().flat_map(crate::attributed_agents).collect())
                .unwrap_or_default();
            drop(ledger);
            let mut detail = format!("grant {gid}");
            if let Some((v, line)) = who {
                detail.push_str(&format!("; used by {line}"));
                let users = crate::attributed_agents(v);
                // The grant is usable by anything in the box; flag use by someone else.
                if !approved_for.is_empty() && !users.is_empty() && !users.iter().any(|u| approved_for.contains(u)) {
                    detail.push_str(&format!("; WARNING: approved for {}", approved_for.join(" | ")));
                }
            }
            Outcome::Allow(detail)
        }
        Ok(None) => {
            if let Ok(Some(rid)) = ledger.denied_recently(op) {
                return Outcome::Denied { request: rid };
            }
            match ledger.pending_for(op, &why, who.map(|(v, _)| v)) {
                Ok((rid, fresh)) => Outcome::Pending { request: rid, fresh, why },
                Err(e) => Outcome::Error(e.to_string()),
            }
        }
        Err(e) => Outcome::Error(e.to_string()),
    }
}

/// The control host's answer when a node asks it to raise a pending request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asked {
    Pending { request: String, fresh: bool },
    Denied { request: String },
}

/// A node's link to the control host, as the decider needs it.
pub trait ControlLink: Send + Sync {
    /// Whether the control channel is up right now.
    fn connected(&self) -> bool;
    /// Asks the control host to raise (or find) the pending request for `op`.
    fn ask<'a>(&'a self, op: &'a Op, why: &'a str, who: Option<&'a serde_json::Value>) -> BoxFuture<'a, Result<Asked, String>>;
    /// Queues the ask on the node while the control host is unreachable (#153), to be raised when it
    /// is back: the ask's node-local id. The default queues nothing.
    fn queue(&self, _op: &Op, _why: &str, _who: Option<&serde_json::Value>) -> Result<String, String> {
        Err("no ask queue".into())
    }
}

/// The node's clock for feed decisions (Unix ms, see `wicket-cli`'s node clock: wall time anchored
/// once, advanced by a monotonic clock).
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// What the agent is told when the node can't reach the control host to escalate.
pub const UNREACHABLE: &str = "wicket's control plane is unreachable from this node, so nothing new can be approved right now; retry later";

/// Decisions from a node's verified feed replica.
pub struct NodeDecider {
    pub replica: Arc<Mutex<Replica<BoxAuthority>>>,
    pub clock: Clock,
    pub control: Arc<dyn ControlLink>,
}

impl NodeDecider {
    fn decide_now(&self, op: &Op) -> Decision {
        let now = (self.clock)();
        self.replica.lock().expect("replica").decide(op, now)
    }
}

/// The text for a refusal in a mode that isn't fresh.
pub fn stale_text(mode: Mode, why: &str) -> String {
    match mode {
        Mode::Lagging => format!("this node is catching up with wicket's policy feed ({why}); retry in a moment"),
        Mode::Closed => format!("this node holds no valid policy from wicket's control plane ({why}); retry later"),
        Mode::Fresh | Mode::Offline => why.to_string(),
    }
}

impl Decider for NodeDecider {
    fn host_verdict(&self, ctx: &RunCtx, host: &str) -> HostVerdict {
        // An early refusal from the zone the box's token was minted from; the token decides each
        // request. No (valid) token for the box: the request itself is refused by `decide`.
        self.replica.lock().expect("replica").host_verdict(&ctx.run.0, host)
    }

    fn decide<'a>(&'a self, ctx: &'a RunCtx, op: &'a Op, who: Option<&'a (serde_json::Value, String)>) -> BoxFuture<'a, Outcome> {
        Box::pin(async move {
            let decision = match self.decide_now(op) {
                Decision::NeedsGrant(why) => Decision::NeedsGrant(wicket_core::git::ask_reason(op, &why)),
                d => d,
            };
            match decision {
                Decision::Allow(Allowed::Reach(i)) => Outcome::Allow(format!("reach rule {i} (node)")),
                Decision::Allow(Allowed::Ceiling) => Outcome::Allow("the box's token (node)".into()),
                Decision::Allow(Allowed::Grant(g)) => Outcome::Allow(format!("grant {g} (counted on the node)")),
                Decision::Allow(other) => Outcome::Allow(format!("{other:?}")),
                Decision::Forbidden(why) => Outcome::Forbidden(why),
                Decision::Refused { mode, why } => Outcome::Unavailable(stale_text(mode, &why)),
                Decision::NeedsGrant(why) if !ctx.escalate => Outcome::NoEscalation(why),
                Decision::NeedsGrant(why) if !self.control.connected() => match self.control.queue(op, &why, who.map(|(v, _)| v)) {
                    Ok(id) => Outcome::Queued { id, why },
                    Err(_) => Outcome::Unavailable(UNREACHABLE.into()),
                },
                Decision::NeedsGrant(why) => match self.control.ask(op, &why, who.map(|(v, _)| v)).await {
                    Ok(Asked::Pending { request, fresh }) => Outcome::Pending { request, fresh, why },
                    Ok(Asked::Denied { request }) => Outcome::Denied { request },
                    // The link looked up but the control host didn't answer (a partition the node
                    // hasn't noticed yet): queued, as when it is known to be down (#153).
                    Err(_) => match self.control.queue(op, &why, who.map(|(v, _)| v)) {
                        Ok(id) => Outcome::Queued { id, why },
                        Err(_) => Outcome::Unavailable(UNREACHABLE.into()),
                    },
                },
            }
        })
    }

    /// From the box's token, as `decide` reads it, without recording a grant use ([`Replica::peek`]).
    fn refuses(&self, _ctx: &RunCtx, op: &Op) -> Option<String> {
        let now = (self.clock)();
        match self.replica.lock().expect("replica").peek(op, now) {
            Decision::Forbidden(why) => Some(why),
            _ => None,
        }
    }

    fn splice(&self, ctx: &RunCtx, host: &str) -> Option<usize> {
        self.splice_now(ctx, host)
    }

    fn splice_lost(&self, _ctx: &RunCtx, _host: &str) -> String {
        let mode = self.replica.lock().expect("replica").mode((self.clock)());
        match mode {
            Mode::Fresh | Mode::Offline => "the box's authority on this node no longer allows the host wholesale".into(),
            Mode::Lagging => "this node is catching up with its policy feed (nothing is allowed until it has)".into(),
            Mode::Closed => "this node's policy is closed (nothing is allowed until the control host returns)".into(),
        }
    }

    fn splice_note(&self) -> &'static str {
        " (on the node)"
    }
}

/// Splicing on a node (#141): only while the replica is fresh, and only if the box's token allows
/// the host for every method and path ([`Replica::<BoxAuthority>::splice`]). Narrow and closed
/// decide each request (plain reads, then nothing), which a hostname can't carry, so a node in
/// those modes inspects, and cuts the connections it spliced at the next check.
impl NodeDecider {
    fn splice_now(&self, ctx: &RunCtx, host: &str) -> Option<usize> {
        let now = (self.clock)();
        self.replica.lock().expect("replica").splice(&ctx.tenant, &ctx.run.0, host, now)
    }
}

/// Where a node's egress proxy sends a CONNECT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// Terminate TLS here with the node CA, and decide here.
    Terminate,
    /// Tunnel the raw CONNECT to the control host's egress proxy, which decides and terminates TLS
    /// with the run's own CA (the box trusts both). The reason is logged.
    Forward(String),
}

/// Whether a host is inside one X.509 permitted DNS subtree, as a verifier reads it: `api.example.com`
/// permits itself and every name under it; `.example.org` permits names under it, not the apex.
pub fn subtree_permits(subtree: &str, host: &str) -> bool {
    // The control host's own node's CA: any name.
    if subtree == "*" {
        return true;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let subtree = subtree.to_ascii_lowercase();
    match subtree.strip_prefix('.') {
        Some(base) => host.len() > base.len() + 1 && host.ends_with(&subtree),
        None => host == subtree || host.ends_with(&format!(".{subtree}")),
    }
}

/// The node's forwarding rule. It never terminates TLS for:
/// - a host with an `inject` rule whose secret isn't sealed to the node ([`route_sealed`]), or a
///   credential swap;
/// - a host outside the node CA's name constraints (e.g. one approved later under
///   `unlisted_hosts: escalate`): a leaf for it wouldn't verify anyway;
/// - anything at all once the node CA has expired, or without one: never mint.
pub fn route(host: &str, zone: &ZoneSpec, swaps: &[crate::CredentialSwap], ca: Option<(&[String], i64)>, now_secs: i64) -> Route {
    route_sealed(host, zone, swaps, ca, now_secs, &|_| false)
}

/// [`route`] on a node that holds some secrets sealed to it (#152): a host whose `inject` rules all
/// name a secret the node holds (`held`) is terminated and injected on the node, within the CA's
/// constraints like any other.
pub fn route_sealed(
    host: &str,
    zone: &ZoneSpec,
    swaps: &[crate::CredentialSwap],
    ca: Option<(&[String], i64)>,
    now_secs: i64,
    held: &dyn Fn(&str) -> bool,
) -> Route {
    use wicket_core::manifest::host_matches;
    if zone.inject.iter().any(|r| host_matches(&r.host, host) && !held(&r.secret)) {
        return Route::Forward("the zone injects a credential for this host".into());
    }
    if swaps.iter().any(|s| host_matches(&s.host, host)) {
        return Route::Forward("a credential is swapped for this host".into());
    }
    match ca {
        None => Route::Forward("this node has no CA".into()),
        Some((_, not_after)) if now_secs >= not_after => Route::Forward("the node CA has expired".into()),
        Some((permitted, _)) if !permitted.iter().any(|s| subtree_permits(s, host)) => {
            Route::Forward("outside the node CA's name constraints".into())
        }
        Some(_) => Route::Terminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
    use wicket_core::{Manifest, RunId, TenantId};
    use wicket_feed::{Change, Issuer, KeyCert, LiveGrant, Publisher, PublisherConfig, ReplicaConfig};

    fn zone() -> ZoneSpec {
        Manifest::from_yaml(
            "task: t\nprogram: { name: p, command: [x], on_pending: wait }\nzone:\n  name: z\n  reach:\n    - { host: api.example.com, methods: [GET, POST], paths: [\"/v1/**\"] }\n  inject:\n    - { host: secret.example.com, header: authorization, format: \"Bearer {secret}\", secret: s }\n",
        )
        .unwrap()
        .zone
    }

    /// #51: the control host decides hosts it forwards for (credentials injected here) and its own
    /// boxes' egress: the org layer refuses there too, hard, and nothing splices under it.
    #[test]
    fn the_org_layer_refuses_on_the_control_host_and_stops_splicing() {
        use wicket_authz::{HostPat, HttpMatch, OrgLayer, PathPat};
        let op = |m: &str, h: &str, p: &str| Op::egress(&TenantId::single(), &RunId("run_a".into()), "z", m, h, p);
        let mut c = ctx(true);
        // Without an org layer: the zone allows this.
        assert!(matches!(central(&c, &op("GET", "api.example.com", "/v1/x"), None), Outcome::Allow(_)));
        c.org = Some(Arc::new(OrgLayer {
            version: "v1".into(),
            http: None,
            forbid: vec![
                HttpMatch {
                    hosts: vec![HostPat::Exact("api.example.com".into())],
                    paths: vec![PathPat::Glob("/v1/admin/**".into())],
                    ..Default::default()
                },
                HttpMatch { hosts: vec![HostPat::Exact("secret.example.com".into())], ..Default::default() },
            ],
            spawn: None,
            msg_from: None,
            inject: None,
        }));
        assert!(matches!(central(&c, &op("GET", "api.example.com", "/v1/x"), None), Outcome::Allow(_)), "other paths still allowed");
        assert!(
            matches!(central(&c, &op("GET", "api.example.com", "/v1/admin/users"), None), Outcome::Forbidden(w) if w.contains("org policy"))
        );
        // The host the zone injects into, forwarded to the control host: refused, not a grant away.
        assert!(matches!(central(&c, &op("GET", "secret.example.com", "/"), None), Outcome::Forbidden(w) if w.contains("org policy")));
        assert_eq!(Central.splice(&c, "api.example.com"), None, "not a host the org layer allows wholesale");
    }

    #[test]
    fn subtrees_match_like_a_verifier() {
        // The same lists as ca.rs's verifier test, which checks these against webpki.
        for (st, host) in [
            ("api.example.com", "api.example.com"),
            ("api.example.com", "x.api.example.com"),
            (".example.org", "www.example.org"),
            (".example.org", "a.b.example.org"),
        ] {
            assert!(subtree_permits(st, host), "{st} {host}");
        }
        for (st, host) in [
            ("api.example.com", "evil.example.net"),
            ("api.example.com", "example.com"),
            (".example.org", "example.org"),
            ("api.example.com", "api.example.com.evil.example.net"),
            ("api.example.com", "xapi.example.com"),
        ] {
            assert!(!subtree_permits(st, host), "{st} {host}");
        }
    }

    #[test]
    fn the_node_forwards_secret_hosts_out_of_constraint_hosts_and_everything_once_its_ca_expires() {
        let z = zone();
        let permitted = ["api.example.com".to_string(), "secret.example.com".to_string()];
        let ca = Some((&permitted[..], 2_000));
        assert_eq!(route("api.example.com", &z, &[], ca, 1_000), Route::Terminate);
        assert!(matches!(route("secret.example.com", &z, &[], ca, 1_000), Route::Forward(r) if r.contains("injects")));
        let swap = crate::CredentialSwap {
            box_bearers: false,
            name: "login".into(),
            host: "api.example.com".into(),
            placeholder: "p".into(),
            real: crate::SwapSource::Value("v".into()),
        };
        assert!(matches!(route("api.example.com", &z, &[swap], ca, 1_000), Route::Forward(r) if r.contains("swapped")));
        assert!(matches!(route("later.example.net", &z, &[], ca, 1_000), Route::Forward(r) if r.contains("name constraints")));
        assert!(matches!(route("api.example.com", &z, &[], ca, 2_000), Route::Forward(r) if r.contains("expired")));
        assert!(matches!(route("api.example.com", &z, &[], None, 0), Route::Forward(_)));
        // #152: a node holding the injected secret sealed to it terminates and injects itself.
        let held = |n: &str| n == "s";
        let wide = Some((&[".example.com".to_string()][..], 1_500));
        assert_eq!(route_sealed("secret.example.com", &z, &[], wide, 1_000, &held), Route::Terminate);
        assert!(matches!(route_sealed("secret.example.com", &z, &[], wide, 1_000, &|_| false), Route::Forward(r) if r.contains("injects")));
    }

    struct Link {
        up: AtomicBool,
        asks: AtomicI64,
    }

    impl ControlLink for Link {
        fn connected(&self) -> bool {
            self.up.load(Ordering::SeqCst)
        }
        fn ask<'a>(&'a self, _op: &'a Op, _why: &'a str, _who: Option<&'a serde_json::Value>) -> BoxFuture<'a, Result<Asked, String>> {
            let n = self.asks.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(Asked::Pending { request: format!("r-{n}"), fresh: true }) })
        }
        fn queue(&self, _op: &Op, _why: &str, _who: Option<&serde_json::Value>) -> Result<String, String> {
            Ok("q-1".into())
        }
    }

    fn ctx(escalate: bool) -> RunCtx {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_a".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone()).unwrap()),
            org: None,
            ledger: Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap())),
            vault: crate::vault::Vault::new(std::env::temp_dir().join("wicket-decide-no-vault")),
            events: tx,
            escalate,
            attribute: None,
            identity: None,
            spawner: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            fence: None,
            waker: None,
        }
    }

    /// A publisher of box authority and a replica fed from it, with the clock in the test's hands.
    fn feed() -> (Publisher<BoxAuthority>, Arc<Mutex<Replica<BoxAuthority>>>, std::path::PathBuf, wicket_authz::SigningKey) {
        use ed25519_dalek::SigningKey;
        let dir = std::env::temp_dir().join(format!("wicket-decide-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = SigningKey::from_bytes(&[7; 32]);
        let key = SigningKey::from_bytes(&[8; 32]);
        let authz_root = wicket_authz::SigningKey::from_bytes(&[9; 32]).unwrap();
        let cert = KeyCert::new(&key.verifying_key(), 1, i64::MAX / 2, 30_000);
        let cert_jws = wicket_feed::sign(&root, wicket_feed::TYP_KEY, &cert);
        let cfg = PublisherConfig { ttl_ms: 1_000, refresh_ms: 100, retain: 100 };
        let p = Publisher::open_with(&dir, "n1", &root.verifying_key(), key, &cert_jws, cfg, authz_root.public()).unwrap();
        let r = Replica::new_with("n1", root.verifying_key(), ReplicaConfig::default(), authz_root.public());
        (p, Arc::new(Mutex::new(r)), dir, authz_root)
    }

    fn op(method: &str, path: &str) -> Op {
        Op::egress(&TenantId::single(), &RunId("run_a".into()), "z", method, "api.example.com", path)
    }

    #[tokio::test]
    async fn the_node_decider_works_offline_until_the_token_expires_and_queues_asks() {
        let (mut p, replica, dir, authz_root) = feed();
        let approver = wicket_authz::SigningKey::from_bytes(&[10; 32]).unwrap();
        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock: Clock = {
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let link = Arc::new(Link { up: AtomicBool::new(true), asks: AtomicI64::new(0) });
        let d = NodeDecider { replica: replica.clone(), clock, control: link.clone() };
        let c = ctx(true);
        let t0 = now.load(Ordering::SeqCst);
        // Closed before any feed arrives.
        assert!(matches!(d.decide(&c, &op("GET", "/v1/a"), None).await, Outcome::Unavailable(_)));
        let tenant = TenantId::single().0;
        let issuer = Issuer::root(&authz_root, &tenant, "run:run_a", "run_a", 0, &zone(), &[], 3_600, vec![approver.public()]).unwrap();
        p.commit(vec![Change::PutZone { zone: issuer.publish(&approver, &[]).unwrap() }], t0).unwrap();
        let hello = replica.lock().unwrap().hello();
        for f in p.catch_up(&hello, t0).unwrap() {
            replica.lock().unwrap().accept(&f, t0).unwrap();
        }
        // Fresh: reads and writes by the token's ceiling; out of reach is put to the control host.
        assert!(matches!(d.decide(&c, &op("GET", "/v1/a"), None).await, Outcome::Allow(t) if t.contains("token")));
        assert!(matches!(d.decide(&c, &op("POST", "/v1/a"), None).await, Outcome::Allow(_)));
        assert!(matches!(d.decide(&c, &op("GET", "/other"), None).await, Outcome::Pending { request, .. } if request == "r-0"));
        assert!(matches!(d.decide(&ctx(false), &op("GET", "/other"), None).await, Outcome::NoEscalation(_)));
        assert_eq!(d.host_verdict(&c, "169.254.169.254"), wicket_core::CompiledZone::new(zone()).unwrap().host_verdict("169.254.169.254"));
        link.up.store(false, Ordering::SeqCst);
        assert!(matches!(d.decide(&c, &op("GET", "/other"), None).await, Outcome::Queued { id, .. } if id == "q-1"));
        assert_eq!(link.asks.load(Ordering::SeqCst), 1, "queued, not asked, while disconnected");
        // Past the TTL, and long after (#153): offline, the token's authority holds, writes included,
        // until the token itself expires (block 0's not_after: 3600 s).
        for t in [t0 + 1_500, t0 + 150_000, 3_599_000] {
            now.store(t, Ordering::SeqCst);
            assert_eq!(replica.lock().unwrap().mode(t), Mode::Offline);
            assert!(matches!(d.decide(&c, &op("GET", "/v1/a"), None).await, Outcome::Allow(_)), "{t}");
            assert!(matches!(d.decide(&c, &op("POST", "/v1/a"), None).await, Outcome::Allow(_)), "{t}");
        }
        now.store(3_601_000, Ordering::SeqCst);
        assert!(matches!(d.decide(&c, &op("GET", "/v1/a"), None).await, Outcome::Forbidden(_)), "expired with its token");
        // A grant: a block appended to the box's token on the control host, its uses counted on the
        // node; a revocation applies at once.
        let t1 = t0 + 4_000;
        now.store(t1, Ordering::SeqCst);
        let g = wicket_authz::Grant {
            gid: "g-1".into(),
            box_id: String::new(),
            epoch: 0,
            host: "api.example.com".into(),
            method: "GET".into(),
            path: "/other".into(),
            not_after: 3_600,
            approver: "human:test".into(),
            digest: vec![],
        };
        let a = issuer.publish(&approver, &[LiveGrant { grant: g, uses: Some(2) }]).unwrap();
        let delta = p.commit(vec![Change::PutZone { zone: a }], t1).unwrap();
        replica.lock().unwrap().accept(&delta, t1).unwrap();
        replica.lock().unwrap().accept(&p.statement(t1), t1).unwrap();
        assert!(matches!(d.decide(&c, &op("GET", "/other"), None).await, Outcome::Allow(t) if t.contains("g-1")));
        let rev =
            p.commit(vec![Change::Revoke { kind: wicket_feed::RevokeKind::Grant, id: "g-1".into(), until: t1 + 60_000 }], t1).unwrap();
        replica.lock().unwrap().accept(&rev, t1).unwrap();
        link.up.store(true, Ordering::SeqCst);
        assert!(matches!(d.decide(&c, &op("GET", "/other"), None).await, Outcome::Pending { .. }));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #26 at the edge: on a node, from the box's token, a push is one op (its discovery and upload
    /// share one grant, which covers them until the window ends on the node's clock), and a
    /// protected ref's path is refused by the token as the zone refuses it, without asking.
    #[tokio::test]
    async fn on_a_node_a_push_is_one_op_with_a_window_and_protected_refs_are_refused_from_the_token() {
        let (mut p, replica, dir, authz_root) = feed();
        let approver = wicket_authz::SigningKey::from_bytes(&[10; 32]).unwrap();
        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock: Clock = {
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let link = Arc::new(Link { up: AtomicBool::new(true), asks: AtomicI64::new(0) });
        let d = NodeDecider { replica: replica.clone(), clock, control: link.clone() };
        let z = Manifest::from_yaml(
            "task: t\nprogram: { name: p, command: [x], on_pending: wait }\nzone:\n  name: z\n  reach:\n    - { host: github.com, methods: [GET, POST], paths: [\"/acme/app.git/info/refs\", \"/acme/app.git/git-upload-pack\"] }\n  forbid:\n    - { host: github.com, paths: [\"/**/git-receive-pack/refs/heads/main\"] }\n",
        )
        .unwrap()
        .zone;
        let mut c = ctx(true);
        c.zone = Arc::new(wicket_core::CompiledZone::new(z.clone()).unwrap());
        let t0 = now.load(Ordering::SeqCst);
        let tenant = TenantId::single();
        let issuer = Issuer::root(&authz_root, &tenant.0, "run:run_a", "run_a", 0, &z, &[], 3_600, vec![approver.public()]).unwrap();
        p.commit(vec![Change::PutZone { zone: issuer.publish(&approver, &[]).unwrap() }], t0).unwrap();
        let hello = replica.lock().unwrap().hello();
        for f in p.catch_up(&hello, t0).unwrap() {
            replica.lock().unwrap().accept(&f, t0).unwrap();
        }
        let run = RunId("run_a".into());
        let push = Op::egress(&tenant, &run, "z", "POST", "github.com", &wicket_core::git::push_op_path("/acme/app.git"));
        let fetch = Op::egress(&tenant, &run, "z", "POST", "github.com", "/acme/app.git/git-upload-pack");
        // A fetch is a read the token allows; the push is asked about, worded as a push.
        assert!(matches!(d.decide(&c, &fetch, None).await, Outcome::Allow(_)));
        assert!(
            matches!(d.decide(&c, &push, None).await, Outcome::Pending { why, .. } if why.starts_with("git push to github.com/acme/app.git"))
        );
        // Protected refs: refused by the token and by the zone alike; other refs aren't refused.
        for (name, refused) in [("refs/heads/main", true), ("refs/heads/MAIN", true), ("refs/heads/feat", false)] {
            for path in wicket_core::git::ref_paths("/acme/app", name) {
                let o = Op::egress(&tenant, &run, "z", "POST", "github.com", &path);
                assert_eq!(d.refuses(&c, &o).is_some(), refused, "node {path}");
                assert_eq!(Central.refuses(&c, &o).is_some(), refused, "zone {path}");
            }
        }
        assert_eq!(link.asks.load(Ordering::SeqCst), 1, "refusing a ref asked nothing");
        // A push grant, as the ledger makes it: no use count, until the window ends.
        let t1 = t0 + 1_000;
        now.store(t1, Ordering::SeqCst);
        let until = u64::try_from(t1 / 1000).unwrap() + wicket_core::git::PUSH_WINDOW_SECS;
        let g = wicket_authz::Grant {
            gid: "g-push".into(),
            box_id: String::new(),
            epoch: 0,
            host: "github.com".into(),
            method: "POST".into(),
            path: push.path.clone(),
            not_after: until,
            approver: "human:test".into(),
            digest: vec![],
        };
        let a = issuer.publish(&approver, &[LiveGrant { grant: g, uses: None }]).unwrap();
        let delta = p.commit(vec![Change::PutZone { zone: a }], t1).unwrap();
        replica.lock().unwrap().accept(&delta, t1).unwrap();
        for _ in 0..3 {
            assert!(matches!(d.decide(&c, &push, None).await, Outcome::Allow(t) if t.contains("g-push")));
        }
        let main = Op::egress(&tenant, &run, "z", "POST", "github.com", "/acme/app.git/git-receive-pack/refs/heads/main");
        assert!(d.refuses(&c, &main).is_some(), "no grant lifts a protected ref");
        // Past the window, on the node's clock: asked about again.
        now.store(i64::try_from(until + 1).unwrap() * 1000, Ordering::SeqCst);
        replica.lock().unwrap().accept(&p.statement(now.load(Ordering::SeqCst)), now.load(Ordering::SeqCst)).unwrap();
        assert!(matches!(d.decide(&c, &push, None).await, Outcome::Pending { .. }));
        assert_eq!(link.asks.load(Ordering::SeqCst), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_use_is_on_disk_before_the_request_goes_ahead() {
        use wicket_store::{AuditWriter, Ledger, WriterConfig};
        let dir = std::env::temp_dir().join(format!("wicket-decide-durable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ledger.db");
        let mut l = Ledger::open(&p).unwrap();
        // A long linger, so a deferred record visibly waits in the queue (a durable one or a flush cuts it short).
        let w = AuditWriter::start(&p, WriterConfig { max_batch: 512, linger: std::time::Duration::from_secs(30), retries: 5 }).unwrap();
        l.start_audit_writer(Some(w)).unwrap();
        let mut c = ctx(true);
        c.ledger = Arc::new(Mutex::new(l));
        let reader = Ledger::open(&p).unwrap();
        let ev = |detail: &str| crate::Event::Egress {
            method: "GET".into(),
            host: "api.example.com".into(),
            path: "/".into(),
            risk: "Read".into(),
            outcome: "allow".into(),
            detail: detail.into(),
        };
        c.emit(ev("reach rule 0"));
        c.emit(ev("grant g-1"));
        assert_eq!(
            reader.audit_tail(10).unwrap().len(),
            2,
            "the grant's use committed before emit returned, with what was queued before it"
        );
        c.emit(ev("reach rule 0"));
        assert_eq!(reader.audit_tail(10).unwrap().len(), 2, "a reach-allowed request doesn't wait for its record");
        c.ledger.lock().unwrap().flush_audit().unwrap();
        assert_eq!(reader.verify_audit().unwrap(), 3);
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_use_fails_closed_when_its_audit_record_cannot_be_written() {
        use wicket_store::{AuditWriter, Ledger, WriterConfig};
        let dir = std::env::temp_dir().join(format!("wicket-decide-closed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ledger.db");
        let mut l = Ledger::open(&p).unwrap();
        let w = AuditWriter::start(&p, WriterConfig { retries: 0, ..WriterConfig::default() }).unwrap();
        l.start_audit_writer(Some(w)).unwrap();
        // Every commit of an audit record fails from now on.
        rusqlite_free_fail(&p);
        let mut c = ctx(true);
        c.ledger = Arc::new(Mutex::new(l));
        let ev = |detail: &str| crate::Event::Egress {
            method: "GET".into(),
            host: "api.example.com".into(),
            path: "/".into(),
            risk: "Read".into(),
            outcome: "allow".into(),
            detail: detail.into(),
        };
        let r = c.record(ev("grant g-1"));
        assert!(r.as_ref().is_err_and(|e| e.contains("audit")), "the grant's use is refused: {r:?}");
        assert!(c.record(ev("reach rule 0")).is_ok(), "a reach-allowed request doesn't wait for its record");
        // Without a writer (an inline ledger), the same.
        let mut c2 = ctx(true);
        let l2 = Ledger::open(&p).unwrap();
        c2.ledger = Arc::new(Mutex::new(l2));
        assert!(c2.record(ev("grant g-1")).is_err());
        drop((c, c2));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Makes every insert into the audit table fail (a trigger, through the ledger's own SQL).
    fn rusqlite_free_fail(p: &std::path::Path) {
        wicket_store::Ledger::open(p).unwrap().fail_audit_inserts_for_tests().unwrap();
    }
}

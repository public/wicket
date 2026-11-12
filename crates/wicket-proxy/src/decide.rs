//! Where the egress proxy's decisions come from (#57). The proxy itself (CONNECT, TLS, canonical
//! paths, forwarding, the problem texts) is the same everywhere; only the decision differs:
//!
//! - [`Central`]: the control host's ledger, today's path and behaviour, unchanged: the zone decides
//!   by reach, else a live ledger grant is consumed, else a pending request is raised (or a recent
//!   denial repeated).
//! - [`NodeDecider`]: a remote node's verified feed replica (`wicket_feed::Replica::decide`), so a box
//!   keeps working while the control host is unreachable, failing narrow: fresh, everything the box's
//!   token and its live grants allow; narrow, plain reads (R1) only; closed, nothing. The feed
//!   carries each box's authority as a Biscuit token chain (`wicket_feed::token`), loaded once. A request that needs a
//!   grant is put to the control host (which raises the pending request, so `wicket pending` and
//!   `wicket approve` work as usual) when the node is connected; when it isn't, it fails with a clear
//!   403 and no request id. Grant uses are counted on the node, for its boxes only.

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
    /// The node can't decide this now (stale or closed policy, or the control host is unreachable).
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
}

fn central(ctx: &RunCtx, op: &Op, who: Option<&(serde_json::Value, String)>) -> Outcome {
    let why = match ctx.zone.evaluate(op) {
        Verdict::AllowByReach(i) => return Outcome::Allow(format!("reach rule {i}")),
        Verdict::Forbidden(why) => return Outcome::Forbidden(why),
        Verdict::NeedsGrant(why) if !ctx.escalate => return Outcome::NoEscalation(why),
        Verdict::NeedsGrant(why) => why,
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
        Mode::Narrow => format!(
            "wicket's control plane has been unreachable for longer than its freshness lease, so this node allows only plain reads in the zone's reach until it returns ({why}); retry later"
        ),
        Mode::Closed => format!("wicket's control plane has been unreachable too long: this node allows nothing until it returns ({why}); retry later"),
        Mode::Fresh => why.to_string(),
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
            match self.decide_now(op) {
                Decision::Allow(Allowed::Reach(i)) => Outcome::Allow(format!("reach rule {i} (node)")),
                Decision::Allow(Allowed::Ceiling) => Outcome::Allow("the box's token (node)".into()),
                Decision::Allow(Allowed::Grant(g)) => Outcome::Allow(format!("grant {g} (counted on the node)")),
                Decision::Allow(other) => Outcome::Allow(format!("{other:?}")),
                Decision::Forbidden(why) => Outcome::Forbidden(why),
                Decision::Refused { mode, why } => Outcome::Unavailable(stale_text(mode, &why)),
                Decision::NeedsGrant(why) if !ctx.escalate => Outcome::NoEscalation(why),
                Decision::NeedsGrant(_) if !self.control.connected() => Outcome::Unavailable(UNREACHABLE.into()),
                Decision::NeedsGrant(why) => match self.control.ask(op, &why, who.map(|(v, _)| v)).await {
                    Ok(Asked::Pending { request, fresh }) => Outcome::Pending { request, fresh, why },
                    Ok(Asked::Denied { request }) => Outcome::Denied { request },
                    Err(_) => Outcome::Unavailable(UNREACHABLE.into()),
                },
            }
        })
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
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let subtree = subtree.to_ascii_lowercase();
    match subtree.strip_prefix('.') {
        Some(base) => host.len() > base.len() + 1 && host.ends_with(&subtree),
        None => host == subtree || host.ends_with(&format!(".{subtree}")),
    }
}

/// The node's forwarding rule. It never terminates TLS for:
/// - a host with an `inject` rule or a credential swap (secrets stay on the control host);
/// - a host outside the node CA's name constraints (e.g. one approved later under
///   `unlisted_hosts: escalate`): a leaf for it wouldn't verify anyway;
/// - anything at all once the node CA has expired, or without one: never mint.
pub fn route(host: &str, zone: &ZoneSpec, swaps: &[crate::CredentialSwap], ca: Option<(&[String], i64)>, now_secs: i64) -> Route {
    use wicket_core::manifest::host_matches;
    if zone.inject.iter().any(|r| host_matches(&r.host, host)) {
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
            name: "login".into(),
            host: "api.example.com".into(),
            placeholder: "p".into(),
            real: crate::SwapSource::Value("v".into()),
        };
        assert!(matches!(route("api.example.com", &z, &[swap], ca, 1_000), Route::Forward(r) if r.contains("swapped")));
        assert!(matches!(route("later.example.net", &z, &[], ca, 1_000), Route::Forward(r) if r.contains("name constraints")));
        assert!(matches!(route("api.example.com", &z, &[], ca, 2_000), Route::Forward(r) if r.contains("expired")));
        assert!(matches!(route("api.example.com", &z, &[], None, 0), Route::Forward(_)));
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
    }

    fn ctx(escalate: bool) -> RunCtx {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_a".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone()).unwrap()),
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
        let cert = KeyCert::new(&key.verifying_key(), 1, i64::MAX / 2, 30_000, 120_000);
        let cert_jws = wicket_feed::sign(&root, wicket_feed::TYP_KEY, &cert);
        let cfg = PublisherConfig { ttl_ms: 1_000, refresh_ms: 100, narrow_ms: 2_000, retain: 100 };
        let p = Publisher::open_with(&dir, "n1", &root.verifying_key(), key, &cert_jws, cfg, authz_root.public()).unwrap();
        let r = Replica::new_with("n1", root.verifying_key(), ReplicaConfig::default(), authz_root.public());
        (p, Arc::new(Mutex::new(r)), dir, authz_root)
    }

    fn op(method: &str, path: &str) -> Op {
        Op::egress(&TenantId::single(), &RunId("run_a".into()), "z", method, "api.example.com", path)
    }

    #[tokio::test]
    async fn the_node_decider_fails_narrow_and_escalates_only_when_connected() {
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
        assert_eq!(d.decide(&c, &op("GET", "/other"), None).await, Outcome::Unavailable(UNREACHABLE.into()));
        assert_eq!(link.asks.load(Ordering::SeqCst), 1, "no ask while disconnected");
        // Past the TTL: narrow, reads only.
        now.store(t0 + 1_500, Ordering::SeqCst);
        assert!(matches!(d.decide(&c, &op("GET", "/v1/a"), None).await, Outcome::Allow(_)));
        assert!(matches!(d.decide(&c, &op("POST", "/v1/a"), None).await, Outcome::Unavailable(t) if t.contains("plain reads")));
        // Past the narrow window: closed.
        now.store(t0 + 3_500, Ordering::SeqCst);
        assert!(matches!(d.decide(&c, &op("GET", "/v1/a"), None).await, Outcome::Unavailable(t) if t.contains("allows nothing")));
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
}

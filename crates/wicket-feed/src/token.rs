//! Boxes' authority as Biscuit token chains in the feed (#57 step 4; #76, design A).
//!
//! The feed's entries are [`BoxAuthority`] records, one per box (keyed by run id), each carrying the
//! box's whole token: block 0 (the zone's ceiling, minted with the authority root key on the control
//! plane), a spawn block per ancestor link below it, and a third-party grant block per live grant. A
//! node loads each token once, when the delta carrying it applies ([`Policy::compile`]):
//! signatures against the pinned authority root, every block's revocation id against the feed's
//! revocation list, the strict structural check, then the fork's prepared and compiled evaluator
//! with its step budget (`wicket_authz::load`). Requests are decided by `wicket_authz`'s decision
//! (Allow / NeedsGrant / Forbidden), mapped onto the feed's modes
//! ([`Replica::<BoxAuthority>::decide`]).
//!
//! - **What the token decides, and what it doesn't.** Every allow comes from the token. The record's
//!   [`BoxAuthority::zone`] (the zone block 0 was minted from) is used only for things that can't
//!   widen authority: the pre-TLS host verdict (an early refusal), which hosts the node forwards to
//!   the control host (injected credentials), and the run's limits. A zone that disagrees with the
//!   token can only refuse more.
//! - **Grants** are the token's own third-party blocks. The record's [`BoxAuthority::grants`] carries
//!   what the token can't: each grant's use cap (counted on the node, `uses.log`), and the request it
//!   names, used only to pick which grant to try. The token's grant rule needs a `uses_left` fact,
//!   which the node supplies for one candidate at a time, so a grant the record doesn't list never
//!   fires, and the node knows exactly which grant an allow consumed.
//! - **Revocation.** A `Revoke { kind: Token, id }` names a block's revocation id (hex). It refuses
//!   every token containing that block: revoking a spawn block revokes the box it started and every
//!   box below it. Held revocations are checked when a token loads; a revocation that arrives later
//!   invalidates already-loaded tokens as its delta applies ([`Policy::revoked_by`]). Revoking a
//!   grant by its id (`kind: Grant`) stops that grant only.
//! - **Shipping grants.** `wicket_authz::SignedGrant` has no parser (the fork can't read a lone
//!   third-party block), so grant blocks never travel alone: the control host, which holds the
//!   approver key, appends them and publishes the whole token ([`Issuer::publish`]). It rebuilds the
//!   token from its unchanged base (block 0 and spawn blocks) with the live grants each time they
//!   change, so dead grants drop out, the chain stays under the block cap, and the base's revocation
//!   ids (what subtree revocation names) never change.

use crate::format::RevokeKind;
use crate::replica::{Allowed, Decision, Mode, Replica};
use crate::state::{Policy, Zone};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use wicket_authz as authz;
use wicket_core::{CompiledZone, HostVerdict, Op, ZoneSpec};

/// The most grants one box's token carries: the structural block cap less block 0 and room for five
/// spawn links (the design's depth).
pub const MAX_GRANTS: usize = 10;

/// One box's authority, as the feed carries it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoxAuthority {
    /// The box's run id: the entry's key.
    pub run: String,
    /// The box's path in its spawn tree (`run_a`, `run_a/run_b`): the `box` fact the token checks.
    pub box_path: String,
    /// The box's epoch, the `epoch` fact grants are bound to.
    pub epoch: i64,
    /// The zone block 0 was minted from (see the module docs: never used to allow).
    pub zone: ZoneSpec,
    /// The serialized token, base64url.
    pub token: String,
    /// The grants the token carries.
    #[serde(default)]
    pub grants: Vec<TokenGrant>,
    /// With the authority root offline (#154): the certificate of the online issuing key that minted
    /// block 0, signed by the root ([`AuthzKeyCert`]). None: the root minted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_cert: Option<String>,
    /// The org layer block 0 carries (#51), as data: a node splices a host through only if it allows
    /// that host wholesale. It narrows splicing only; every allow still comes from the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<authz::OrgLayer>,
}

/// An online authority issuing key, certified by the (offline) authority root (#154): tokens whose
/// block 0 it minted load against it, until `not_after`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthzKeyCert {
    /// The issuing key's public bytes, hex.
    pub x: String,
    /// Refused from this time (Unix ms).
    pub not_after: i64,
}

impl AuthzKeyCert {
    /// Signs a certificate for `key` with the authority root's seed.
    pub fn sign(root_seed: &[u8; 32], key: &authz::PublicKey, not_after: i64) -> String {
        let root = ed25519_dalek::SigningKey::from_bytes(root_seed);
        crate::jws::sign(&root, crate::jws::TYP_AUTHZ_KEY, &AuthzKeyCert { x: key.to_hex(), not_after })
    }

    /// The issuing key `cert` certifies under `root`, and until when (Unix ms), if it verifies.
    /// Expiry is the caller's to check, by its own clock (a node's: [`Replica::decide`]).
    pub fn open(cert: &str, root: &authz::PublicKey) -> Result<(authz::PublicKey, i64), String> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&root.0).map_err(|_| "the authority root is not a key".to_string())?;
        let c: AuthzKeyCert = crate::jws::open(cert, crate::jws::TYP_AUTHZ_KEY, &crate::jws::kid(&vk), &vk)
            .map_err(|e| format!("issuing key certificate: {e}"))?;
        let b: [u8; 32] = hex::decode(&c.x).ok().and_then(|b| b.try_into().ok()).ok_or("issuing key certificate: x")?;
        Ok((authz::PublicKey(b), c.not_after))
    }
}

/// What the node needs to know about one of a token's grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenGrant {
    /// The grant id (the block's `approved` gid).
    pub id: String,
    pub host: String,
    pub method: String,
    pub path: String,
    /// At most this many uses, counted on this node. `None`: until the grant expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<u32>,
}

/// A loaded token, and the zone's compiled form for host verdicts.
pub struct CompiledAuthority {
    pub loaded: authz::Loaded,
    pub zone: CompiledZone,
    /// Every block's revocation id, hex, in block order.
    pub ids: Vec<String>,
    /// Until when the issuing key that minted block 0 is certified (Unix ms): the box is forbidden
    /// everything from then, by the node's clock (#154). None: the root minted it.
    pub issuer_until: Option<i64>,
}

/// A block revocation id as the feed names it.
pub fn revocation_id(id: &[u8]) -> String {
    hex::encode(id)
}

impl BoxAuthority {
    pub fn token_bytes(&self) -> Result<Vec<u8>, String> {
        B64.decode(&self.token).map_err(|e| format!("token encoding: {e}"))
    }
}

impl Policy for BoxAuthority {
    type Compiled = CompiledAuthority;
    /// The authority root's public key, pinned on the node.
    type Ctx = authz::PublicKey;

    fn zone_name(&self) -> &str {
        &self.run
    }

    fn compile(&self, root: &authz::PublicKey, revoked: &dyn Fn(RevokeKind, &str) -> bool) -> Result<CompiledAuthority, String> {
        if self.run.is_empty() || self.run.contains('/') {
            return Err(format!("bad run id {:?}", self.run));
        }
        // The node knows the run from the transport; the box path must end in it, so a record can't
        // file one box's token under another box's run.
        if self.box_path != self.run && !self.box_path.ends_with(&format!("/{}", self.run)) {
            return Err(format!("box path {} is not run {}'s", self.box_path, self.run));
        }
        if self.grants.len() > MAX_GRANTS {
            return Err(format!("{} grants (cap {MAX_GRANTS})", self.grants.len()));
        }
        let mut ids: Vec<&str> = self.grants.iter().map(|g| g.id.as_str()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err("a grant id is listed twice".into());
        }
        let bytes = self.token_bytes()?;
        // Minted by an issuing key the root certified (#154), or by the root itself.
        let (key, issuer_until) = match &self.issuer_cert {
            Some(c) => AuthzKeyCert::open(c, root).map(|(k, until)| (k, Some(until)))?,
            None => (*root, None),
        };
        let loaded = authz::load(&bytes, &key, &|id| revoked(RevokeKind::Token, &revocation_id(id))).map_err(|e| e.to_string())?;
        let ids = loaded.revocation_ids().iter().map(|i| revocation_id(i)).collect();
        let zone = CompiledZone::new(self.zone.clone()).map_err(|e| format!("zone {}: {e}", self.zone.name))?;
        Ok(CompiledAuthority { loaded, zone, ids, issuer_until })
    }

    fn revoked_by(c: &CompiledAuthority, kind: RevokeKind, id: &str) -> bool {
        kind == RevokeKind::Token && c.ids.iter().any(|i| i == id)
    }
}

/// The request the token decides for `op`: every field from the node (its clock, the box's record,
/// the transport's attribution of the op), never from the box. No credential is injected on a node,
/// so `inject` is always empty.
fn request(spec: &BoxAuthority, op: &Op, now_ms: i64) -> authz::Request {
    authz::Request {
        time: u64::try_from(now_ms.div_euclid(1000)).unwrap_or(0),
        tenant: op.tenant.0.clone(),
        box_id: spec.box_path.clone(),
        epoch: spec.epoch,
        action: authz::Action::from_op(op, None),
        uses_left: vec![],
    }
}

/// The reason shown to people (`wicket pending`, the agent's 403): the zone's own wording when the
/// zone agrees with the token's decision, else the token's failed checks.
fn reason(c: &CompiledAuthority, op: &Op, forbidden: bool, token: String) -> String {
    match c.zone.evaluate(op) {
        wicket_core::Verdict::Forbidden(why) if forbidden => why,
        wicket_core::Verdict::NeedsGrant(why) if !forbidden => why,
        _ => token,
    }
}

/// The paths a node probes a box's token at before it splices a host (#141): the root, and a deep
/// path no rule names.
const SPLICE_PROBES: [&str; 2] = ["/", "/.wicket-splice-probe/a/b.c"];

/// What a token decision found, before the replica records a use (which needs it mutably).
enum Found {
    Done(Decision),
    Grant { id: String, counted: bool },
}

impl Replica<BoxAuthority> {
    /// The decision for one op at `now`, from the box's token:
    ///
    /// | token says | fresh or offline |
    /// |---|---|
    /// | Allow (by its ceilings) | allow |
    /// | NeedsGrant | try each live listed grant for this request; allow on the first the token accepts (one use consumed), else NeedsGrant |
    /// | Forbidden | forbidden |
    ///
    /// Offline (#153) decides exactly as fresh: the token and its grants carry their own expiries,
    /// checked against the node's clock, and nothing else bounds how long a node works alone. The
    /// caller queues a NeedsGrant raised offline. Closed and lagging refuse everything; a revoked run, a box with no record, a token that didn't load or
    /// was revoked, and an op for another zone are forbidden.
    pub fn decide(&mut self, op: &Op, now: i64) -> Decision {
        self.decide_inner(op, now, true)
    }

    /// What [`Self::decide`] would say, without recording a use of a counted grant: for asking
    /// ahead (`request_access`, #164), which must not spend one.
    pub fn peek(&mut self, op: &Op, now: i64) -> Decision {
        self.decide_inner(op, now, false)
    }

    fn decide_inner(&mut self, op: &Op, now: i64, record: bool) -> Decision {
        let found = match self.gate(op, now) {
            Err(d) => Found::Done(d),
            Ok((_, st)) => match self.entry(&op.run.0) {
                None => Found::Done(Decision::Forbidden(format!("no authority for box {} on this node", op.run))),
                Some(entry) => match &entry.compiled {
                    Err(e) => Found::Done(Decision::Forbidden(format!("this box's authority is invalid: {e}"))),
                    Ok(_) if entry.spec.zone.name != op.zone => Found::Done(Decision::Forbidden(format!(
                        "op for zone {}, but box {} holds authority for zone {}",
                        op.zone, op.run, entry.spec.zone.name
                    ))),
                    Ok(c) if c.issuer_until.is_some_and(|u| now >= u) => Found::Done(Decision::Forbidden(
                        "the authority issuing key that minted this box's token is no longer certified (wicket keys certify)".into(),
                    )),
                    Ok(c) => {
                        let mut req = request(&entry.spec, op, now);
                        match c.loaded.decide(&req) {
                            authz::Decision::Forbidden(r) => Found::Done(Decision::Forbidden(reason(c, op, true, r))),
                            authz::Decision::Allow => Found::Done(Decision::Allow(Allowed::Ceiling)),
                            authz::Decision::NeedsGrant(r) => {
                                let r = reason(c, op, false, r);
                                let candidates = entry.spec.grants.iter().filter(|g| {
                                    g.host.eq_ignore_ascii_case(&op.host)
                                        && g.method.eq_ignore_ascii_case(&op.method)
                                        && g.path == op.path
                                        && !st.is_revoked(RevokeKind::Grant, &g.id)
                                        && g.uses.is_none_or(|max| self.uses(&g.id) < max)
                                });
                                let mut hit = None;
                                for g in candidates {
                                    let left = g.uses.map_or(i64::MAX, |max| i64::from(max - self.uses(&g.id)));
                                    req.uses_left = vec![(g.id.clone(), left)];
                                    if c.loaded.decide(&req) == authz::Decision::Allow {
                                        hit = Some(Found::Grant { id: g.id.clone(), counted: g.uses.is_some() });
                                        break;
                                    }
                                }
                                hit.unwrap_or(Found::Done(Decision::NeedsGrant(r)))
                            }
                        }
                    }
                },
            },
        };
        match found {
            Found::Done(d) => d,
            Found::Grant { id, counted } => {
                if counted && record {
                    if let Err(e) = self.record_use(&id) {
                        return Decision::Refused { mode: Mode::Fresh, why: e };
                    }
                }
                Decision::Allow(Allowed::Grant(id))
            }
        }
    }

    /// The verdict on a host before any request to it (and before TLS), from the zone the box's
    /// token was minted from: an early refusal only (see the module docs). A box with no record, or
    /// whose token didn't load, gets `Open`: its requests are then refused one by one by
    /// [`Self::decide`].
    pub fn host_verdict(&self, run: &str, host: &str) -> HostVerdict {
        match self.state().and_then(|_| self.entry(run)).map(|z| &z.compiled) {
            Some(Ok(c)) => c.zone.host_verdict(host),
            _ => HostVerdict::Open,
        }
    }

    /// The reach rule that lets this node splice connections from box `run` to `host` through
    /// without terminating TLS (#141; which hosts: [`wicket_core::splice`]), at `now`. Read-only: no
    /// grant is tried and no use is recorded. All of these must hold, else None (inspect):
    ///
    /// - the replica is fresh or offline (lagging and closed refuse per request);
    /// - the box is a top-level box: a child's token is narrowed by its ancestors' ceilings, which
    ///   the record's zone doesn't show;
    /// - the zone the box's token was minted from allows the host wholesale;
    /// - the token itself allows every method the proxy forwards, at the root and at a deep path,
    ///   by its ceiling alone (the allow comes from the token, as for every request).
    pub fn splice(&self, tenant: &wicket_core::TenantId, run: &str, host: &str, now: i64) -> Option<usize> {
        self.state()?;
        let entry = self.entry(run)?;
        let c = entry.compiled.as_ref().ok()?;
        if entry.spec.box_path != entry.spec.run {
            return None;
        }
        // Under an org policy (#51) a rule can depend on any path, which probes can't vouch for: only
        // a host its org layer allows wholesale is spliced (the record carries the layer; a token
        // with an org layer and no record of it is never spliced).
        if c.loaded.has_org_layer() && !entry.spec.org.as_ref().is_some_and(|o| o.allows_host_wholesale(host)) {
            return None;
        }
        let rule = match wicket_core::splice::inspection(&entry.spec.zone, host) {
            wicket_core::splice::Inspection::Spliced { rule } => rule,
            wicket_core::splice::Inspection::Inspected(_) => return None,
        };
        let run_id = wicket_core::RunId(run.to_string());
        for method in wicket_core::op::HTTP_METHODS {
            for path in SPLICE_PROBES {
                let op = Op::egress(tenant, &run_id, &entry.spec.zone.name, method, host, path);
                match self.gate(&op, now) {
                    Ok((Mode::Fresh | Mode::Offline, _)) => {}
                    _ => return None,
                }
                if c.loaded.decide(&request(&entry.spec, &op, now)) != authz::Decision::Allow {
                    return None;
                }
            }
        }
        Some(rule)
    }

    /// When box `run`'s authority ends (Unix ms), read from its verified token: the earliest expiry
    /// of its first-party blocks (#153). None if the node holds no valid token for it.
    pub fn authority_until(&self, run: &str) -> Option<i64> {
        let c = self.entry(run)?.compiled.as_ref().ok()?;
        // The token's check is `time <= not_after` in whole seconds: it allows through that second.
        c.loaded.not_after().map(|s| i64::try_from(s).unwrap_or(i64::MAX / 1000).saturating_add(1).saturating_mul(1000))
    }

    /// Derives box `child`'s authority on this node (#164), from box `parent`'s base token (its
    /// block 0 and spawn links, without grants, as its control host handed it to the node): the
    /// base must verify against the authority root (or the issuing key that minted it), and be the
    /// start of the token the feed holds for `parent`, unrevoked. The child's token is the base
    /// with a spawn block bounded to `<parent's box path>/<child>`, so it holds at most what its
    /// parent's token does, and goes when any of its parent's blocks is revoked. Held as an entry
    /// of this node's own until the feed holds `child`.
    pub fn derive_child(
        &mut self,
        parent: &str,
        base: &str,
        child: &str,
        zone: &ZoneSpec,
        ceiling: &authz::Ceiling,
    ) -> Result<BoxAuthority, String> {
        let (spec, ids) = match self.entry(parent) {
            Some(Zone { spec, compiled: Ok(c) }) => (spec.clone(), c.ids.clone()),
            Some(Zone { compiled: Err(e), .. }) => return Err(format!("box {parent}'s authority is invalid: {e}")),
            None => return Err(format!("no authority for box {parent} on this node")),
        };
        let key = match &spec.issuer_cert {
            Some(c) => AuthzKeyCert::open(c, self.ctx())?.0,
            None => *self.ctx(),
        };
        let bytes = B64.decode(base).map_err(|e| format!("base token encoding: {e}"))?;
        let base = authz::Token::from_bytes(&bytes, &key).map_err(|e| e.to_string())?;
        let base_ids: Vec<String> = base.revocation_ids().iter().map(|i| revocation_id(i)).collect();
        // Exactly the token without its grant blocks (appended last): a child never inherits its
        // parent's grants.
        let first_party = ids.len().saturating_sub(spec.grants.len());
        if base_ids.is_empty() || base_ids.len() != first_party || base_ids[..] != ids[..first_party] {
            return Err(format!("the base token isn't box {parent}'s, without its grants"));
        }
        let issuer = Issuer {
            base,
            run: spec.run.clone(),
            box_path: spec.box_path.clone(),
            epoch: spec.epoch,
            zone: spec.zone.clone(),
            issuer_cert: spec.issuer_cert.clone(),
            org: spec.org.clone(),
        };
        let record = issuer.child(child, 0, zone, ceiling).map_err(|e| e.to_string())?.record().map_err(|e| e.to_string())?;
        self.put_local(record.clone())?;
        Ok(record)
    }

    /// Box `run`'s path in its spawn tree, if the node holds its authority.
    pub fn box_path_of(&self, run: &str) -> Option<String> {
        self.entry(run).map(|z| z.spec.box_path.clone())
    }

    /// The org layer box `run`'s block 0 carries (#51), as data.
    pub fn org_of(&self, run: &str) -> Option<authz::OrgLayer> {
        self.entry(run).and_then(|z| z.spec.org.clone())
    }

    /// The zone a box's authority was minted from, if the node holds it.
    pub fn zone_of(&self, run: &str) -> Option<&ZoneSpec> {
        self.entry(run).map(|z| &z.spec.zone)
    }
}

/// The control plane's side of one box's authority: the base token (block 0 and spawn blocks),
/// which never changes, and how to publish it with the box's live grants.
#[derive(Clone)]
pub struct Issuer {
    pub base: authz::Token,
    pub run: String,
    pub box_path: String,
    pub epoch: i64,
    pub zone: ZoneSpec,
    /// The minting key's certificate, when it isn't the root ([`BoxAuthority::issuer_cert`]).
    pub issuer_cert: Option<String>,
    /// Block 0's org layer, carried into every record ([`BoxAuthority::org`]).
    pub org: Option<authz::OrgLayer>,
}

/// One grant to publish: what the token says, and its use cap.
#[derive(Clone, Debug)]
pub struct LiveGrant {
    pub grant: authz::Grant,
    pub uses: Option<u32>,
}

impl Issuer {
    /// A top-level box: block 0 minted by `root` with the zone's ceiling, until `not_after` (Unix
    /// seconds), accepting grants signed by `grant_keys`. `images` are added to the images the box
    /// may start children from (its own image, which the zone doesn't name).
    #[allow(clippy::too_many_arguments)]
    pub fn root(
        root: &authz::SigningKey,
        tenant: &str,
        principal: &str,
        run: &str,
        epoch: i64,
        zone: &ZoneSpec,
        images: &[String],
        not_after: u64,
        grant_keys: Vec<authz::PublicKey>,
    ) -> Result<Issuer, authz::AuthzError> {
        let mut c = authz::Ceiling::from_zone(zone, run, not_after, grant_keys)?;
        c.spawn.images.extend(images.iter().cloned());
        Issuer::from_ceiling(root, tenant, principal, run, epoch, zone, &c)
    }

    /// A top-level box whose ceiling was compiled already: from its zone's and the org's Cedar
    /// policies (`wicket-policy`, #51). `zone` is the one the ceiling was compiled from.
    pub fn from_ceiling(
        root: &authz::SigningKey,
        tenant: &str,
        principal: &str,
        run: &str,
        epoch: i64,
        zone: &ZoneSpec,
        ceiling: &authz::Ceiling,
    ) -> Result<Issuer, authz::AuthzError> {
        if ceiling.box_prefix != run {
            return Err(authz::AuthzError::Ceiling(format!(
                "a top-level box's ceiling is bounded to its own run, not {}",
                ceiling.box_prefix
            )));
        }
        let base = authz::mint(root, tenant, principal, ceiling)?;
        Ok(Issuer { base, run: run.into(), box_path: run.into(), epoch, zone: zone.clone(), issuer_cert: None, org: ceiling.org.clone() })
    }

    /// A child box started by this one, in `zone`: this box's base token plus a spawn block with the
    /// child's ceiling. Whatever the ceiling says, the child holds at most what this box holds.
    pub fn child(&self, run: &str, epoch: i64, zone: &ZoneSpec, ceiling: &authz::Ceiling) -> Result<Issuer, authz::AuthzError> {
        let box_path = format!("{}/{run}", self.box_path);
        if ceiling.box_prefix != box_path {
            return Err(authz::AuthzError::Ceiling(format!("a child of {} must be bounded to {box_path}", self.box_path)));
        }
        Ok(Issuer {
            base: self.base.attenuate(ceiling)?,
            run: run.into(),
            box_path,
            epoch,
            zone: zone.clone(),
            issuer_cert: self.issuer_cert.clone(),
            org: self.org.clone(),
        })
    }

    /// The base token's revocation ids (hex), in block order. The last one is this box's own link:
    /// revoking it revokes this box and every box below it.
    pub fn block_ids(&self) -> Vec<String> {
        self.base.revocation_ids().iter().map(|i| revocation_id(i)).collect()
    }

    /// The record of the base token alone, without grants.
    pub fn record(&self) -> Result<BoxAuthority, authz::AuthzError> {
        Ok(BoxAuthority {
            run: self.run.clone(),
            box_path: self.box_path.clone(),
            epoch: self.epoch,
            zone: self.zone.clone(),
            token: B64.encode(self.base.to_bytes()?),
            grants: vec![],
            issuer_cert: self.issuer_cert.clone(),
            org: self.org.clone(),
        })
    }

    /// The record to publish: the base token with one grant block per live grant, signed by
    /// `approver`. Each grant is bound to this box and epoch whatever it says.
    pub fn publish(&self, approver: &authz::SigningKey, grants: &[LiveGrant]) -> Result<BoxAuthority, authz::AuthzError> {
        if grants.len() > MAX_GRANTS {
            return Err(authz::AuthzError::Structure(format!("{} grants (cap {MAX_GRANTS})", grants.len())));
        }
        let mut token = self.base.clone();
        let mut listed = Vec::with_capacity(grants.len());
        for g in grants {
            let mut grant = g.grant.clone();
            grant.box_id = self.box_path.clone();
            grant.epoch = self.epoch;
            token = authz::grant(&token, approver, &grant)?;
            listed.push(TokenGrant {
                id: grant.gid.clone(),
                host: grant.host.to_ascii_lowercase(),
                method: grant.method.to_ascii_uppercase(),
                path: grant.path.clone(),
                uses: g.uses,
            });
        }
        Ok(BoxAuthority {
            run: self.run.clone(),
            box_path: self.box_path.clone(),
            epoch: self.epoch,
            zone: self.zone.clone(),
            token: B64.encode(token.to_bytes()?),
            grants: listed,
            issuer_cert: self.issuer_cert.clone(),
            org: self.org.clone(),
        })
    }
}

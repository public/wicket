//! Keys and tokens: minting (block 0), attenuation (spawn blocks) and grants (third-party blocks).

use crate::generator::{ceiling_code, grant_code, AuthorityInfo};
use crate::payload::{Ceiling, Grant, PublicKey};
use crate::AuthzError;
use biscuit_auth::{Algorithm, Biscuit, PrivateKey, ThirdPartyBlock, ThirdPartyRequest};

fn enc(e: impl std::fmt::Display) -> AuthzError {
    AuthzError::Encode(e.to_string())
}

/// An Ed25519 signing key: the control plane's root key, the approval service's, or a box's grantor
/// key (held by the node for that box).
#[derive(Clone)]
pub struct SigningKey(PrivateKey);

impl SigningKey {
    pub fn generate() -> SigningKey {
        SigningKey(PrivateKey::new())
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<SigningKey, AuthzError> {
        PrivateKey::from_bytes(bytes, Algorithm::Ed25519).map(SigningKey).map_err(enc)
    }

    pub fn public(&self) -> PublicKey {
        let v = self.0.public().to_bytes();
        PublicKey(v.try_into().expect("an Ed25519 public key is 32 bytes"))
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", self.public().to_hex())
    }
}

/// Runs the structural check a node runs at load on a token this crate just built, so a ceiling
/// that no node would accept (over a cap) is an error where it is made, not at every node. Then the
/// cost estimate (`cost`, #183): a token whose costliest host could exceed the step budget in the
/// generic engine is refused here, naming `zone` and the host, rather than deciding `Forbidden`
/// per request if it ever ran there.
fn checked(b: Biscuit, zone: &str) -> Result<Token, AuthzError> {
    let len = b.to_vec().map_err(enc)?.len();
    crate::structure::check(&b, len, &crate::structure::Policy::default()).map_err(AuthzError::Structure)?;
    crate::cost::check(&b).map_err(|e| AuthzError::Cost(format!("zone {zone}: {e}")))?;
    Ok(Token(b))
}

pub(crate) fn biscuit_key(k: &PublicKey) -> Result<biscuit_auth::PublicKey, AuthzError> {
    biscuit_auth::PublicKey::from_bytes(&k.0, Algorithm::Ed25519).map_err(|e| AuthzError::Load(format!("bad public key: {e}")))
}

/// An authority token. Its serialized form is what nodes hold and pass to [`crate::load`].
#[derive(Clone)]
pub struct Token(pub(crate) Biscuit);

/// The control plane mints a run's token: block 0, signed by the root key, with the tenant, the
/// principal it acts for and the root ceiling. Fails if the result wouldn't pass a node's
/// structural check (e.g. a zone over the per-block caps), or if a request to one of its hosts could
/// cost more than the step budget in the generic engine ([`AuthzError::Cost`]).
pub fn mint(root: &SigningKey, tenant: &str, principal: &str, ceiling: &Ceiling) -> Result<Token, AuthzError> {
    let code = ceiling_code(ceiling, Some(&AuthorityInfo { tenant, principal }))?;
    checked(code.authority()?.build(&root.0).map_err(enc)?, &ceiling.zone)
}

impl Token {
    /// Parses and verifies every signature against the root key. No structural check: use
    /// [`crate::load`] to decide requests.
    pub fn from_bytes(bytes: &[u8], root: &PublicKey) -> Result<Token, AuthzError> {
        Biscuit::from(bytes, biscuit_key(root)?).map(Token).map_err(|e| AuthzError::Load(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AuthzError> {
        self.0.to_vec().map_err(enc)
    }

    /// Appends a spawn block: the child's ceiling as checks. Whatever it says, the child's authority
    /// is the intersection with every earlier block, so the result never exceeds this token. Fails if
    /// the result wouldn't pass a node's structural check (too many blocks or bytes, a child zone over
    /// the per-block caps), or if a request to one of the chain's hosts, summed over every block,
    /// could cost more than the step budget in the generic engine ([`AuthzError::Cost`]). Grants are
    /// not checked here: [`crate::load`] refuses one from a key no block trusts.
    pub fn attenuate(&self, child: &Ceiling) -> Result<Token, AuthzError> {
        checked(self.0.append(ceiling_code(child, None)?.block()?).map_err(enc)?, &child.zone)
    }

    /// The request a node sends an approver (the approval service, or the parent box's grantor) to
    /// get a grant block bound to this token's last signature.
    pub fn grant_request(&self) -> Result<GrantRequest, AuthzError> {
        self.0.third_party_request().map(GrantRequest).map_err(enc)
    }

    /// Appends a signed grant. `signer` must be the key that signed it.
    pub fn add_grant(&self, signer: &PublicKey, grant: SignedGrant) -> Result<Token, AuthzError> {
        self.0.append_third_party(biscuit_key(signer)?, grant.0).map(Token).map_err(enc)
    }

    /// Every block's revocation id, in block order. Revoking block `i`'s id revokes every token that
    /// contains that block: the subtree under it.
    pub fn revocation_ids(&self) -> Vec<Vec<u8>> {
        self.0.revocation_identifiers()
    }

    pub fn block_count(&self) -> usize {
        self.0.block_count()
    }

    /// The token's Datalog, for debugging.
    pub fn print(&self) -> String {
        self.0.print()
    }

    /// The underlying Biscuit, for tests and tools that need the format itself.
    #[doc(hidden)]
    pub fn biscuit(&self) -> &Biscuit {
        &self.0
    }

    /// Wraps a Biscuit built by other means (tests: hand-made and hostile blocks).
    #[doc(hidden)]
    pub fn from_biscuit(b: Biscuit) -> Token {
        Token(b)
    }
}

/// A grant request, as sent to an approver.
pub struct GrantRequest(ThirdPartyRequest);

impl GrantRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, AuthzError> {
        self.0.serialize().map_err(enc)
    }
    pub fn from_bytes(b: &[u8]) -> Result<GrantRequest, AuthzError> {
        ThirdPartyRequest::deserialize(b).map(GrantRequest).map_err(enc)
    }
}

/// A grant block signed by an approver, as sent back to the node. (Biscuit has no parser for a
/// lone third-party block, so an out-of-process approver's reply needs one before this can cross a
/// process boundary. The feed doesn't: the control host, which holds the approver key, appends
/// grants itself and publishes the whole token, `wicket_feed::token`.)
pub struct SignedGrant(ThirdPartyBlock);

impl SignedGrant {
    pub fn to_bytes(&self) -> Result<Vec<u8>, AuthzError> {
        self.0.serialize().map_err(enc)
    }
}

/// The approver's side: signs `grant` for the token that made `request`.
pub fn sign_grant(request: GrantRequest, approver: &SigningKey, grant: &Grant) -> Result<SignedGrant, AuthzError> {
    request.0.create_block(&approver.0, grant_code(grant).block()?).map(SignedGrant).map_err(enc)
}

/// The whole third-party flow in one call (request, sign, append), for an approver in-process.
pub fn grant(token: &Token, approver: &SigningKey, g: &Grant) -> Result<Token, AuthzError> {
    let signed = sign_grant(token.grant_request()?, approver, g)?;
    token.add_grant(&approver.public(), signed)
}

//! Target 12: what a digest grant records (#258, #483, `wicket_store::digestgrant`): its terms (the
//! action and scope [`wicket_store::Ledger::may_use`] reads from `grants.terms`) and its path
//! (`/digest/sha256:<hex>`, or a CI principal's `/signer/<key id>`). Both are read back from the
//! ledger at every acceptance, and a grant's terms come from whatever wrote its row.
//!
//! The input is tried as terms text, as a path, and as a digest. The oracle, besides panics:
//! - terms that read print (as a grant records them) as terms that read as the same action and
//!   scope, and print the same again;
//! - a path that reads is exactly the path it prints, and a digest path names a valid digest;
//! - a digest is valid only as `sha256:` and 64 lowercase hex digits, and its path reads back as it.

use wicket_store::{digest_terms_text, parse_digest_terms, valid_digest, DigestGrantPath};

pub fn run(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Some((action, scope)) = parse_digest_terms(s) {
        let text = digest_terms_text(action, &scope);
        assert_eq!(parse_digest_terms(&text), Some((action, scope.clone())), "{s:?} reads, but {text:?} doesn't read as it");
        assert_eq!(digest_terms_text(action, &scope), text);
    }
    if let Some(p) = DigestGrantPath::parse(s) {
        assert_eq!(p.path(), s, "{s:?} reads as {p:?}, which prints otherwise");
        if let DigestGrantPath::Digest(d) = &p {
            assert!(valid_digest(d), "{s:?}: {d} isn't a digest");
        }
    }
    if valid_digest(s) {
        let hex = &s["sha256:".len()..];
        assert!(hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "{s:?}");
        let p = DigestGrantPath::Digest(s.to_string());
        assert_eq!(DigestGrantPath::parse(&p.path()), Some(p));
    }
}

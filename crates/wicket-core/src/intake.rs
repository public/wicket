//! Webhook intake (#578 step 4; docs/explanation/trigger-intake.md): what `wicket node intake`
//! checks of a delivery and what it keeps of one. Everything here reads attacker-written bytes: a
//! verified signature says the sender had the secret, not that the content is safe. So a delivery
//! becomes a small, capped set of fields, stripped of control characters, and nothing else of the
//! body goes further than its sha256.
//!
//! This is what every source shares: HMAC and constant-time comparison, tokens, delivery ids, the
//! caps on fields and [`keep_text`]. Each source's own headers, signed message, events and fields
//! are its adapter's, outside core (the `wicket-sources` crate, #740).

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The largest body intake reads (bytes): past it, the delivery is refused unread.
pub const MAX_BODY: usize = 1 << 20;
/// A delivery's fields: at most this many top-level keys (and four times as many values in all) …
pub const MAX_FIELDS: usize = 32;
/// … each string at most this many bytes.
pub const MAX_FIELD_VALUE: usize = 512;
/// The longest delivery id kept (a sender's header; longer is refused).
pub const MAX_DELIVERY: usize = 128;

/// One trigger a node's intake serves, as the control host sends it (protocol 20's `IntakeSync`).
/// The secret is held in memory only, on the node and in `wicket node intake`.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntakeTrigger {
    pub trigger: String,
    /// Its source's adapter (`webhook`, `github`).
    pub kind: String,
    pub token_sha256: String,
    /// The verify secret's value (HMAC key).
    pub secret: String,
    /// What its source names, if it does: a repository (GitHub's `owner/name`) and the events
    /// listened to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<String>,
    /// Served here, but its secret couldn't be read this time: its deliveries are answered 503
    /// (try later), not 404, and nothing counts as a failure (#714 review F5).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unavailable: bool,
}

impl std::fmt::Debug for IntakeTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntakeTrigger")
            .field("trigger", &self.trigger)
            .field("kind", &self.kind)
            .field("repo", &self.repo)
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

/// A verified delivery, as intake keeps it and the node hands it to the control host.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IntakeEvent {
    /// The node's spool id (what the control host acks).
    pub id: String,
    pub trigger: String,
    /// The event's kind, as its source's adapter names it: GitHub's event (`check_suite`), or
    /// `webhook`.
    pub kind: String,
    pub delivery: String,
    /// When intake verified it (Unix s).
    pub received_at: i64,
    pub fields: Value,
    pub raw_sha256: String,
    pub bytes: u64,
}

/// What a node's intake refused since the last sync, counted: deliveries that never became events.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntakeRefused {
    /// An unknown trigger, or a token that doesn't match.
    pub token: u64,
    pub signature: u64,
    pub rate: u64,
    /// Too large, malformed, or the spool full.
    pub other: u64,
}

impl IntakeRefused {
    pub fn total(&self) -> u64 {
        self.token + self.signature + self.rate + self.other
    }
}

/// HMAC-SHA256 (RFC 2104) of `msg` under `key`.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |x: u8| k.iter().map(|b| b ^ x).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

/// Whether two byte strings are equal, in time that depends only on their lengths.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether `header` (`sha256=<hex>`, as GitHub and the generic webhook send it) is the HMAC-SHA256
/// of `body` under `secret`. Anything else (no prefix, bad hex, another length) is not.
pub fn signature_ok(secret: &[u8], body: &[u8], header: Option<&str>) -> bool {
    if secret.len() < MIN_SECRET {
        return false;
    }
    let Some(h) = header.and_then(|h| h.trim().strip_prefix("sha256=")) else { return false };
    let Ok(sig) = hex::decode(h.trim()) else { return false };
    same(&sig, &hmac_sha256(secret, body))
}

/// The shortest verify secret (bytes) intake uses: an empty or short key would let anyone forge a
/// signature (#714 review E).
pub const MIN_SECRET: usize = 16;

/// Whether `secret` is long enough to verify with.
pub fn secret_ok(secret: &str) -> bool {
    secret.len() >= MIN_SECRET
}

/// The sha256 (hex) of a trigger URL's token: what the ledger and intake keep of it.
pub fn token_sha256(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A new trigger URL token: 32 random bytes, URL-safe base64 without padding (43 characters).
pub fn new_token() -> Result<String, String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| format!("random: {e}"))?;
    Ok(base64url(&b))
}

fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |n, (i, x)| n | (u32::from(*x) << (16 - 8 * i)));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Whether `s` is a token's shape (what `new_token` makes): checked before hashing, so a path
/// can't make intake hash a megabyte.
pub fn token_shape(s: &str) -> bool {
    s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A delivery id as kept: the sender's (`X-GitHub-Delivery`, `X-Wicket-Delivery`) if it is
/// printable ASCII of at most [`MAX_DELIVERY`] bytes, else the body's sha256 (so a resent body is
/// the same delivery). None if the sender's id is there but malformed.
pub fn delivery_id(header: Option<&str>, body: &[u8]) -> Option<String> {
    match header.map(str::trim) {
        None | Some("") => Some(format!("sha256:{}", hex::encode(Sha256::digest(body)))),
        Some(h) if h.len() <= MAX_DELIVERY && h.bytes().all(|b| b.is_ascii_graphic()) => Some(h.to_string()),
        Some(_) => None,
    }
}

/// Whether `k` is a field's key: `[a-z0-9_.-]`, 1 to 64 bytes.
pub fn field_key(k: &str) -> bool {
    !k.is_empty() && k.len() <= 64 && k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.'))
}

/// Text from a delivery as kept: control characters stripped, cut at `max` bytes (on a char
/// boundary).
pub fn keep_text(s: &str, max: usize) -> String {
    let mut v = crate::text::strip(s);
    if v.len() > max {
        let mut cut = max;
        while !v.is_char_boundary(cut) {
            cut -= 1;
        }
        v.truncate(cut);
    }
    v
}

/// The sha256 (hex) of a delivery's raw body: all of the body that is kept.
pub fn body_sha256(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Whether a field set is within what intake makes (a check the control host applies again to what
/// a node sends: a node is trusted only as far as its own triggers).
pub fn fields_within(fields: &Value) -> bool {
    fn walk(v: &Value, depth: usize, count: &mut usize) -> bool {
        *count += 1;
        if *count > 4 * MAX_FIELDS || depth > 3 {
            return false;
        }
        match v {
            Value::Object(m) => m.iter().all(|(k, v)| field_key(k) && walk(v, depth + 1, count)),
            Value::String(s) => s.len() <= MAX_FIELD_VALUE && !s.chars().any(crate::text::is_unsafe),
            Value::Number(_) | Value::Bool(_) => true,
            _ => false,
        }
    }
    let mut count = 0;
    fields.is_object() && walk(fields, 0, &mut count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef-key";
    const OTHER: &[u8] = b"0123456789abcdef-other";

    /// RFC 4231's test cases 1, 2 and 6 (a key longer than a block), and GitHub's documented example.
    #[test]
    fn hmac_sha256_is_rfc_4231s() {
        let h = |k: &[u8], m: &[u8]| hex::encode(hmac_sha256(k, m));
        assert_eq!(h(&[0x0b; 20], b"Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(h(b"Jefe", b"what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(
            h(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First"),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // docs.github.com, "Validating webhook deliveries".
        assert!(signature_ok(
            b"It's a Secret to Everybody",
            b"Hello, World!",
            Some("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")
        ));
    }

    #[test]
    fn only_the_right_signature_passes() {
        let sig = format!("sha256={}", hex::encode(hmac_sha256(KEY, b"body")));
        assert!(signature_ok(KEY, b"body", Some(&sig)));
        assert!(!signature_ok(KEY, b"body ", Some(&sig)), "another body");
        assert!(!signature_ok(OTHER, b"body", Some(&sig)), "another key");
        assert!(!signature_ok(KEY, b"body", Some(&sig[7..])), "no prefix");
        assert!(!signature_ok(KEY, b"body", Some("sha256=zz")), "not hex");
        assert!(!signature_ok(KEY, b"body", Some(&sig[..sig.len() - 2])), "short");
        assert!(!signature_ok(KEY, b"body", None));
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
    }

    /// #714 review E: an empty or short key verifies nothing.
    #[test]
    fn a_short_key_verifies_nothing() {
        let sig = format!("sha256={}", hex::encode(hmac_sha256(b"", b"body")));
        assert!(!signature_ok(b"", b"body", Some(&sig)));
        // (The generic webhook's own framing under a short key: `wicket_sources::generic`'s test.)
        assert!(!secret_ok("short") && secret_ok(&"x".repeat(MIN_SECRET)));
    }

    #[test]
    fn tokens_are_unguessable_and_shaped() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_ne!(a, b);
        assert!(token_shape(&a) && token_shape(&b), "{a}");
        assert!(!token_shape("short") && !token_shape(&format!("{}!", &a[..42])));
        assert_eq!(token_sha256(&a).len(), 64);
        assert_eq!(base64url(b"\xfb\xff"), "-_8");
    }

    #[test]
    fn delivery_ids_are_the_senders_or_the_bodys() {
        assert_eq!(
            delivery_id(Some("72d3162e-cc78-11e3-81ab-4c9367dc0958"), b"x").as_deref(),
            Some("72d3162e-cc78-11e3-81ab-4c9367dc0958")
        );
        let a = delivery_id(None, b"x").unwrap();
        assert_eq!(a, delivery_id(Some(""), b"x").unwrap(), "a resent body is the same delivery");
        assert_ne!(a, delivery_id(None, b"y").unwrap());
        assert_eq!(delivery_id(Some("a b"), b"x"), None, "not printable as one word");
        assert_eq!(delivery_id(Some(&"a".repeat(129)), b"x"), None);
    }

    /// What a node sends is checked again: no deep nesting, no long or unsafe text, no odd keys.
    #[test]
    fn fields_from_a_node_are_held_to_intakes_shape() {
        assert!(fields_within(&serde_json::json!({ "a": 1, "b": { "c": "x" } })));
        assert!(!fields_within(&serde_json::json!({ "a": "x".repeat(600) })));
        assert!(!fields_within(&serde_json::json!({ "a": "\u{1b}" })));
        assert!(!fields_within(&serde_json::json!({ "A": 1 })));
        assert!(!fields_within(&serde_json::json!({ "a": [1] })));
        assert!(!fields_within(&serde_json::json!({ "a": { "b": { "c": { "d": 1 } } } })));
        assert!(!fields_within(&serde_json::json!("x")));
    }
}

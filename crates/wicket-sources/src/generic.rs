//! The generic webhook: wicket's own signing scheme, for any sender that can compute an HMAC.
//!
//! A sender signs `v1:<timestamp>:<length of the delivery id>:<delivery id>:` then the raw body
//! ([`generic_signed`]) and sends `X-Wicket-Signature-256: sha256=<hex>`, `X-Wicket-Timestamp` and,
//! if it has one, `X-Wicket-Delivery`. Its fields are the top-level scalars of a JSON object body.

use crate::{Adapter, Header, Hook, Signed, Unfit};
use serde_json::{Map, Value};
use std::borrow::Cow;
use wicket_core::intake::{self as ik, IntakeTrigger};
use wicket_core::trigger::Source;

/// A generic webhook's fields: at most this many top-level keys …
pub const MAX_GENERIC_FIELDS: usize = ik::MAX_FIELDS;
/// … each value at most this many bytes.
pub const MAX_GENERIC_VALUE: usize = ik::MAX_FIELD_VALUE;
/// The signature header (`sha256=<hex>` of the HMAC-SHA256 of [`generic_signed`]: the time, the
/// delivery id and the body).
pub const GENERIC_SIGNATURE: &str = "x-wicket-signature-256";
/// The delivery header.
pub const GENERIC_DELIVERY: &str = "x-wicket-delivery";
/// The timestamp header (Unix seconds), signed with the body.
pub const GENERIC_TIMESTAMP: &str = "x-wicket-timestamp";
/// How far a generic delivery's timestamp may be from intake's clock (s), either way.
pub const GENERIC_WINDOW_SECS: i64 = 300;
/// Its kind, and every event's.
pub const KIND: &str = "webhook";

/// What a generic webhook's sender signs: `v1:<timestamp>:<length of the delivery id>:<delivery
/// id>:` then the raw body (the id empty, length 0, if it sends none). The timestamp and the id are
/// under the MAC, so a captured delivery can't be sent again later, or under another id; the id's
/// length is too, so a capture can't be split differently between id and body (#714 review F1).
pub fn generic_signed(timestamp: i64, delivery: &str, body: &[u8]) -> Vec<u8> {
    let mut m = format!("v1:{timestamp}:{}:{delivery}:", delivery.len()).into_bytes();
    m.extend_from_slice(body);
    m
}

/// The `X-Wicket-Signature-256` a sender sends (`sha256=<hex>`).
pub fn generic_signature(secret: &[u8], timestamp: i64, delivery: &str, body: &[u8]) -> String {
    format!("sha256={}", hex::encode(ik::hmac_sha256(secret, &generic_signed(timestamp, delivery, body))))
}

/// Why a generic delivery's signature doesn't pass, if it doesn't: its timestamp missing, malformed
/// or outside [`GENERIC_WINDOW_SECS`] of `now`, or its MAC over [`generic_signed`] wrong.
pub fn generic_check(
    secret: &[u8],
    timestamp: Option<&str>,
    delivery: Option<&str>,
    body: &[u8],
    signature: Option<&str>,
    now: i64,
) -> Result<(), &'static str> {
    let ts = timestamp.and_then(|t| t.trim().parse::<i64>().ok()).ok_or("no timestamp")?;
    if (now - ts).abs() > GENERIC_WINDOW_SECS {
        return Err("timestamp outside the window");
    }
    let signed = generic_signed(ts, delivery.map(str::trim).unwrap_or(""), body);
    if ik::signature_ok(secret, &signed, signature) {
        Ok(())
    } else {
        Err("bad signature")
    }
}

/// A generic webhook's fields: the top-level scalars of a JSON object body (strings, numbers,
/// bools), at most [`MAX_GENERIC_FIELDS`], keys `[a-z0-9_-]` of at most 64 bytes, strings cut at
/// [`MAX_GENERIC_VALUE`], the first by key order kept. Anything else in the body (nested values,
/// other keys) is dropped. A body that isn't a JSON object gives no fields.
pub fn generic_fields(body: &[u8]) -> Value {
    let mut out = Map::new();
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(body) else { return Value::Object(out) };
    // In key order, whatever order the body had (and whether serde_json keeps it): which keys
    // are kept under the cap doesn't depend on how the sender ordered them.
    let mut entries: Vec<(String, Value)> = m.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in entries {
        if out.len() >= MAX_GENERIC_FIELDS {
            break;
        }
        // A dotted key would read as a nested field to a filter or a template: kept only plain.
        if !ik::field_key(&k) || k.contains('.') {
            continue;
        }
        let v = match v {
            Value::String(s) => Value::String(ik::keep_text(&s, MAX_GENERIC_VALUE)),
            Value::Number(n) => Value::Number(n),
            Value::Bool(b) => Value::Bool(b),
            _ => continue,
        };
        out.insert(k, v);
    }
    Value::Object(out)
}

/// The generic webhook's adapter.
pub struct Generic;

impl Adapter for Generic {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn hook<'a>(&self, source: &'a Source) -> Option<Hook<'a>> {
        match source {
            Source::Webhook { verify } => Some(Hook { kind: KIND, verify: &verify.hmac_sha256, repo: None, events: vec![] }),
            _ => None,
        }
    }

    fn verify<'b>(&self, secret: &[u8], header: Header<'_>, body: &'b [u8], now: i64) -> Option<Signed<'b>> {
        let delivery = header(GENERIC_DELIVERY);
        let timestamp = header(GENERIC_TIMESTAMP);
        generic_check(secret, timestamp.as_deref(), delivery.as_deref(), body, header(GENERIC_SIGNATURE).as_deref(), now).ok()?;
        // A delivery with no id is named by its whole signed message (time included), so the same
        // body sent again later is a new delivery (#714 review C); and its dedup is keyed on it, so
        // the same body sent again as a new delivery isn't taken for a resend (#714 review F12).
        let ts = timestamp.as_deref().and_then(|t| t.trim().parse::<i64>().ok()).unwrap_or(0);
        let message = generic_signed(ts, delivery.as_deref().map(str::trim).unwrap_or(""), body);
        Some(Signed { delivery, message: Cow::Owned(message) })
    }

    fn normalise(&self, _: &IntakeTrigger, _: Header<'_>, body: &[u8]) -> Result<(String, Value), Unfit> {
        Ok((KIND.to_string(), generic_fields(body)))
    }

    fn listens(&self, _: &Hook<'_>, kind: &str) -> bool {
        kind == KIND
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::intake::fields_within;

    const KEY: &[u8] = b"0123456789abcdef-key";

    /// #714 review H2: a generic delivery's timestamp and id are under its MAC, so it can't be sent
    /// again later or under another id, and only within the window.
    #[test]
    fn a_generic_signature_binds_its_time_and_id() {
        let sig = generic_signature(KEY, 1000, "d-1", b"{}");
        let ok = |ts: &str, id: Option<&str>, body: &[u8], now: i64| generic_check(KEY, Some(ts), id, body, Some(&sig), now);
        assert_eq!(ok("1000", Some("d-1"), b"{}", 1000), Ok(()));
        assert_eq!(ok("1000", Some("d-1"), b"{}", 1299), Ok(()));
        assert_eq!(ok("1000", Some("d-1"), b"{}", 1301), Err("timestamp outside the window"), "too late");
        assert_eq!(ok("1000", Some("d-1"), b"{}", 699), Err("timestamp outside the window"), "too early");
        assert_eq!(ok("1000", Some("d-2"), b"{}", 1000), Err("bad signature"), "another id: a replay");
        assert_eq!(ok("1001", Some("d-1"), b"{}", 1000), Err("bad signature"), "another time");
        assert_eq!(ok("1000", None, b"{}", 1000), Err("bad signature"), "the id dropped");
        assert_eq!(generic_check(KEY, None, Some("d-1"), b"{}", Some(&sig), 1000), Err("no timestamp"));
        assert_eq!(generic_check(KEY, Some("x"), Some("d-1"), b"{}", Some(&sig), 1000), Err("no timestamp"));
    }

    /// #714 review F1: a capture can't be replayed by moving the boundary between its id and its
    /// body (an id with a `:` and the body's start).
    #[test]
    fn a_capture_cant_be_split_differently() {
        let sig = generic_signature(KEY, 1000, "d-1", br#"{"a":1}"#);
        let split = |id: &str, body: &[u8]| generic_check(KEY, Some("1000"), Some(id), body, Some(&sig), 1000);
        assert_eq!(split("d-1", br#"{"a":1}"#), Ok(()));
        assert_eq!(split(r#"d-1:{"a""#, b"1}"), Err("bad signature"));
        assert_eq!(split("d", br#"1:{"a":1}"#), Err("bad signature"));
    }

    /// #714 review E: an empty or short key verifies nothing.
    #[test]
    fn a_short_key_verifies_nothing() {
        let short = generic_signature(b"k", 1, "", b"b");
        assert_eq!(generic_check(b"k", Some("1"), None, b"b", Some(&short), 1), Err("bad signature"));
    }

    /// A generic body keeps only top-level scalars with plain keys, capped and stripped.
    #[test]
    fn a_generic_body_keeps_little() {
        let mut m = serde_json::Map::new();
        for i in 0..40 {
            m.insert(format!("k{i:02}"), Value::from(i));
        }
        m.insert("Bad Key".into(), "x".into());
        m.insert("a.b".into(), "nested-looking".into());
        m.insert("nested".into(), serde_json::json!({ "x": 1 }));
        m.insert("aa_text".into(), Value::String(format!("\u{1b}[31m{}", "y".repeat(600))));
        let f = generic_fields(&serde_json::to_vec(&Value::Object(m)).unwrap());
        let o = f.as_object().unwrap();
        assert_eq!(o.len(), MAX_GENERIC_FIELDS);
        assert!(!o.contains_key("Bad Key") && !o.contains_key("a.b") && !o.contains_key("nested"));
        let t = o["aa_text"].as_str().unwrap();
        assert!(t.len() <= MAX_GENERIC_VALUE && !t.contains('\u{1b}'), "{t}");
        assert!(fields_within(&f));
        assert_eq!(generic_fields(b"[1,2]"), serde_json::json!({}));
        assert_eq!(generic_fields(b"not json"), serde_json::json!({}));
    }
}

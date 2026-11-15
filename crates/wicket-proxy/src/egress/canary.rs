//! Placeholders as canaries, and the guard against reflected secrets (#362). Part of
//! [`super::Egress`].
//!
//! - A run's credential placeholder belongs in one place: `Authorization: Bearer <placeholder>` on
//!   its own host. Seen anywhere else (another host, the URL, a body, another header), or another
//!   run's placeholder seen at all, means the box is trying to move it: the request is refused,
//!   audited as an anomaly and counted as a strike.
//! - On responses from a host wicket attached a credential to, the body is asked for, and must come,
//!   unencoded, and is scanned as it streams for the real secret, raw or in base64 or hex: each
//!   occurrence is masked before it reaches the box, and the reflection is audited.

use super::*;
use base64::Engine;
use std::ops::Range;

/// What every wicket-made placeholder contains, followed by its run's id (`run-` and a lowercase
/// ULID): how another run's placeholder is recognised (wicket-agent makes them).
const MARKERS: &[&str] = &["wicket-placeholder-run-", "wicket-session-placeholder-run-"];
/// The ULID after a marker.
const TAG_LEN: usize = 26;
/// The shortest form of a secret scanned for in a response: shorter ones would mask common bytes.
const MIN_FORM: usize = 8;

/// A request refused by the tripwire: what was seen, and the strike note for the agent.
#[derive(Debug)]
pub(crate) struct Tripped {
    pub what: String,
    pub note: String,
}

impl std::fmt::Display for Tripped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused: {}", self.what)
    }
}

impl std::error::Error for Tripped {}

/// The box's answer when `e` is a tripwire refusal: a 403, never retryable.
pub(crate) fn tripped_response(e: &anyhow::Error) -> Option<Response<BoxBody>> {
    let t = e.downcast_ref::<Tripped>()?;
    Some(problem(
        403,
        "forbidden",
        "Blocked by wicket sandbox: never allowed",
        &format!(
            "{}. A credential placeholder is only ever sent as `Authorization: Bearer <placeholder>` to its own host; anywhere else it is treated as an attempt to move it, and recorded. {} Do not retry it.{}",
            t.what,
            crate::SANDBOX_FACT,
            t.note
        ),
        None,
    ))
}

struct Pattern {
    bytes: Vec<u8>,
    /// How many run-id characters (`[0-9a-z]`) must follow for a match (a marker's run id).
    tail: usize,
}

/// A streaming exact-match scanner over several patterns. What it hands on stops short of anything
/// that could be the start of a match, so a match split across chunks is seen whole before any of
/// it is passed on.
pub(crate) struct Scanner {
    pats: Vec<Pattern>,
    carry: Vec<u8>,
    /// Which bytes of `carry` are part of a match already found.
    mask: Vec<bool>,
}

/// What [`Scanner::feed`] hands on: the bytes now safe to pass (matches masked), and whether a match
/// was seen.
pub(crate) struct Fed {
    pub out: Bytes,
    pub hit: bool,
}

impl Scanner {
    fn new(pats: Vec<Pattern>) -> Scanner {
        let mut seen = std::collections::HashSet::new();
        let pats = pats.into_iter().filter(|p| !p.bytes.is_empty() && seen.insert((p.bytes.clone(), p.tail))).collect();
        Scanner { pats, carry: Vec::new(), mask: Vec::new() }
    }

    /// This run's placeholders, exactly, and any wicket placeholder's shape (another run's).
    pub(crate) fn placeholders<'a>(own: impl Iterator<Item = &'a str>) -> Scanner {
        let mut pats: Vec<Pattern> = own.map(|p| Pattern { bytes: p.as_bytes().to_vec(), tail: 0 }).collect();
        pats.extend(MARKERS.iter().map(|m| Pattern { bytes: m.as_bytes().to_vec(), tail: TAG_LEN }));
        Scanner::new(pats)
    }

    /// Each of `secrets` as it could be reflected: raw, hex (either case), and base64 (standard and
    /// URL-safe) at each of the three alignments it could have inside a longer encoded value.
    pub(crate) fn secrets(secrets: &[String]) -> Scanner {
        let mut pats = Vec::new();
        for s in secrets {
            for form in forms(s.as_bytes()) {
                if form.len() >= MIN_FORM {
                    pats.push(Pattern { bytes: form, tail: 0 });
                }
            }
        }
        Scanner::new(pats)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pats.is_empty()
    }

    /// The first match in `whole` (a value read whole), if any.
    pub(crate) fn first(&self, whole: &[u8]) -> Option<Range<usize>> {
        self.matches(whole, true).0.into_iter().min_by_key(|r| r.start)
    }

    /// Every match in `buf`, and where to hold back from (`buf.len()` for nothing held): the start of
    /// the earliest suffix that could still become a match. At the end, nothing is held.
    fn matches(&self, buf: &[u8], at_end: bool) -> (Vec<Range<usize>>, usize) {
        let mut found = Vec::new();
        let mut hold = buf.len();
        for p in &self.pats {
            for s in memchr::memmem::find_iter(buf, &p.bytes) {
                let end = s + p.bytes.len();
                let tail = &buf[end..buf.len().min(end + p.tail)];
                if !tail.iter().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()) {
                    continue;
                }
                if tail.len() == p.tail {
                    found.push(s..end + p.tail);
                } else if !at_end {
                    hold = hold.min(s);
                }
            }
            if !at_end {
                let max = (p.bytes.len() - 1).min(buf.len());
                if let Some(k) = (1..=max).rev().find(|&k| buf.ends_with(&p.bytes[..k])) {
                    hold = hold.min(buf.len() - k);
                }
            }
        }
        (found, hold)
    }

    /// Takes the next chunk; returns what can be passed on now.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Fed {
        self.carry.extend_from_slice(chunk);
        self.mask.resize(self.carry.len(), false);
        self.step(false)
    }

    /// The stream has ended: everything still held, matches masked.
    pub(crate) fn finish(&mut self) -> Fed {
        self.step(true)
    }

    fn step(&mut self, at_end: bool) -> Fed {
        let (found, hold) = self.matches(&self.carry, at_end);
        for r in &found {
            self.mask[r.clone()].iter_mut().for_each(|m| *m = true);
        }
        let rest = self.carry.split_off(hold);
        let rest_mask = self.mask.split_off(hold);
        let mut out = std::mem::replace(&mut self.carry, rest);
        for (b, m) in out.iter_mut().zip(std::mem::replace(&mut self.mask, rest_mask)) {
            if m {
                *b = b'*';
            }
        }
        Fed { out: Bytes::from(out), hit: !found.is_empty() }
    }
}

/// A secret's reflectable forms (see [`Scanner::secrets`]).
fn forms(raw: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![raw.to_vec(), hex::encode(raw).into_bytes(), hex::encode_upper(raw).into_bytes()];
    for engine in [base64::engine::general_purpose::STANDARD_NO_PAD, base64::engine::general_purpose::URL_SAFE_NO_PAD] {
        for k in 0..3usize {
            let mut buf = vec![0u8; k];
            buf.extend_from_slice(raw);
            let enc = engine.encode(&buf);
            // The characters that hold only the secret's bits: none of the leading pad's, none of
            // the zero bits after its end.
            let start = [0, 2, 3][k];
            let end = (buf.len() * 8 / 6).min(enc.len());
            if end > start {
                out.push(enc.as_bytes()[start..end].to_vec());
            }
        }
    }
    out
}

/// `s` with its percent-escapes decoded (bytes, as a URL may hold any).
pub(crate) fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// A request body, scanned for placeholders as it streams upstream: on a match it ends with an
/// error before the match's first byte has gone, and `tripped` says why.
pub(crate) fn guard_request(
    body: impl futures_util::Stream<Item = std::result::Result<Bytes, Box<dyn std::error::Error + Send + Sync>>> + Send + 'static,
    scan: Scanner,
    tripped: Arc<std::sync::OnceLock<String>>,
) -> impl futures_util::Stream<Item = std::result::Result<Bytes, Box<dyn std::error::Error + Send + Sync>>> + Send + 'static {
    futures_util::stream::unfold((Box::pin(body), scan, false), move |(mut body, mut scan, done)| {
        let tripped = tripped.clone();
        async move {
            use futures_util::StreamExt;
            if done {
                return None;
            }
            let trip = |tripped: &std::sync::OnceLock<String>| {
                let _ = tripped.set("a credential placeholder in the request body".into());
                Box::<dyn std::error::Error + Send + Sync>::from("refused: a credential placeholder in the request body")
            };
            match body.next().await {
                Some(Ok(chunk)) => {
                    let fed = scan.feed(&chunk);
                    if fed.hit {
                        return Some((Err(trip(&tripped)), (body, scan, true)));
                    }
                    Some((Ok(fed.out), (body, scan, false)))
                }
                Some(Err(e)) => Some((Err(e), (body, scan, true))),
                None => {
                    let fed = scan.finish();
                    if fed.hit {
                        return Some((Err(trip(&tripped)), (body, scan, true)));
                    }
                    Some((Ok(fed.out), (body, scan, true)))
                }
            }
        }
    })
}

/// A response body from a credentialed host, with every form of its secrets masked as it streams
/// (same length, so a `content-length` still holds); `on_hit` is called once, at the first.
pub(crate) fn guard_response(body: BoxBody, scan: Scanner, on_hit: impl FnOnce() + Send + Sync + 'static) -> BoxBody {
    type Hook = Box<dyn FnOnce() + Send + Sync>;
    let on_hit: Option<Hook> = Some(Box::new(on_hit));
    let stream =
        futures_util::stream::unfold((body.into_data_stream(), scan, false, on_hit), |(mut body, mut scan, done, mut on_hit)| async move {
            use futures_util::StreamExt;
            if done {
                return None;
            }
            let (item, done) = match body.next().await {
                Some(Ok(chunk)) => (Ok(scan.feed(&chunk)), false),
                Some(Err(e)) => (Err(e), true),
                None => (Ok(scan.finish()), true),
            };
            let item = item.map(|fed| {
                if fed.hit {
                    if let Some(f) = on_hit.take() {
                        f();
                    }
                }
                Frame::data(fed.out)
            });
            Some((item, (body, scan, done, on_hit)))
        });
    BodyExt::boxed(StreamBody::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `chunks` through `s`; returns what came out and whether anything matched.
    fn run(mut s: Scanner, chunks: &[&[u8]]) -> (String, bool) {
        let (mut out, mut hit) = (Vec::new(), false);
        for c in chunks {
            let f = s.feed(c);
            out.extend_from_slice(&f.out);
            hit |= f.hit;
        }
        let f = s.finish();
        out.extend_from_slice(&f.out);
        (String::from_utf8(out).unwrap(), hit || f.hit)
    }

    #[test]
    fn a_secret_split_across_chunks_is_masked_and_nothing_else_is() {
        let s = || Scanner::secrets(&["s3cret-value-42".to_string()]);
        let (out, hit) = run(s(), &[b"abc s3cr", b"et-val", b"ue-42 def"]);
        assert_eq!(out, "abc *************** def");
        assert!(hit);
        // A prefix that never completes passes through whole, held only until it can't match.
        let (out, hit) = run(s(), &[b"abc s3cr", b"et-nope"]);
        assert_eq!((out.as_str(), hit), ("abc s3cret-nope", false));
        // Byte by byte.
        let text = b"x s3cret-value-42 y";
        let chunks: Vec<&[u8]> = text.chunks(1).collect();
        assert_eq!(run(s(), &chunks).0, "x *************** y");
    }

    #[test]
    fn nothing_that_cant_start_a_match_is_held() {
        let mut s = Scanner::secrets(&["s3cret-value-42".to_string()]);
        assert_eq!(&s.feed(b"data: {\"delta\":\"hi\"}\n\n").out[..], b"data: {\"delta\":\"hi\"}\n\n");
        assert_eq!(&s.feed(b"tail s3c").out[..], b"tail ");
    }

    #[test]
    fn base64_and_hex_forms_are_found_at_any_alignment() {
        let secret = "s3cret-value-42";
        for prefix in ["", "u:", "user:", "git-user:"] {
            for engine in [base64::engine::general_purpose::STANDARD, base64::engine::general_purpose::URL_SAFE] {
                let enc = engine.encode(format!("{prefix}{secret}"));
                assert!(Scanner::secrets(&[secret.into()]).first(enc.as_bytes()).is_some(), "{prefix:?} {enc}");
            }
        }
        for h in [hex::encode(secret), hex::encode_upper(secret)] {
            assert!(Scanner::secrets(&[secret.into()]).first(format!("id={h};").as_bytes()).is_some());
        }
        // Too short a secret isn't scanned for at all, rather than masking common bytes.
        assert!(Scanner::secrets(&["abc".into()]).is_empty());
    }

    #[test]
    fn another_runs_placeholder_needs_its_run_id() {
        let s = || Scanner::placeholders(["ph-own-1234"].into_iter());
        let other = "sk-ant-oat01-wicket-placeholder-run-01jabcdefghjkmnpqrstvwxyz0";
        assert!(s().first(format!("x={other}").as_bytes()).is_some());
        assert!(s().first(b"x=ph-own-1234").is_some());
        // Source code naming the shape isn't a placeholder.
        assert!(s().first(b"format!(\"sk-ant-oat01-wicket-placeholder-run-{tag}\")").is_none());
        // Split across chunks, the run id arriving last: held until it can be told.
        let (_, hit) = run(s(), &[&other.as_bytes()[..40], &other.as_bytes()[40..]]);
        assert!(hit);
        let (out, hit) = run(s(), &[b"sk-ant-oat01-wicket-placeholder-run-01j", b"}"]);
        assert_eq!((out.as_str(), hit), ("sk-ant-oat01-wicket-placeholder-run-01j}", false));
    }

    #[test]
    fn percent_escapes_decode() {
        assert_eq!(percent_decode("/a%2Fb%zz%4"), b"/a/b%zz%4");
    }
}

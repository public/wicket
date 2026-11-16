//! Windowed egress caps on the node (#368, `wicket_core::window`): this activation's own count of
//! requests and bytes through the egress proxy, held to the slice its control host leased it.
//!
//! - **Fail closed.** A zone with caps sends nothing upstream without a slice that has room: none
//!   leased yet, or one spent (the control host unreachable), and the request is refused (429).
//! - **Requests** are counted when one is decided and about to go upstream, and journaled first
//!   ([`EgressCounter::set_journal`]), so a `serve` that crashes and restarts counts it.
//! - **Bytes** are counted as they pass, both ways: a request whose declared length doesn't fit is
//!   refused before it is sent, and a body (either way) that would pass the slice is cut there.

use super::*;
use wicket_core::window::{EgressCaps, EgressSlice, EgressUse};

type Journal = Box<dyn Fn(EgressUse) + Send + Sync>;

/// An activation's egress counter on its node.
pub struct EgressCounter {
    caps: EgressCaps,
    state: std::sync::Mutex<(EgressUse, Option<EgressSlice>)>,
    journal: std::sync::Mutex<Option<Journal>>,
}

/// Why a request or a body was stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capped(pub String);

impl std::fmt::Display for Capped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Capped {}

impl EgressCounter {
    pub fn new(caps: EgressCaps) -> Arc<EgressCounter> {
        Arc::new(EgressCounter { caps, state: std::sync::Mutex::new((EgressUse::default(), None)), journal: std::sync::Mutex::new(None) })
    }

    pub fn caps(&self) -> EgressCaps {
        self.caps
    }

    /// What this activation has counted.
    pub fn used(&self) -> EgressUse {
        self.state.lock().expect("egress counter").0
    }

    /// Takes in what this node counted before a restart (its journal). Counters only go up.
    pub fn merge_used(&self, u: EgressUse) {
        let mut s = self.state.lock().expect("egress counter");
        s.0.requests = s.0.requests.max(u.requests);
        s.0.bytes = s.0.bytes.max(u.bytes);
    }

    pub fn set_slice(&self, slice: Option<EgressSlice>) {
        self.state.lock().expect("egress counter").1 = slice;
    }

    pub fn slice(&self) -> Option<EgressSlice> {
        self.state.lock().expect("egress counter").1
    }

    /// Has `f` told the count before each request goes upstream (the node persists it).
    pub fn set_journal(&self, f: impl Fn(EgressUse) + Send + Sync + 'static) {
        *self.journal.lock().expect("journal") = Some(Box::new(f));
    }

    /// Tells the journal the count now.
    pub fn journal(&self) {
        if let Some(f) = &*self.journal.lock().expect("journal") {
            f(self.used());
        }
    }

    fn why(&self, what: &str) -> String {
        let w = self.caps.window_secs;
        let window = if w % 3600 == 0 {
            format!("{}h", w / 3600)
        } else if w % 60 == 0 {
            format!("{}m", w / 60)
        } else {
            format!("{w}s")
        };
        match what {
            "none" => {
                "this node has no egress allowance for the box yet (its zone caps egress, and its control host hasn't leased it one)".into()
            }
            "requests" => format!(
                "the zone's egress cap of {} requests per {window} is reached (as much of it as this node holds)",
                self.caps.requests.unwrap_or(0)
            ),
            _ => format!(
                "the zone's egress cap of {} bytes per {window} is reached (as much of it as this node holds)",
                self.caps.bytes.unwrap_or(0)
            ),
        }
    }

    /// Admits one request going upstream (`declared`: its body's length, if it says): counted and
    /// journaled, or refused.
    pub fn admit(&self, declared: Option<u64>) -> std::result::Result<(), Capped> {
        {
            let mut s = self.state.lock().expect("egress counter");
            let (used, slice) = (s.0, s.1);
            let Some(slice) = slice else { return Err(Capped(self.why("none"))) };
            slice.admits(used).map_err(|w| Capped(self.why(w)))?;
            if let (Some(n), Some(left)) = (declared, slice.bytes_left(used)) {
                if n > left {
                    return Err(Capped(format!("a {n}-byte body doesn't fit: {}", self.why("bytes"))));
                }
            }
            s.0.requests += 1;
        }
        self.journal();
        Ok(())
    }

    /// Whether `n` more bytes would fit, without counting them.
    pub fn fits(&self, n: u64) -> std::result::Result<(), Capped> {
        let s = self.state.lock().expect("egress counter");
        match s.1.and_then(|sl| sl.bytes_left(s.0)) {
            Some(left) if n > left => Err(Capped(format!("a {n}-byte body doesn't fit: {}", self.why("bytes")))),
            _ => Ok(()),
        }
    }

    /// Counts `n` bytes passing, or refuses them if they don't fit (the body is cut there).
    pub fn pass(&self, n: u64) -> std::result::Result<(), Capped> {
        let mut s = self.state.lock().expect("egress counter");
        let left = match s.1 {
            None => Some(0),
            Some(sl) => sl.bytes_left(s.0),
        };
        if left.is_some_and(|l| n > l) {
            return Err(Capped(self.why("bytes")));
        }
        s.0.bytes = s.0.bytes.saturating_add(n);
        Ok(())
    }
}

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Counts a stream of chunks, ending it with an error at the first chunk that doesn't fit.
fn count_stream(
    body: impl futures_util::Stream<Item = std::result::Result<Bytes, BoxErr>> + Send + 'static,
    c: Arc<EgressCounter>,
) -> impl futures_util::Stream<Item = std::result::Result<Frame<Bytes>, BoxErr>> + Send + 'static {
    futures_util::stream::unfold((Box::pin(body), c, false), |(mut body, c, done)| async move {
        use futures_util::StreamExt;
        if done {
            return None;
        }
        match body.next().await {
            Some(Ok(chunk)) => match c.pass(chunk.len() as u64) {
                Ok(()) => Some((Ok(Frame::data(chunk)), (body, c, false))),
                Err(e) => Some((Err(Box::new(e) as BoxErr), (body, c, true))),
            },
            Some(Err(e)) => Some((Err(e), (body, c, true))),
            None => None,
        }
    })
}

/// `req` with its body counted as it goes upstream.
pub(super) fn counted_request<B>(
    req: Request<B>,
    c: Arc<EgressCounter>,
) -> Request<StreamBody<impl futures_util::Stream<Item = std::result::Result<Frame<Bytes>, BoxErr>> + Send + 'static>>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxErr>,
{
    let (parts, body) = req.into_parts();
    // `Limited` only to have the body's error boxed; its limit is the counter's.
    let data = Limited::new(body, usize::MAX).into_data_stream();
    Request::from_parts(parts, StreamBody::new(count_stream(data, c)))
}

/// `resp` with its body counted as it goes back to the box.
pub(super) fn counted_response(resp: Response<BoxBody>, c: Arc<EgressCounter>) -> Response<BoxBody> {
    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, BodyExt::boxed(StreamBody::new(count_stream(body.into_data_stream(), c))))
}

impl Egress {
    /// The run's egress counter (#368), on a node whose zone caps egress.
    pub fn set_egress_counter(&self, c: Arc<EgressCounter>) {
        let _ = self.counter.set(c);
    }

    /// Whether this run's zone caps egress (then nothing is spliced: every byte is counted here).
    pub(crate) fn capped(&self) -> bool {
        self.ctx.zone.limits.egress.is_some()
    }

    /// The counter for a request about to go upstream: Ok(None) when the zone has no caps, Err when
    /// it has them and the request doesn't fit (or the counter is missing: fail closed).
    pub(super) fn admit_egress(&self, declared: Option<u64>) -> std::result::Result<Option<Arc<EgressCounter>>, Capped> {
        if !self.capped() {
            return Ok(None);
        }
        let c = self.counter.get().ok_or_else(|| Capped("this proxy has no egress counter for a zone that caps egress".into()))?;
        c.admit(declared)?;
        Ok(Some(c.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> EgressCaps {
        EgressCaps { window_secs: 3600, requests: Some(10), bytes: Some(100) }
    }

    #[test]
    fn nothing_goes_without_a_slice_and_a_slice_bounds_everything() {
        let c = EgressCounter::new(caps());
        assert!(c.admit(None).unwrap_err().0.contains("no egress allowance"));
        assert!(c.pass(1).is_err());
        c.set_slice(Some(EgressSlice { requests: Some(2), bytes: Some(50) }));
        let journaled = Arc::new(std::sync::Mutex::new(vec![]));
        let j = journaled.clone();
        c.set_journal(move |u| j.lock().unwrap().push(u));
        c.admit(Some(10)).unwrap();
        assert_eq!(journaled.lock().unwrap().last(), Some(&EgressUse { requests: 1, bytes: 0 }), "journaled before it goes");
        assert!(c.admit(Some(51)).unwrap_err().0.contains("doesn't fit"), "a declared body over what is left");
        c.pass(40).unwrap();
        assert!(c.pass(11).is_err(), "a frame past the slice is cut");
        c.pass(10).unwrap();
        assert_eq!(c.used(), EgressUse { requests: 1, bytes: 50 });
        assert!(c.admit(None).unwrap_err().0.contains("bytes"));
        c.set_slice(Some(EgressSlice { requests: Some(2), bytes: Some(1000) }));
        c.admit(None).unwrap();
        assert!(c.admit(None).unwrap_err().0.contains("10 requests per 1h"));
        // A restart: the journal's count is taken in, never lowered.
        c.merge_used(EgressUse { requests: 1, bytes: 5 });
        assert_eq!(c.used(), EgressUse { requests: 2, bytes: 50 });
    }

    #[tokio::test]
    async fn a_counted_body_is_cut_where_it_passes_the_slice() {
        let c = EgressCounter::new(caps());
        c.set_slice(Some(EgressSlice { requests: Some(5), bytes: Some(10) }));
        let frames = [b"12345".as_slice(), b"678", b"9abc"].map(|b| Ok::<_, BoxErr>(Bytes::from_static(b)));
        let body = StreamBody::new(count_stream(futures_util::stream::iter(frames), c.clone()));
        let got = body.collect().await;
        assert!(got.is_err(), "the third frame doesn't fit");
        assert_eq!(c.used().bytes, 8);
    }
}

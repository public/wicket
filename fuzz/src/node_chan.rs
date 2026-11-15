//! Target 3a: the control/node channel (`wicket-cli/src/chan.rs`), both directions: the node reads
//! what the control host sends and the control host what the node sends, through the same
//! [`crate::chan::read_frame`]. The input is a byte stream of frames.
//!
//! Decoding doesn't depend on the negotiated version (every message of every supported version is
//! one serde enum; what a version adds is only ever *sent* on connections that negotiated it), so
//! one decoder covers them all; the seeds hold messages of each version, and the first four bytes
//! are also put through [`crate::chan::negotiate`] against this build's version.
//!
//! The oracle: no panic, and every frame that decodes re-encodes to a frame that decodes to itself.

use crate::chan::{negotiate, read_frame, Frame, PROTOCOL};

pub fn run(data: &[u8]) {
    if data.len() >= 4 {
        let theirs = u32::from_be_bytes(data[..4].try_into().unwrap());
        if let Ok(v) = negotiate(PROTOCOL, theirs) {
            assert!(v <= PROTOCOL && v <= theirs && PROTOCOL.abs_diff(theirs) <= crate::chan::PROTOCOL_SKEW);
        }
    }
    // One frame body, as `decode_body` sees it after the length prefix.
    if let Ok(f) = Frame::decode_body(data) {
        round_trip(&f);
    }
    // The whole input as a stream of length-prefixed frames.
    let rt = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
    rt.block_on(async {
        let mut r = data;
        while let Ok(Some(f)) = read_frame(&mut r).await {
            round_trip(&f);
        }
    });
}

fn round_trip(f: &Frame) {
    let wire = f.encode();
    let back = Frame::decode_body(&wire[4..]).unwrap_or_else(|e| panic!("{f:?} re-encoded doesn't decode: {e}"));
    // JSON floats and maps needn't be byte-identical, but the decoded frame must be the same.
    if back != *f {
        // Messages carrying f64s can differ by rounding only if serde_json's float formatting isn't
        // round-trip exact; it is, so any difference is a finding.
        panic!("{f:?} round-trips to {back:?}");
    }
}

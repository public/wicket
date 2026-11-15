//! The simulated channels' wire format.
//!
//! **Control host ↔ node.** This follows the node channel's framing (`wicket-cli/src/chan.rs`): a
//! 4-byte big-endian length, then a kind byte (`1` a JSON message, `3` one wicket-feed frame line),
//! then the body. The messages are the few of `chan::Msg` the simulation needs, with the same
//! payloads (`Slice` and `Spent` are wicket-proxy's own types). `chan.rs` lives in the CLI binary, so
//! it can't be linked here yet; moving it into a library is listed as remaining work.
//!
//! **Box ↔ node.** This stands in for the box's proxies on its unix sockets (`ctl/*.sock`): one
//! egress request or one model call at a time, answered with the decision.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use wicket_proxy::llm::{Slice, Spent};

pub const KIND_MSG: u8 = 1;
pub const KIND_FEED: u8 = 3;
/// The largest frame body: a feed snapshot plus framing, as `chan::MAX_FRAME`.
pub const MAX_FRAME: usize = wicket_feed::MAX_FRAME_BYTES + 4096;

/// A control message, as `chan::Msg`'s variants of the same names.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Ctl {
    /// Node → control host on connecting: what its replica holds, for catch-up.
    Hello { hello: wicket_feed::Hello },
    /// Control host → node: a run's budget slice (`Msg::BudgetSlice`).
    BudgetSlice { run: String, slice: Slice },
    /// Node → control host: what a run's model proxy has counted (`Msg::Spent`).
    Spent { run: String, spent: Spent },
}

/// A box's request to its node.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum BoxReq {
    /// Which box this connection is (on a node, the box's own socket says so).
    Hello {
        run: String,
    },
    Egress {
        method: String,
        host: String,
        path: String,
    },
    Model {
        max_tokens: u64,
    },
}

/// The node's answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum BoxResp {
    Egress {
        allowed: bool,
        why: String,
    },
    /// 200 with the output tokens generated, or the refusal's status.
    Model {
        status: u16,
        output: u64,
    },
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, body: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.extend(((body.len() + 1) as u32).to_be_bytes());
    out.push(kind);
    out.extend(body);
    w.write_all(&out).await
}

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, m: &T) -> std::io::Result<()> {
    write_frame(w, KIND_MSG, &serde_json::to_vec(m).expect("messages serialise")).await
}

/// Reads one frame: `None` at a clean end of stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("frame length {n}")));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    let kind = body.remove(0);
    Ok(Some((kind, body)))
}

pub fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> std::io::Result<T> {
    serde_json::from_slice(body).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

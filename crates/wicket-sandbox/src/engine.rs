//! A small client for the Docker Engine API over the daemon's unix socket (#287): what a box start
//! asks Docker (create and start, inspect, wait, logs, kill, rm, image inspect, the image events)
//! without a `docker` CLI process per call. One HTTP/1.1 connection per request (a unix socket's
//! connect costs microseconds), unversioned paths (the daemon's own API version: a daemon that has
//! dropped an older one still answers), JSON bodies.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::path::{Path, PathBuf};

/// The daemon's socket when nothing says otherwise.
pub const DEFAULT_SOCKET: &str = "/var/run/docker.sock";

#[derive(Debug)]
pub(crate) struct Engine {
    pub(crate) sock: PathBuf,
}

/// Percent-encodes `s` for a URL path segment (`slash`: `/` kept, as in an image reference) or a
/// query value.
pub(crate) fn enc(s: &str, slash: bool) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric() || b"-._~".contains(&b) || (slash && b"/:@".contains(&b));
        if keep {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// What the daemon said went wrong (`{"message": …}`), or the body as text.
pub(crate) fn message(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["message"].as_str().map(String::from))
        .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string())
}

impl Engine {
    pub(crate) fn new(sock: impl Into<PathBuf>) -> Engine {
        Engine { sock: sock.into() }
    }

    pub(crate) fn socket(&self) -> &Path {
        &self.sock
    }

    /// Sends one request on a fresh connection: the response, its body still streaming.
    pub(crate) async fn send(&self, method: Method, path: &str, body: Option<&serde_json::Value>) -> Result<Response<Incoming>> {
        let stream = tokio::net::UnixStream::connect(&self.sock)
            .await
            .with_context(|| format!("connecting to Docker at {}", self.sock.display()))?;
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.context("Docker's API")?;
        // Drives the connection for as long as the response (a followed stream, say) is read.
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut req = Request::builder().method(method).uri(path).header(hyper::header::HOST, "docker");
        let bytes = match body {
            Some(b) => {
                req = req.header(hyper::header::CONTENT_TYPE, "application/json");
                Bytes::from(serde_json::to_vec(b)?)
            }
            None => Bytes::new(),
        };
        let req = req.body(Full::new(bytes))?;
        tx.send_request(req).await.with_context(|| format!("Docker's API: {path}"))
    }

    /// As [`Engine::send`], with the whole body read.
    pub(crate) async fn call(&self, method: Method, path: &str, body: Option<&serde_json::Value>) -> Result<(StatusCode, Bytes)> {
        let resp = self.send(method, path, body).await?;
        let status = resp.status();
        let body = resp.into_body().collect().await.with_context(|| format!("Docker's API: {path}"))?.to_bytes();
        Ok((status, body))
    }

    /// A JSON answer: None if Docker has no such thing (404), an error for any other failure.
    pub(crate) async fn get_json(&self, path: &str) -> Result<Option<serde_json::Value>> {
        let (status, body) = self.call(Method::GET, path, None).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            bail!("{} ({status})", message(&body));
        }
        Ok(Some(serde_json::from_slice(&body).with_context(|| format!("Docker's answer to {path}"))?))
    }
}

/// Splits Docker's multiplexed log stream (a container without a TTY: frames of an 8-byte header,
/// the stream (1 stdout, 2 stderr) and a big-endian length, then that many bytes).
#[derive(Default)]
pub(crate) struct Demux {
    buf: Vec<u8>,
}

impl Demux {
    /// Takes the next bytes read: the whole frames they complete, as (stream index 0 or 1, bytes).
    pub(crate) fn feed(&mut self, data: &[u8]) -> Vec<(usize, Vec<u8>)> {
        self.buf.extend_from_slice(data);
        let mut out = vec![];
        let mut at = 0;
        while self.buf.len() - at >= 8 {
            let h = &self.buf[at..at + 8];
            let len = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
            if self.buf.len() - at - 8 < len {
                break;
            }
            let stream = if h[0] == 2 { 1 } else { 0 };
            out.push((stream, self.buf[at + 8..at + 8 + len].to_vec()));
            at += 8 + len;
        }
        self.buf.drain(..at);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_keeps_references_readable_and_nothing_else_through() {
        assert_eq!(enc("ghcr.io/a/b:1@sha256:00ff", true), "ghcr.io/a/b:1@sha256:00ff");
        assert_eq!(enc("a/b?x#y z", true), "a/b%3Fx%23y%20z");
        assert_eq!(enc(r#"{"type":["image"]}"#, false), "%7B%22type%22%3A%5B%22image%22%5D%7D");
        assert_eq!(enc("a/b", false), "a%2Fb");
    }

    #[test]
    fn the_log_stream_splits_by_frame_however_it_is_read() {
        let mut wire = vec![];
        for (s, d) in [(1u8, &b"out one\n"[..]), (2, b"err\n"), (1, b""), (1, b"out two")] {
            wire.extend_from_slice(&[s, 0, 0, 0]);
            wire.extend_from_slice(&(d.len() as u32).to_be_bytes());
            wire.extend_from_slice(d);
        }
        for chunk in [1, 3, 7, 8, 9, wire.len()] {
            let mut m = Demux::default();
            let mut got: [Vec<u8>; 2] = Default::default();
            for c in wire.chunks(chunk) {
                for (i, d) in m.feed(c) {
                    got[i].extend(d);
                }
            }
            assert_eq!(got, [b"out one\nout two".to_vec(), b"err\n".to_vec()], "read {chunk} bytes at a time");
        }
    }

    #[test]
    fn a_daemon_error_reads_as_its_message() {
        assert_eq!(message(br#"{"message":"No such container: x"}"#), "No such container: x");
        assert_eq!(message(b"plain\n"), "plain");
    }
}
